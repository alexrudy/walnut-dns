use std::collections::BTreeMap;

use hickory_proto::rr::{DNSClass, LowerName, RecordType, RrKey, rdata};
use rusqlite::{ToSql, types::FromSql};

use crate::{
    authority::{Lookup, ZoneInfo},
    database::FromRow,
};

use super::{
    Name, Record, SerialNumber, TimeToLive, ZoneID,
    rset::{Mismatch, RecordSet},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum ZoneType {
    Primary = 1,
    Secondary = 2,
    External = 3,
}

impl From<ZoneType> for hickory_server::authority::ZoneType {
    fn from(value: ZoneType) -> Self {
        match value {
            ZoneType::Primary => hickory_server::authority::ZoneType::Primary,
            ZoneType::Secondary => hickory_server::authority::ZoneType::Secondary,
            ZoneType::External => hickory_server::authority::ZoneType::External,
        }
    }
}

impl From<hickory_server::authority::ZoneType> for ZoneType {
    fn from(value: hickory_server::authority::ZoneType) -> Self {
        match value {
            hickory_server::authority::ZoneType::Primary => ZoneType::Primary,
            hickory_server::authority::ZoneType::Secondary => ZoneType::Secondary,
            hickory_server::authority::ZoneType::External => ZoneType::External,
            _ => panic!("Deprecated zone type"),
        }
    }
}

impl ToSql for ZoneType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            ZoneType::Primary => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(1),
            )),
            ZoneType::Secondary => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(2),
            )),
            ZoneType::External => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(3),
            )),
        }
    }
}

impl FromSql for ZoneType {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Integer(1) => Ok(ZoneType::Primary),
            rusqlite::types::ValueRef::Integer(2) => Ok(ZoneType::Secondary),
            rusqlite::types::ValueRef::Integer(3) => Ok(ZoneType::External),
            rusqlite::types::ValueRef::Integer(i) => {
                Err(rusqlite::types::FromSqlError::OutOfRange(i))
            }
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

#[derive(Debug)]
pub struct Zone {
    id: ZoneID,
    zone_type: ZoneType,
    name: Name,
    origin: LowerName,
    allow_axfr: bool,
    dns_class: DNSClass,
    records: BTreeMap<RrKey, RecordSet>,
}

impl Zone {
    /// Create a new empty Zone file with only a SOA record (which is required)
    pub fn empty(
        name: Name,
        soa: Record<rdata::SOA>,
        zone_type: ZoneType,
        allow_axfr: bool,
    ) -> Self {
        let mut records = BTreeMap::new();
        records.insert(soa.rrkey(), RecordSet::from_record(name.clone(), soa));
        let origin = (&name).into();

        Self {
            id: ZoneID::new(),
            zone_type,
            name,
            origin,
            allow_axfr,
            dns_class: DNSClass::IN,
            records,
        }
    }
}

impl Zone {
    /// Database ID
    pub fn id(&self) -> ZoneID {
        self.id
    }

    /// The name of this zone.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// The type of this zone, (Primary / Secondary / External)
    pub fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Whether to allow zone transfers
    pub fn allow_axfr(&self) -> bool {
        self.allow_axfr
    }

    /// Set whether to allow zone transfers
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) {
        self.allow_axfr = allow_axfr;
    }

    /// Set the DNS class of this zone.
    pub fn set_dns_class(&mut self, dns_class: DNSClass) {
        self.dns_class = dns_class;
    }

    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.values().flat_map(|rrset| rrset.records())
    }

    pub fn replace(&mut self, rrset: RecordSet) -> Option<RecordSet> {
        let key = rrset.rrkey();
        self.records.insert(key, rrset)
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl FromRow for Zone {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let id = row.get("id")?;
        let name: Name = row.get("name")?;
        let zone_type = row.get("zone_type")?;
        let allow_axfr = row.get("allow_axfr")?;
        let dns_class = row.get::<_, u16>("dns_class")?.into();
        let origin = (&name).into();

        Ok(Zone {
            id,
            name,
            origin,
            zone_type,
            allow_axfr,
            dns_class,
            records: Default::default(),
        })
    }
}

impl ZoneInfo for Zone {
    fn name(&self) -> &Name {
        &self.name
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr
    }

    fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    fn soa(&self) -> Option<&Record> {
        let rrset = self
            .records
            .get(&RrKey::new(self.name().into(), RecordType::SOA))?;

        rrset.records().next()
    }

    /// The serial number of this zone, from the SOA record.
    fn serial(&self) -> SerialNumber {
        self.soa()
            .and_then(|soa| soa.rdata().as_soa())
            .map_or(SerialNumber::ZERO, |soa| SerialNumber::from(soa.serial()))
    }

    /// The minimum TTL for this zone, from the SOA record.
    fn minimum_ttl(&self) -> TimeToLive {
        self.soa()
            .and_then(|soa| soa.rdata().as_soa())
            .map_or(TimeToLive::ZERO, |soa| TimeToLive::from(soa.minimum()))
    }

    /// Increment the serial number of this zone's SOA record.
    fn increment_soa_serial(&mut self) -> SerialNumber {
        let Some(rrset) = self
            .records
            .get_mut(&RrKey::new(self.name().into(), RecordType::SOA))
        else {
            return SerialNumber::ZERO;
        };

        let Some(soa_data) = rrset
            .records_mut()
            .next()
            .and_then(|record| record.rdata_mut().as_soa_mut())
        else {
            return SerialNumber::ZERO;
        };

        soa_data.increment_serial();
        SerialNumber::from(soa_data.serial())
    }
}

impl Lookup for Zone {
    fn get(&self, key: &RrKey) -> Option<&RecordSet> {
        self.records.get(key)
    }

    fn keys(&self) -> impl Iterator<Item = &RrKey> {
        self.records.keys()
    }

    fn records(&self) -> impl Iterator<Item = &RecordSet> {
        self.records.values()
    }

    fn records_mut(&mut self) -> impl Iterator<Item = &mut RecordSet> {
        self.records.values_mut()
    }

    fn records_reversed(&self) -> impl Iterator<Item = &RecordSet> {
        self.records.values().rev()
    }

    fn upsert(&mut self, record: Record, serial: SerialNumber) -> Result<bool, Mismatch> {
        if record.dns_class() != self.dns_class() {
            return Err(Mismatch("DNS Class"));
        }

        fn is_nsec(upsert_type: RecordType, occupied_type: RecordType) -> bool {
            // NSEC is always allowed
            upsert_type == RecordType::NSEC
                || upsert_type == RecordType::NSEC3
                || occupied_type == RecordType::NSEC
                || occupied_type == RecordType::NSEC3
        }

        fn label_does_not_allow_multiple(
            upsert_type: RecordType,
            occupied_type: RecordType,
            check_type: RecordType,
        ) -> bool {
            // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
            (upsert_type == check_type && occupied_type != check_type) ||
                // it's a different record, but there is already a CNAME/ANAME here
                (upsert_type != check_type && occupied_type == check_type)
        }

        let start_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MAX));

        let multiple_records_at_label_disallowed = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .any(|(key, _)| {
                !is_nsec(record.record_type(), key.record_type)
                    && label_does_not_allow_multiple(
                        record.record_type(),
                        key.record_type,
                        RecordType::CNAME,
                    )
            });

        if multiple_records_at_label_disallowed {
            // consider making this an error?
            return Ok(false);
        }

        let rrset = self
            .records
            .entry(record.rrkey())
            .or_insert_with(|| RecordSet::new(record.name().clone(), record.record_type()));

        rrset.insert(record, serial)
    }

    fn range<T, R>(&self, range: R) -> impl Iterator<Item = (&RrKey, &RecordSet)>
    where
        T: Ord + ?Sized,
        RrKey: std::borrow::Borrow<T> + Ord,
        R: std::ops::RangeBounds<T>,
    {
        self.records.range(range)
    }

    fn remove(&mut self, key: &RrKey) -> Option<RecordSet> {
        self.records.remove(key)
    }
}
