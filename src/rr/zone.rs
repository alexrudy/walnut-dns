use std::{collections::BTreeMap, fs, io, path::Path};

use hickory_proto::{
    rr::{DNSClass, LowerName, RecordType, RrKey, rdata},
    serialize::txt::Parser,
};
use rusqlite::{ToSql, types::FromSql};
use tracing::{debug, error, info};

use crate::{
    authority::{Lookup, ZoneAuthority, ZoneInfo},
    database::FromRow,
};

use super::{
    Name, Record, SerialNumber, SqlName, TimeToLive, ZoneID,
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

#[derive(Debug, Clone)]
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

    pub fn from_rrsets(
        name: Name,
        records: impl Iterator<Item = RecordSet>,
        zone_type: ZoneType,
    ) -> Self {
        let mut rrsets = BTreeMap::new();
        for record in records {
            rrsets.insert(record.rrkey(), record);
        }
        let origin = (&name).into();

        Self {
            id: ZoneID::new(),
            zone_type,
            name,
            origin,
            allow_axfr: false,
            dns_class: DNSClass::IN,
            records: rrsets,
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
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) -> &mut Self {
        self.allow_axfr = allow_axfr;
        self
    }

    /// Set the DNS class of this zone.
    pub fn set_dns_class(&mut self, dns_class: DNSClass) -> &mut Self {
        self.dns_class = dns_class;
        self
    }

    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .flat_map(|rrset| rrset.signed_records())
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
        let name: Name = row.get::<_, SqlName>("name")?.into();
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

    fn get_mut(&mut self, key: &RrKey) -> Option<&mut RecordSet> {
        self.records.get_mut(key)
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

impl From<Zone> for ZoneAuthority<Zone> {
    fn from(value: Zone) -> Self {
        ZoneAuthority::new(value)
    }
}

impl Zone {
    pub fn read_from_file(
        origin: Name,
        path: impl AsRef<Path>,
        zone_type: ZoneType,
    ) -> io::Result<Self> {
        let zone_path = path.as_ref();
        info!("loading zone file: {:?}", zone_path);

        let buf = fs::read_to_string(zone_path).inspect_err(|e| {
            error!("failed to read {}: {:?}", zone_path.display(), e);
        })?;

        let (origin, records) = Parser::new(buf, Some(zone_path.to_path_buf()), Some(origin))
            .parse()
            .map_err(|e| {
                error!("failed to parse {}: {:?}", zone_path.display(), e);
                io::Error::other(e)
            })?;

        info!(
            "zone file loaded: {} with {} records",
            origin,
            records.len()
        );
        debug!("zone: {:#?}", records);

        let records = records.into_values().map(Into::into);
        let zone = Zone::from_rrsets(origin, records, zone_type);
        Ok(zone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RecordType, rdata::A};

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com").unwrap()
    }

    fn create_test_soa() -> Record<rdata::SOA> {
        let name = create_test_name();
        let soa = rdata::SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        Record::from_rdata(name, TimeToLive::from(3600), soa)
    }

    #[test]
    fn test_zone_type_conversions() {
        // Test to hickory_server::authority::ZoneType
        assert_eq!(
            hickory_server::authority::ZoneType::from(ZoneType::Primary),
            hickory_server::authority::ZoneType::Primary
        );
        assert_eq!(
            hickory_server::authority::ZoneType::from(ZoneType::Secondary),
            hickory_server::authority::ZoneType::Secondary
        );
        assert_eq!(
            hickory_server::authority::ZoneType::from(ZoneType::External),
            hickory_server::authority::ZoneType::External
        );

        // Test from hickory_server::authority::ZoneType
        assert_eq!(
            ZoneType::from(hickory_server::authority::ZoneType::Primary),
            ZoneType::Primary
        );
        assert_eq!(
            ZoneType::from(hickory_server::authority::ZoneType::Secondary),
            ZoneType::Secondary
        );
        assert_eq!(
            ZoneType::from(hickory_server::authority::ZoneType::External),
            ZoneType::External
        );
    }

    #[test]
    fn test_zone_type_debug() {
        assert!(format!("{:?}", ZoneType::Primary).contains("Primary"));
        assert!(format!("{:?}", ZoneType::Secondary).contains("Secondary"));
        assert!(format!("{:?}", ZoneType::External).contains("External"));
    }

    #[test]
    fn test_zone_creation() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        assert_eq!(zone.name(), &name);
        assert_eq!(zone.zone_type(), ZoneType::Primary);
        assert_eq!(zone.dns_class(), DNSClass::IN);
        assert!(!zone.allow_axfr());
        assert_eq!(zone.records().count(), 1); // SOA record
        assert!(!zone.is_empty()); // Has SOA record
    }

    #[test]
    fn test_zone_with_allow_axfr() {
        let name = create_test_name();
        let soa = create_test_soa();

        let mut zone = Zone::empty(
            name.clone(),
            soa,
            ZoneType::Primary,
            true, // allow_axfr
        );

        assert_eq!(zone.name(), &name);
        assert_eq!(zone.zone_type(), ZoneType::Primary);
        assert!(zone.allow_axfr());

        // Test set_allow_axfr
        zone.set_allow_axfr(false);
        assert!(!zone.allow_axfr());
    }

    #[test]
    fn test_zone_upsert_record() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record = Record::from_rdata(name, TimeToLive::from(300), A::new(192, 168, 1, 1))
            .into_record_rdata();

        let result = zone.upsert(a_record.clone(), SerialNumber::from(1));
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(zone.records().count(), 2); // SOA + A record
    }

    #[test]
    fn test_zone_remove_record() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record = Record::from_rdata(name, TimeToLive::from(300), A::new(192, 168, 1, 1))
            .into_record_rdata();

        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();
        assert_eq!(zone.records().count(), 2);

        // Remove A record (using the key)
        let key = a_record.rrkey();
        let removed = zone.remove(&key);
        assert!(removed.is_some());
        assert_eq!(zone.records().count(), 1); // Only SOA remains
    }

    #[test]
    fn test_zone_get_by_key() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record =
            Record::from_rdata(name.clone(), TimeToLive::from(300), A::new(192, 168, 1, 1))
                .into_record_rdata();

        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();

        // Test get by key
        let key = a_record.rrkey();
        let result = zone.get(&key);
        assert!(result.is_some());

        let rrset = result.unwrap();
        assert_eq!(rrset.record_type(), RecordType::A);
        assert_eq!(rrset.len(), 1);
    }

    #[test]
    fn test_zone_soa_access() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Test SOA access
        let soa_record = zone.soa().unwrap();
        assert_eq!(soa_record.record_type(), RecordType::SOA);

        // Test serial number
        let serial = zone.serial();
        assert_eq!(serial.get(), 1); // From our test SOA
    }

    #[test]
    fn test_zone_is_empty() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone = Zone::empty(name, soa, ZoneType::Primary, false);

        // Zone with only SOA is not considered empty
        assert!(!zone.is_empty());
    }

    #[test]
    fn test_zone_iterators() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record = Record::from_rdata(name, TimeToLive::from(300), A::new(192, 168, 1, 1))
            .into_record_rdata();

        zone.upsert(a_record, SerialNumber::from(1)).unwrap();

        // Test records iterator
        assert_eq!(zone.records().count(), 2); // SOA + A
    }

    #[test]
    fn test_zone_properties() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone1 = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Test that zones can be inspected (no Clone trait)
        assert_eq!(zone1.name(), &name);
        assert_eq!(zone1.zone_type(), ZoneType::Primary);
        assert_eq!(zone1.records().count(), 1);
    }

    #[test]
    fn test_zone_id_uniqueness() {
        let name = create_test_name();
        let zone1 = Zone::empty(name.clone(), create_test_soa(), ZoneType::Primary, false);
        let zone2 = Zone::empty(name, create_test_soa(), ZoneType::Primary, false);

        assert_ne!(zone1.id(), zone2.id());
    }
}
