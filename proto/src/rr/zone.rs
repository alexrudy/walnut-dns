use std::{collections::BTreeMap, fs, io, path::Path};

use hickory_proto::{
    rr::{DNSClass, Name, RrKey, rdata},
    serialize::txt::Parser,
};
use rusqlite::{ToSql, types::FromSql};
use tracing::{debug, error, info};

use crate::serialize::sqlite::FromRow;

use super::{Record, SqlName, ZoneID, rset::RecordSet};

/// The authoratative nature of this zone.
///
/// This type exists to provide a canonical form to write to a database.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum ZoneType {
    /// This is a primary nameserver, and holds the zone files of record.
    Primary = 1,
    /// This nameserver replicates the zone files of recrod.
    Secondary = 2,
    /// This nameserver provides exteranal zone data
    External = 3,
}

impl ZoneType {
    pub fn is_authoritative(&self) -> bool {
        matches!(self, ZoneType::Primary | ZoneType::Secondary)
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

/// Represents a DNS Zone/Authority and associated records
#[derive(Debug, Clone)]
pub struct Zone {
    pub id: ZoneID,
    pub zone_type: ZoneType,
    pub name: Name,
    pub origin: Name,
    pub allow_axfr: bool,
    pub dns_class: DNSClass,
    pub records: BTreeMap<RrKey, RecordSet>,
}

impl Zone {
    /// Create a new empty zone with only a SOA record
    ///
    /// Creates a new DNS zone containing only the required SOA record.
    /// Additional records can be added later using the zone's methods.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name (e.g., "example.com.")
    /// * `soa` - The Start of Authority record for this zone
    /// * `zone_type` - The type of zone (Primary, Secondary, External)
    /// * `allow_axfr` - Whether to allow zone transfers (AXFR)
    ///
    /// # Returns
    ///
    /// A new zone instance
    pub fn empty(
        name: Name,
        soa: Record<rdata::SOA>,
        zone_type: ZoneType,
        allow_axfr: bool,
    ) -> Self {
        let mut records = BTreeMap::new();
        records.insert(soa.rrkey(), RecordSet::from_record(name.clone(), soa));
        let origin = name.to_lowercase();

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

    /// Create a zone from an iterator of record sets
    ///
    /// Creates a new DNS zone from a collection of record sets. This is useful
    /// when loading a zone from a file or database.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name
    /// * `records` - An iterator of record sets to include in the zone
    /// * `zone_type` - The type of zone (Primary, Secondary, External)
    ///
    /// # Returns
    ///
    /// A new zone instance containing the provided records
    pub fn from_rrsets(
        name: Name,
        records: impl Iterator<Item = RecordSet>,
        zone_type: ZoneType,
    ) -> Self {
        let mut rrsets = BTreeMap::new();
        for record in records {
            rrsets.insert(record.rrkey(), record);
        }
        let origin = name.to_lowercase();

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
    /// Get the unique database identifier for this zone
    ///
    /// Returns the unique ID assigned to this zone when it was created.
    /// This ID is used internally for database operations.
    ///
    /// # Returns
    ///
    /// The unique zone identifier
    pub fn id(&self) -> ZoneID {
        self.id
    }

    /// Get the name of this zone
    ///
    /// Returns the fully qualified domain name that this zone is authoritative for.
    ///
    /// # Returns
    ///
    /// A reference to the zone name
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Get the type of this zone
    ///
    /// Returns whether this zone is Primary (authoritative), Secondary (slave),
    /// or External (forwarding).
    ///
    /// # Returns
    ///
    /// The zone type
    pub fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Check if zone transfers are allowed
    ///
    /// Returns whether this zone permits AXFR (zone transfer) requests.
    ///
    /// # Returns
    ///
    /// `true` if zone transfers are allowed
    pub fn allow_axfr(&self) -> bool {
        self.allow_axfr
    }

    /// Set whether to allow zone transfers
    ///
    /// Enables or disables AXFR (zone transfer) requests for this zone.
    ///
    /// # Arguments
    ///
    /// * `allow_axfr` - Whether to allow zone transfers
    ///
    /// # Returns
    ///
    /// A mutable reference to this zone for method chaining
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) -> &mut Self {
        self.allow_axfr = allow_axfr;
        self
    }

    /// Set the DNS class of this zone
    ///
    /// Updates the DNS class (typically IN for Internet) for this zone.
    ///
    /// # Arguments
    ///
    /// * `dns_class` - The new DNS class
    ///
    /// # Returns
    ///
    /// A mutable reference to this zone for method chaining
    pub fn set_dns_class(&mut self, dns_class: DNSClass) -> &mut Self {
        self.dns_class = dns_class;
        self
    }

    /// Get an iterator over all records in this zone
    ///
    /// Returns an iterator that yields all DNS records in the zone,
    /// including signed records (with RRSIG signatures).
    ///
    /// # Returns
    ///
    /// An iterator over all records in the zone
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .flat_map(|rrset| rrset.signed_records())
    }

    /// Replace a record set in this zone
    ///
    /// Replaces an existing record set with a new one, or inserts the new
    /// record set if no matching one exists.
    ///
    /// # Arguments
    ///
    /// * `rrset` - The record set to insert or replace
    ///
    /// # Returns
    ///
    /// The previously existing record set, or None if this is a new insertion
    pub fn replace(&mut self, rrset: RecordSet) -> Option<RecordSet> {
        let key = rrset.rrkey();
        self.records.insert(key, rrset)
    }

    /// Check if this zone is empty
    ///
    /// Returns true if the zone contains no record sets. Note that a zone
    /// with only a SOA record is not considered empty.
    ///
    /// # Returns
    ///
    /// `true` if the zone contains no record sets
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
        let origin = name.to_lowercase();

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

impl Zone {
    /// Load a zone from a DNS zone file
    ///
    /// Reads and parses a DNS zone file, creating a new zone instance
    /// with the records found in the file.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone origin (root name for the zone)
    /// * `path` - Path to the zone file to read
    /// * `zone_type` - The type of zone to create
    ///
    /// # Returns
    ///
    /// A new zone instance loaded from the file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed
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
    use crate::rr::TimeToLive;

    use super::*;

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com.").unwrap()
    }

    fn create_test_soa() -> Record<rdata::SOA> {
        let name = create_test_name();
        let soa = rdata::SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        Record::from_rdata(name, TimeToLive::from(3600), soa)
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
        assert_eq!(zone.dns_class, DNSClass::IN);
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
