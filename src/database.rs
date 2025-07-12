use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use camino::Utf8PathBuf;
use hickory_proto::serialize::binary::BinEncodable;
use monarch_db::{MonarchDB, StaticMonarchConfiguration};
use rusqlite::{Connection, named_params};
use serde::Deserialize;

use crate::{
    authority::{Lookup as _, ZoneCatalog, ZoneInfo as _},
    rr::{LowerName, Name, Record, SerialNumber, SqlName, Zone, ZoneID},
};

pub(crate) trait FromRow {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized;
}

const MONARCH: StaticMonarchConfiguration<1> = StaticMonarchConfiguration {
    name: "walnut",
    enable_foreign_keys: true,
    migrations: [include_str!("migrations/01.zone.sql")],
};

/// Configuration for the SQLite backend.
#[derive(Debug, Clone, Deserialize)]
pub struct SqliteConfiguration {
    #[serde(default)]
    path: Option<Utf8PathBuf>,
}

/// SqliteCatalog is a catalog implementation that uses SQLite as the backend for DNS zones and records
#[derive(Debug, Clone)]
pub struct SqliteCatalog {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteCatalog {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    fn prepare(connection: Connection) -> rusqlite::Result<Self> {
        let db = MonarchDB::from(MONARCH);
        let connection = db.migrations(connection)?;
        Ok(Self::new(connection))
    }

    /// Creates a new SqliteCatalog instance from a configuration.
    pub fn new_from_config(config: &SqliteConfiguration) -> rusqlite::Result<Self> {
        let connection = if let Some(path) = &config.path {
            rusqlite::Connection::open(path)?
        } else {
            rusqlite::Connection::open_in_memory()?
        };

        Self::prepare(connection)
    }

    /// Creates a new SqliteCatalog instance from an in-memory database.
    pub fn new_in_memory() -> rusqlite::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Self::prepare(connection)
    }
}

impl From<rusqlite::Error> for crate::authority::CatalogError {
    fn from(err: rusqlite::Error) -> Self {
        crate::authority::CatalogError::new(err)
    }
}

impl ZoneCatalog for SqliteCatalog {
    #[tracing::instrument(skip_all, fields(zone=%id), level = "debug")]
    fn get(&self, id: ZoneID) -> Result<Zone, crate::authority::CatalogError> {
        let mut conn = self.connection.lock().expect("connection poisoned");
        let tx = conn.transaction()?;
        let zx = ZonePersistence::new(&tx);
        let zone = zx.get(id)?;
        tx.commit()?;
        Ok(zone)
    }

    #[tracing::instrument(skip_all, fields(%origin), level = "debug")]
    fn find(&self, origin: &LowerName) -> Result<Vec<Zone>, crate::authority::CatalogError> {
        let mut conn = self.connection.lock().expect("connection poisoned");
        let tx = conn.transaction()?;
        let zx = ZonePersistence::new(&tx);
        let zones = zx.find(origin)?;
        tx.commit()?;
        tracing::debug!("find {n} zones", n = zones.len());
        Ok(zones)
    }

    #[tracing::instrument(skip_all, fields(zone=%zone.name()), level = "debug")]
    fn upsert(&self, zone: Zone) -> Result<(), crate::authority::CatalogError> {
        let mut conn = self.connection.lock().expect("connection poisoned");
        let tx = conn.transaction()?;
        let zx = ZonePersistence::new(&tx);
        let n = zx.upsert(zone)?;
        tx.commit()?;
        tracing::debug!("upsert {n} zones");
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(zone=%id), level = "debug")]
    fn delete(&self, id: ZoneID) -> Result<(), crate::authority::CatalogError> {
        let mut conn = self.connection.lock().expect("connection poisoned");
        let tx = conn.transaction()?;
        let zx = ZonePersistence::new(&tx);
        let n = zx.delete(id)?;
        tx.commit()?;
        tracing::debug!("delete {n} zones");
        Ok(())
    }

    fn list(&self) -> Result<Vec<Name>, crate::authority::CatalogError> {
        let conn = self.connection.lock().expect("connection poisoned");
        let zx = ZonePersistence::new(&conn);
        let names = zx.list()?;
        tracing::debug!("list {n} zones", n = names.len());
        Ok(names)
    }
}

struct QueryBuilder<const N: usize> {
    table: &'static str,
    columns: [&'static str; N],
    primary: &'static str,
}

impl<const N: usize> QueryBuilder<N> {
    fn select(&self, filters: &str) -> String {
        let columns = self.columns.join(", ");
        format!(
            "SELECT {columns} FROM {table} {filters}",
            table = self.table
        )
    }

    fn select_for_join(&self, filters: &str) -> String {
        let columns = self
            .columns
            .iter()
            .map(|c| format!("{table}.{c} AS {c}", table = self.table))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "SELECT {columns} FROM {table} {filters}",
            table = self.table
        )
    }

    fn insert(&self) -> String {
        let columns = self.columns.join(", ");
        let params = self
            .columns
            .iter()
            .map(|c| format!(":{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "INSERT INTO {table} ({columns}) VALUES ({params})",
            table = self.table
        )
    }

    fn upsert(&self) -> String {
        let conflicts = self
            .columns
            .iter()
            .filter(|&&c| c != self.primary)
            .map(|c| format!("{c}=excluded.{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{insert} ON CONFLICT ({conflict}) DO UPDATE SET {conflicts}",
            insert = self.insert(),
            conflict = self.primary
        )
    }

    fn delete(&self) -> String {
        format!(
            "DELETE FROM {table} WHERE {primary}=:{primary}",
            table = self.table,
            primary = self.primary
        )
    }
}

#[derive(Debug, Clone)]
struct ZonePersistence<'c> {
    connection: &'c Connection,
}

impl<'c> ZonePersistence<'c> {
    fn new(connection: &'c Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<5> = QueryBuilder {
        table: "zone",
        columns: ["id", "name", "zone_type", "allow_axfr", "dns_class"],
        primary: "id",
    };

    /// Get a single zone by ID
    #[tracing::instrument(skip_all, fields(zone=%id), level = "trace")]
    fn get(&self, id: ZoneID) -> rusqlite::Result<Zone> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE id = :zone_id"))?;
        let mut zone = stmt.query_one(named_params! { ":zone_id": id }, Zone::from_row)?;

        let rx = RecordPersistence::new(self.connection);
        rx.populate_zone(&mut zone)?;

        Ok(zone)
    }

    /// Find zones based on zone name
    #[tracing::instrument(skip_all, fields(zone=%name), level = "trace")]
    fn find(&self, name: &LowerName) -> rusqlite::Result<Vec<Zone>> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE lower(name) = lower(:name)"))?;
        let mut zones = stmt
            .query_map(
                named_params! { ":name": SqlName::from(name.clone()) },
                Zone::from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;

        if !zones.is_empty() {
            let rx = RecordPersistence::new(self.connection);
            rx.populate_zones(name, zones.as_mut_slice())?;
        }

        Ok(zones)
    }

    #[tracing::instrument(skip_all, fields(zone=%zone.name()), level = "trace")]
    fn upsert(&self, zone: Zone) -> rusqlite::Result<usize> {
        let guard = tracing::trace_span!("zone").entered();

        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        let n = stmt.execute(named_params! { ":id": zone.id(), ":name": SqlName::from(zone.name().clone()), ":zone_type": zone.zone_type(), ":allow_axfr": zone.allow_axfr(), ":dns_class": u16::from(zone.dns_class()) })?;
        if n > 0 {
            tracing::trace!("affected {} rows", n);
        } else {
            tracing::trace!("no rows affected")
        }
        drop(guard);

        if !zone.is_empty() {
            let rx = RecordPersistence::new(self.connection);
            rx.upsert_records(&zone)?;
        }

        Ok(n)
    }

    #[tracing::instrument(skip_all, fields(zone=%id), level = "trace")]
    fn delete(&self, id: ZoneID) -> rusqlite::Result<usize> {
        // CASCADE will handle deleting the associated records.
        let mut stmt = self.connection.prepare(&Self::TABLE.delete())?;
        let n = stmt.execute(named_params! { ":id": id })?;
        Ok(n)
    }

    #[tracing::instrument(skip_all, level = "trace")]
    fn list(&self) -> rusqlite::Result<Vec<Name>> {
        let mut stmt = self.connection.prepare(&format!(
            "SELECT name FROM {table}",
            table = Self::TABLE.table
        ))?;
        let names = stmt
            .query_map([], |row| Ok(row.get::<_, SqlName>("name")?.into()))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }
}

#[derive(Debug, Clone)]
struct RecordPersistence<'c> {
    connection: &'c Connection,
}

impl<'c> RecordPersistence<'c> {
    fn new(connection: &'c Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<9> = QueryBuilder {
        table: "record",
        columns: [
            "id",
            "zone_id",
            "name_labels",
            "dns_class",
            "ttl",
            "record_type",
            "rdata",
            "mdns_cache_flush",
            "expires",
        ],
        primary: "id",
    };

    /// Populate a series of zones with records
    #[tracing::instrument("populate_many", skip_all, level = "trace")]
    fn populate_zones(&self, origin: &LowerName, zones: &mut [Zone]) -> rusqlite::Result<()> {
        tracing::trace!("Joined load for {} zones", zones.len());
        let mut stmt = self.connection.prepare(&Self::TABLE.select_for_join(
            "JOIN zone ON record.zone_id = zone.id WHERE lower(zone.name) == lower(:name)",
        ))?;

        let riter = stmt.query_map(
            named_params! { ":name": SqlName::from(origin.clone()) },
            |row| {
                let record = Record::from_row(row)?;
                let zone_id: ZoneID = row.get("zone_id")?;
                Ok((zone_id, record))
            },
        )?;

        let mut records: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut n = 0usize;
        for result in riter {
            let (zone, record) = result?;
            records.entry(zone).or_default().push(record);
            n += 1;
        }
        tracing::trace!("Populating {} zones from {} records", records.len(), n);
        for zone in zones {
            for record in records.remove(&zone.id()).unwrap_or_default() {
                if record.expired() {
                    continue;
                }
                zone.upsert(record, SerialNumber::ZERO)
                    .expect("Zone and record mismatch during DB Load");
            }
        }

        Ok(())
    }

    /// Populate a single zone with records
    #[tracing::instrument("populate", skip_all, level = "trace")]
    fn populate_zone(&self, zone: &mut Zone) -> rusqlite::Result<()> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE zone_id = :zone_id"))?;
        let records = stmt
            .query_map(named_params! { ":zone_id": zone.id() }, Record::from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        for record in records {
            if record.expired() {
                continue;
            }
            zone.upsert(record, SerialNumber::ZERO)
                .expect("Zone and record mismatch during DB Load");
        }

        Ok(())
    }

    #[tracing::instrument("delete_orphans", skip_all, level = "trace")]
    fn delete_orphaned_records(&self, zone: &Zone) -> rusqlite::Result<()> {
        let params: Vec<_> = zone
            .records()
            .filter(|r| !r.expired())
            .map(|record| record.id())
            .collect();
        let param_template = std::iter::repeat_n("?", params.len())
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            "DELETE FROM {table} WHERE zone_id = :zone_id AND id NOT IN ({param_template})",
            table = Self::TABLE.table
        );
        let mut stmt = self.connection.prepare(&query)?;
        stmt.raw_bind_parameter(c":zone_id", zone.id())?;
        tracing::trace!("retaining {} records", params.len());
        for (idx, param) in params.into_iter().enumerate() {
            let pidx = idx + 2;
            stmt.raw_bind_parameter(pidx, param)?;
        }
        let nrows = stmt.raw_execute()?;
        tracing::trace!("dropped {} records", nrows);
        Ok(())
    }

    /// Upsert the set of records which belong to this zone.
    #[tracing::instrument("upsert", skip_all, level = "trace")]
    fn upsert_records(&self, zone: &Zone) -> rusqlite::Result<()> {
        self.delete_orphaned_records(zone)?;
        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        let mut n = 0;
        for record in zone.records() {
            if record.expired() {
                continue;
            }
            n += stmt.execute(named_params! {
                ":id": record.id(),
                ":zone_id": zone.id(),
                ":name_labels": SqlName::from(record.name().clone()),
                ":dns_class": u16::from(record.dns_class()),
                ":ttl": record.ttl(),
                ":record_type": u16::from(record.record_type()),
                ":rdata": record.rdata().to_bytes().map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
                ":mdns_cache_flush": record.mdns_cache_flush(),
                ":expires": record.expires()
            })?;
        }

        tracing::trace!("upsert {n} records");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rr::{Record, TimeToLive, Zone, ZoneType};
    use hickory_proto::rr::{RecordType, rdata};
    use std::path::Path;
    use tempfile::TempDir;

    fn create_test_zone() -> Zone {
        let name = Name::from_utf8("test.example.com").unwrap();
        let soa = rdata::SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        let soa_record = Record::from_rdata(name.clone(), TimeToLive::from(3600), soa);
        Zone::empty(name, soa_record, ZoneType::Primary, false)
    }

    fn create_test_a_record() -> Record {
        let name = Name::from_utf8("www.test.example.com").unwrap();
        let ttl = TimeToLive::from(300);
        let rdata = rdata::A::new(192, 168, 1, 1);
        Record::from_rdata(name, ttl, rdata).into_record_rdata()
    }

    #[test]
    fn test_sqlite_configuration_serde() {
        // Test deserialization with no path (default)
        let json = "{}";
        let config: SqliteConfiguration = serde_json::from_str(json).unwrap();
        assert!(config.path.is_none());

        // Test deserialization with path
        let json = r#"{"path": "/tmp/test.db"}"#;
        let config: SqliteConfiguration = serde_json::from_str(json).unwrap();
        assert_eq!(config.path, Some(Utf8PathBuf::from("/tmp/test.db")));
    }

    #[test]
    fn test_sqlite_catalog_new() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let catalog = SqliteCatalog::new(connection);

        // Should be created successfully
        assert!(catalog.connection.lock().is_ok());
    }

    #[test]
    fn test_sqlite_catalog_new_in_memory() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();

        // Should be created successfully with migrations applied
        assert!(catalog.connection.lock().is_ok());
    }

    #[test]
    fn test_sqlite_catalog_new_from_config_in_memory() {
        let config = SqliteConfiguration { path: None };
        let catalog = SqliteCatalog::new_from_config(&config).unwrap();

        // Should be created successfully
        assert!(catalog.connection.lock().is_ok());
    }

    #[test]
    fn test_sqlite_catalog_new_from_config_with_file() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = SqliteConfiguration {
            path: Some(Utf8PathBuf::from_path_buf(db_path).unwrap()),
        };

        let catalog = SqliteCatalog::new_from_config(&config).unwrap();

        // Should be created successfully
        assert!(catalog.connection.lock().is_ok());

        // File should exist
        assert!(Path::new(config.path.as_ref().unwrap()).exists());
    }

    #[test]
    fn test_catalog_upsert_and_get_zone() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let zone = create_test_zone();
        let zone_id = zone.id();
        let expected_name = zone.name().clone();
        let expected_type = zone.zone_type();

        // Upsert zone
        let result = catalog.upsert(zone);
        assert!(result.is_ok());

        // Get zone back
        let retrieved_zone = catalog.get(zone_id).unwrap();
        assert_eq!(retrieved_zone.id(), zone_id);
        assert_eq!(retrieved_zone.name(), &expected_name);
        assert_eq!(retrieved_zone.zone_type(), expected_type);
    }

    #[test]
    fn test_catalog_find_zone() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let zone = create_test_zone();
        let zone_name = LowerName::from(zone.name().clone());
        let expected_name = zone.name().clone();

        // Upsert zone
        catalog.upsert(zone).unwrap();

        // Find zone by name
        let found_zones = catalog.find(&zone_name).unwrap();
        assert_eq!(found_zones.len(), 1);
        assert_eq!(found_zones[0].name(), &expected_name);
    }

    #[test]
    fn test_catalog_find_nonexistent_zone() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let nonexistent_name = LowerName::from(Name::from_utf8("nonexistent.example.com").unwrap());

        // Find nonexistent zone
        let found_zones = catalog.find(&nonexistent_name).unwrap();
        assert!(found_zones.is_empty());
    }

    #[test]
    fn test_catalog_delete_zone() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let zone = create_test_zone();
        let zone_id = zone.id();

        // Upsert zone
        catalog.upsert(zone).unwrap();

        // Verify zone exists
        assert!(catalog.get(zone_id).is_ok());

        // Delete zone
        let result = catalog.delete(zone_id);
        assert!(result.is_ok());

        // Verify zone no longer exists
        assert!(catalog.get(zone_id).is_err());
    }

    #[test]
    fn test_catalog_list_zones() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();

        // Start with empty list
        let initial_list = catalog.list().unwrap();
        assert!(initial_list.is_empty());

        // Add a zone
        let zone = create_test_zone();
        let zone_name = zone.name().clone();
        catalog.upsert(zone).unwrap();

        // List should contain the zone
        let zone_list = catalog.list().unwrap();
        assert_eq!(zone_list.len(), 1);
        assert_eq!(zone_list[0], zone_name);
    }

    #[test]
    fn test_catalog_multiple_zones() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();

        // Create multiple zones
        let zone1 = create_test_zone();
        let zone1_name = zone1.name().clone();
        let zone2 = {
            let name = Name::from_utf8("another.example.com").unwrap();
            let soa = rdata::SOA::new(
                name.clone(),
                Name::from_utf8("admin.another.example.com").unwrap(),
                1,
                3600,
                1800,
                604800,
                86400,
            );
            let soa_record = Record::from_rdata(name.clone(), TimeToLive::from(3600), soa);
            Zone::empty(name, soa_record, ZoneType::Secondary, true)
        };
        let zone2_name = zone2.name().clone();

        // Upsert both zones
        catalog.upsert(zone1).unwrap();
        catalog.upsert(zone2).unwrap();

        // List should contain both zones
        let zone_list = catalog.list().unwrap();
        assert_eq!(zone_list.len(), 2);
        assert!(zone_list.contains(&zone1_name));
        assert!(zone_list.contains(&zone2_name));
    }

    #[test]
    fn test_catalog_zone_with_records() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let mut zone = create_test_zone();
        let a_record = create_test_a_record();

        // Add record to zone
        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();
        let zone_id = zone.id();

        // Upsert zone with records
        catalog.upsert(zone).unwrap();

        // Retrieve zone and verify records
        let retrieved_zone = catalog.get(zone_id).unwrap();
        assert_eq!(retrieved_zone.records().count(), 2); // SOA + A record

        // Verify A record exists
        let a_records: Vec<_> = retrieved_zone
            .records()
            .filter(|r| r.record_type() == RecordType::A)
            .collect();
        assert_eq!(a_records.len(), 1);
    }

    #[test]
    fn test_catalog_concurrent_access() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let zone = create_test_zone();
        let zone_name = LowerName::from(zone.name().clone());

        // Test that the catalog can handle concurrent access via Arc<Mutex<Connection>>
        let catalog_clone = catalog.clone();

        // Upsert in original
        catalog.upsert(zone).unwrap();

        // Read from clone
        let found_zones = catalog_clone.find(&zone_name).unwrap();
        assert_eq!(found_zones.len(), 1);
    }

    #[test]
    fn test_catalog_debug_format() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let debug_string = format!("{:?}", catalog);
        assert!(debug_string.contains("SqliteCatalog"));
    }

    #[test]
    fn test_zone_update_serial_number() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let mut zone = create_test_zone();
        let a_record = create_test_a_record();

        // Add record with serial 1
        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();
        let zone_id = zone.id();
        catalog.upsert(zone).unwrap();

        // Retrieve zone and add same record with serial 2 (simulating an update)
        let mut retrieved_zone = catalog.get(zone_id).unwrap();
        retrieved_zone
            .upsert(a_record, SerialNumber::from(2))
            .unwrap();
        catalog.upsert(retrieved_zone).unwrap();

        // Retrieve and verify the zone was updated
        let final_zone = catalog.get(zone_id).unwrap();
        assert_eq!(final_zone.records().count(), 2); // SOA + A record (not duplicated)
    }

    #[test]
    fn test_zone_name_case_insensitive_search() {
        let catalog = SqliteCatalog::new_in_memory().unwrap();
        let zone = create_test_zone();
        let expected_name = zone.name().clone();

        catalog.upsert(zone).unwrap();

        // Search with different case
        let upper_name = LowerName::from(Name::from_utf8("TEST.EXAMPLE.COM").unwrap());
        let found_zones = catalog.find(&upper_name).unwrap();
        assert_eq!(found_zones.len(), 1);
        assert_eq!(found_zones[0].name(), &expected_name);
    }
}
