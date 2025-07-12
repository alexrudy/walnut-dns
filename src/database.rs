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
