//! Database Catalogs for DNS

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use camino::Utf8PathBuf;
use hickory_proto::serialize::binary::BinEncodable;
use monarch_db::{MonarchDB, StaticMonarchConfiguration};
use rusqlite::named_params;
use serde::Deserialize;

pub use self::dnssec::{DNSKey, DNSSecStore};
use self::journal::SqliteJournal;
use crate::authority::{Lookup as _, ZoneAuthority, ZoneInfo as _};
use crate::catalog::{CatalogError, CatalogStore};
use crate::rr::{LowerName, Name, Record, SerialNumber, SqlName, Zone, ZoneID};

pub mod dnssec;
pub mod journal;

#[cfg(feature = "pool")]
pub type Error = bb8::RunError<rusqlite::Error>;
#[cfg(not(feature = "pool"))]
pub type Error = rusqlite::Error;

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

#[cfg(feature = "pool")]
mod pool;

#[cfg(feature = "pool")]
pub use pool::RusqliteConnectionManager;

/// Trait for deserializing objects from SQLite rows
///
/// This trait provides a way to construct objects from SQLite query results.
/// It's used throughout the database layer to convert raw row data into
/// strongly-typed Rust structures.
pub(crate) trait FromRow {
    /// Create an instance from a SQLite row
    ///
    /// Extracts the necessary data from the provided row and constructs
    /// a new instance of the implementing type.
    ///
    /// # Arguments
    ///
    /// * `row` - The SQLite row containing the data
    ///
    /// # Returns
    ///
    /// A new instance of the implementing type
    ///
    /// # Errors
    ///
    /// Returns an error if the row data cannot be converted to the expected type
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized;
}

const MONARCH: StaticMonarchConfiguration<1> = StaticMonarchConfiguration {
    name: "walnut",
    enable_foreign_keys: true,
    migrations: [include_str!("../migrations/01.zone.sql")],
};

/// Provides access to a (possibly) pooled connection
#[derive(Debug, Clone)]
pub struct ConnectionManager {
    inner: InnerConnectionManager,
}

#[derive(Debug, Clone)]
enum InnerConnectionManager {
    #[cfg(feature = "pool")]
    Pool(self::pool::Pool),
    Single(Arc<Mutex<rusqlite::Connection>>),
}

impl From<rusqlite::Connection> for ConnectionManager {
    fn from(value: rusqlite::Connection) -> Self {
        tracing::trace!("New single connection");
        ConnectionManager {
            inner: InnerConnectionManager::Single(Arc::new(Mutex::new(value))),
        }
    }
}

#[cfg(feature = "pool")]
impl From<self::pool::Pool> for ConnectionManager {
    fn from(value: self::pool::Pool) -> Self {
        tracing::trace!("New pooled connection");

        ConnectionManager {
            inner: InnerConnectionManager::Pool(value),
        }
    }
}

impl ConnectionManager {
    /// Get the underlying conneciton
    pub async fn get(&self) -> Result<Connection<'_>> {
        match &self.inner {
            #[cfg(feature = "pool")]
            InnerConnectionManager::Pool(pool) => pool.get().await.map(Connection::pool),
            InnerConnectionManager::Single(locked) => Ok(Connection::single(
                locked.lock().expect("connection mutex poisoned"),
            )),
        }
    }
}

#[derive(Debug)]
enum InnerConnection<'c> {
    #[cfg(feature = "pool")]
    Pool(bb8::PooledConnection<'c, self::pool::RusqliteConnectionManager>),
    Single(std::sync::MutexGuard<'c, rusqlite::Connection>),
}

/// A unified connection which is either derived from a
/// single connection in a Mutex, or a proper connection pool.
#[derive(Debug)]
pub struct Connection<'c> {
    inner: InnerConnection<'c>,
}

impl<'c> Connection<'c> {
    #[cfg(feature = "pool")]
    fn pool(pool: bb8::PooledConnection<'c, self::pool::RusqliteConnectionManager>) -> Self {
        Self {
            inner: InnerConnection::Pool(pool),
        }
    }

    fn single(single: std::sync::MutexGuard<'c, rusqlite::Connection>) -> Self {
        Self {
            inner: InnerConnection::Single(single),
        }
    }
}

impl<'c> Deref for Connection<'c> {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        match &self.inner {
            #[cfg(feature = "pool")]
            InnerConnection::Pool(pool) => pool,
            InnerConnection::Single(single) => single,
        }
    }
}

impl<'c> DerefMut for Connection<'c> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.inner {
            #[cfg(feature = "pool")]
            InnerConnection::Pool(pool) => pool,
            InnerConnection::Single(single) => single,
        }
    }
}

/// Configuration for the SQLite database backend
///
/// This structure contains all the configuration options needed to set up
/// a SQLite database connection for the DNS server.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SqliteConfiguration {
    /// Path to the SQLite database file
    ///
    /// If None, an in-memory database will be used. For persistent storage,
    /// provide a path to where the database file should be created or opened.
    #[serde(default)]
    path: Option<Utf8PathBuf>,

    /// Busy timeout in milliseconds
    ///
    /// How long to wait when the database is locked by another connection
    /// before giving up. Only used when connection pooling is enabled.
    #[allow(dead_code)]
    busy_timeout: Option<u64>,
}

/// SQLite-based DNS zone and record storage
///
/// SqliteStore provides a complete implementation of DNS zone storage using SQLite
/// as the backend database. It supports both in-memory and file-based databases,
/// with optional connection pooling for improved concurrency.
///
/// The store handles:
/// - Zone metadata storage and retrieval
/// - DNS record persistence with proper indexing
/// - Transaction-based operations for consistency
/// - Automatic database schema migrations
/// - Connection pooling (when enabled)
#[derive(Debug, Clone)]
pub struct SqliteStore {
    manager: ConnectionManager,
}

impl SqliteStore {
    /// Create a new SQLite store with an existing connection manager
    ///
    /// Initializes the SQLite store with the provided connection manager
    /// and applies any necessary database migrations.
    ///
    /// # Arguments
    ///
    /// * `manager` - The connection manager to use for database access
    ///
    /// # Returns
    ///
    /// A new SqliteStore instance
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be accessed or migrations fail
    pub async fn new(manager: ConnectionManager) -> Result<Self> {
        let db = MonarchDB::from(MONARCH);
        {
            let mut connection = manager.get().await?;
            db.migrations(&mut connection).prepare()?;
        }
        Ok(Self { manager })
    }

    /// Create a new SQLite store from configuration
    ///
    /// Creates a new SQLite store using the provided configuration.
    /// The configuration determines whether to use a file-based or in-memory database,
    /// and whether to enable connection pooling.
    ///
    /// # Arguments
    ///
    /// * `config` - The SQLite configuration
    ///
    /// # Returns
    ///
    /// A new SqliteStore instance
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created or accessed
    pub async fn new_from_config(config: &SqliteConfiguration) -> Result<Self> {
        let manager = if let Some(path) = &config.path {
            #[cfg(not(feature = "pool"))]
            {
                rusqlite::Connection::open(path)?.into()
            }
            #[cfg(feature = "pool")]
            {
                self::pool::pool(
                    path,
                    std::time::Duration::from_millis(config.busy_timeout.unwrap_or(0)),
                )
                .await?
                .into()
            }
        } else {
            rusqlite::Connection::open_in_memory()?.into()
        };

        Self::new(manager).await
    }

    /// Create a new SQLite store using an in-memory database
    ///
    /// Creates a new store that uses an in-memory SQLite database.
    /// This is useful for testing or temporary storage where persistence
    /// is not required.
    ///
    /// # Returns
    ///
    /// A new SqliteStore instance with in-memory storage
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory database cannot be created
    pub async fn new_in_memory() -> Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Self::new(connection.into()).await
    }

    /// Get a journal for recording DNS operations
    ///
    /// Returns a journal that can be used to record DNS update operations
    /// for this store. The journal uses the same connection manager as the store.
    ///
    /// # Returns
    ///
    /// A SqliteJournal instance for this store
    pub fn journal(&self) -> SqliteJournal {
        SqliteJournal::new(self.manager.clone())
    }
}

impl From<Error> for CatalogError {
    fn from(err: Error) -> Self {
        CatalogError::new(err)
    }
}

#[cfg(feature = "pool")]
impl From<rusqlite::Error> for CatalogError {
    fn from(err: rusqlite::Error) -> Self {
        CatalogError::new(err)
    }
}

impl SqliteStore {
    /// Get a database connection from the connection manager
    ///
    /// Returns a database connection that can be used for direct SQL operations.
    /// The connection is automatically managed and will be returned to the pool
    /// when dropped (if pooling is enabled).
    ///
    /// # Returns
    ///
    /// A database connection
    ///
    /// # Errors
    ///
    /// Returns an error if no connection is available
    pub async fn connection(&self) -> Result<Connection<'_>, CatalogError> {
        self.manager.get().await.map_err(Into::into)
    }

    /// Get a zone by its unique identifier
    ///
    /// Retrieves a complete zone (including all its records) from the database
    /// using the zone's unique ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the zone to retrieve
    ///
    /// # Returns
    ///
    /// The zone with all its records
    ///
    /// # Errors
    ///
    /// Returns an error if the zone is not found or cannot be loaded
    #[tracing::instrument(skip_all, fields(zone=%id), level = "debug")]
    pub async fn get(&self, id: ZoneID) -> Result<Zone, CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);
            let zone = zx.get(id)?;
            tx.commit()?;
            Ok(zone)
        })
    }

    /// Delete a zone and all its records
    ///
    /// Removes a zone and all associated records from the database.
    /// This operation is permanent and cannot be undone.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the zone to delete
    ///
    /// # Returns
    ///
    /// Success if the zone was deleted
    ///
    /// # Errors
    ///
    /// Returns an error if the zone cannot be deleted
    #[tracing::instrument(skip_all, fields(zone=%id), level = "debug")]
    pub async fn delete(&self, id: ZoneID) -> Result<(), CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);
            let n = zx.delete(id)?;
            tx.commit()?;
            tracing::debug!("delete {n} zones");
            Ok(())
        })
    }

    /// Insert or update a zone and all its records
    ///
    /// Stores a zone and all its records in the database. If the zone already
    /// exists, it will be updated with the new data.
    ///
    /// # Arguments
    ///
    /// * `zone` - The zone to insert or update
    ///
    /// # Returns
    ///
    /// The number of zones affected (typically 1)
    ///
    /// # Errors
    ///
    /// Returns an error if the zone cannot be stored
    #[tracing::instrument(skip_all, fields(zone=%zone.name()), level = "debug")]
    pub async fn insert(&self, zone: &Zone) -> Result<usize, CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);
            let n = zx.upsert(zone)?;
            tx.commit()?;
            tracing::debug!("insert {n} zones");
            Ok(n)
        })
    }
}

#[async_trait::async_trait]
impl CatalogStore<ZoneAuthority<Zone>> for SqliteStore {
    #[tracing::instrument(skip_all, fields(%origin), level = "debug")]
    async fn find(
        &self,
        origin: &LowerName,
    ) -> Result<Option<Vec<ZoneAuthority<Zone>>>, CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);
            let zones = zx.find(origin)?;
            tx.commit()?;
            tracing::debug!(
                "found {n} zones",
                n = zones.as_ref().map(|z| z.len()).unwrap_or_default()
            );
            Ok(zones.map(|z| z.into_iter().map(ZoneAuthority::new).collect()))
        })
    }

    #[tracing::instrument(skip_all, fields(zone=%name), level = "debug")]
    async fn upsert(
        &self,
        name: LowerName,
        zones: &[ZoneAuthority<Zone>],
    ) -> Result<(), CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);

            // First clear existing name
            zx.clear(&name)?;
            let mut n = 0;
            for zone in zones {
                n += zx.upsert(zone)?;
            }
            tx.commit()?;
            tracing::debug!("upsert {n} zones");
            Ok(())
        })
    }

    #[tracing::instrument(skip_all, level = "debug")]
    async fn list(&self, name: &LowerName) -> Result<Vec<Name>, CatalogError> {
        let conn = self.manager.get().await?;
        tracing::trace!("List records for {name}");
        crate::block_in_place(|| {
            let zx = ZonePersistence::new(&conn);
            let names = zx.list(name)?;
            tracing::debug!("list {n} zones", n = names.len());
            Ok(names)
        })
    }

    #[tracing::instrument(skip_all, fields(zone=%name), level = "debug")]
    async fn remove(
        &self,
        name: &LowerName,
    ) -> Result<Option<Vec<ZoneAuthority<Zone>>>, CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);
            let zones = zx.find(name)?;
            let n = zx.clear(name)?;
            tracing::debug!("removed {n} zones");
            tx.commit()?;
            Ok(zones.map(|z| z.into_iter().map(ZoneAuthority::new).collect()))
        })
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
pub(crate) struct ZonePersistence<'c> {
    connection: &'c rusqlite::Connection,
}

impl<'c> ZonePersistence<'c> {
    pub(crate) fn new(connection: &'c rusqlite::Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<5> = QueryBuilder {
        table: "zone",
        columns: ["id", "name", "zone_type", "allow_axfr", "dns_class"],
        primary: "id",
    };

    /// Get a single zone by ID
    #[tracing::instrument(skip_all, fields(zone=%id), level = "trace")]
    pub(crate) fn get(&self, id: ZoneID) -> rusqlite::Result<Zone> {
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
    pub(crate) fn find(&self, name: &LowerName) -> rusqlite::Result<Option<Vec<Zone>>> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE lower(name) = lower(:name)"))?;

        let mut name = name.clone();
        loop {
            let mut zones = stmt
                .query_map(
                    named_params! { ":name": SqlName::from(name.clone()) },
                    Zone::from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;

            if !zones.is_empty() {
                let rx = RecordPersistence::new(self.connection);
                rx.populate_zones(&name, zones.as_mut_slice())?;
                return Ok(Some(zones));
            }

            if !name.is_root() {
                name = name.base_name();
            } else {
                return Ok(None);
            }
        }
    }

    #[tracing::instrument(skip_all, fields(zone=%zone.name()), level = "trace")]
    pub(crate) fn upsert(&self, zone: &Zone) -> rusqlite::Result<usize> {
        let guard = tracing::trace_span!("zone").entered();

        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        tracing::trace!("preparing statement for insert with name={}", zone.name());
        let n = stmt.execute(named_params! { ":id": zone.id(), ":name": SqlName::from(zone.name().clone()), ":zone_type": zone.zone_type(), ":allow_axfr": zone.allow_axfr(), ":dns_class": u16::from(zone.dns_class()) })?;
        if n > 0 {
            tracing::trace!("affected {} rows", n);
        } else {
            tracing::trace!("no rows affected")
        }
        drop(guard);

        if !zone.is_empty() {
            let rx = RecordPersistence::new(self.connection);
            rx.upsert_records(zone)?;
        }

        Ok(n)
    }

    #[tracing::instrument(skip_all, fields(zone=%id), level = "trace")]
    pub(crate) fn delete(&self, id: ZoneID) -> rusqlite::Result<usize> {
        // CASCADE will handle deleting the associated records.
        let mut stmt = self.connection.prepare(&Self::TABLE.delete())?;
        let n = stmt.execute(named_params! { ":id": id })?;
        Ok(n)
    }

    #[tracing::instrument(skip_all, fields(zone=%name), level = "trace")]
    pub(crate) fn clear(&self, name: &LowerName) -> rusqlite::Result<usize> {
        // CASCADE will handle deleting the associated records.
        let mut stmt = self.connection.prepare(&format!(
            "DELETE FROM {} WHERE lower(name) = lower(:name)",
            Self::TABLE.table
        ))?;
        let n = stmt.execute(named_params! { ":name": SqlName::from(name.clone()) })?;
        Ok(n)
    }

    #[tracing::instrument(skip_all, level = "trace")]
    pub(crate) fn list(&self, root: &LowerName) -> rusqlite::Result<Vec<Name>> {
        let mut stmt = self.connection.prepare(&format!(
            "SELECT DISTINCT name FROM {table} WHERE lower(name) LIKE :name",
            table = Self::TABLE.table
        ))?;

        let name = format!("%{root}");
        tracing::trace!("Listing records for root: {}", name);

        let names = stmt
            .query_map(named_params! {":name": name}, |row| {
                Ok(row.get::<_, SqlName>("name")?.into())
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RecordPersistence<'c> {
    connection: &'c rusqlite::Connection,
}

impl<'c> RecordPersistence<'c> {
    fn new(connection: &'c rusqlite::Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<10> = QueryBuilder {
        table: "record",
        columns: [
            "id",
            "zone_id",
            "soa_serial",
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
    pub(crate) fn populate_zones(
        &self,
        origin: &LowerName,
        zones: &mut [Zone],
    ) -> rusqlite::Result<()> {
        tracing::trace!("Joined load for {} zones", zones.len());
        let mut stmt = self.connection.prepare(&Self::TABLE.select_for_join(
            "JOIN zone ON record.zone_id = zone.id WHERE lower(zone.name) == lower(:name)",
        ))?;

        let riter = stmt.query_map(
            named_params! { ":name": SqlName::from(origin.clone()) },
            |row| {
                let record = Record::from_row(row)?;
                let zone_id: ZoneID = row.get("zone_id")?;
                let serial: SerialNumber = row.get("soa_serial")?;
                Ok((zone_id, record, serial))
            },
        )?;

        let mut records: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut n = 0usize;
        for result in riter {
            let (zone, record, serial) = result?;
            records.entry(zone).or_default().push((record, serial));
            n += 1;
        }
        tracing::trace!("Populating {} zones from {} records", records.len(), n);
        for zone in zones {
            for (record, serial) in records.remove(&zone.id()).unwrap_or_default() {
                if record.expired() {
                    continue;
                }
                zone.upsert(record, serial)
                    .expect("Zone and record mismatch during DB Load");
            }
        }

        Ok(())
    }

    /// Populate a single zone with records
    #[tracing::instrument("populate", skip_all, level = "trace")]
    pub(crate) fn populate_zone(&self, zone: &mut Zone) -> rusqlite::Result<()> {
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
    pub(crate) fn delete_orphaned_records(&self, zone: &Zone) -> rusqlite::Result<()> {
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
    pub(crate) fn upsert_records(&self, zone: &Zone) -> rusqlite::Result<()> {
        self.delete_orphaned_records(zone)?;
        self.insert_records(zone, zone.records())?;

        Ok(())
    }

    #[tracing::instrument("insert", skip_all, level = "trace")]
    pub(crate) fn insert_records<'z>(
        &self,
        zone: &'z Zone,
        records: impl Iterator<Item = &'z Record>,
    ) -> rusqlite::Result<()> {
        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        let mut n = 0;
        for record in records {
            if record.expired() {
                continue;
            }
            n += stmt.execute(named_params! {
                ":id": record.id(),
                ":zone_id": zone.id(),
                ":soa_serial": zone.serial(),
                ":name_labels": SqlName::from(record.name().clone()),
                ":dns_class": u16::from(record.dns_class()),
                ":ttl": record.ttl(),
                ":record_type": u16::from(record.record_type()),
                ":rdata": record.rdata().to_bytes().map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
                ":mdns_cache_flush": record.mdns_cache_flush(),
                ":expires": record.expires()
            })?;
        }

        tracing::trace!("inserted {n} records");
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

    fn create_test_zone(name: &str) -> Zone {
        let name = Name::from_utf8(name).unwrap();
        let soa = rdata::SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
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
        let name = Name::from_utf8("www.test.example.com.").unwrap();
        let ttl = TimeToLive::from(300);
        let rdata = rdata::A::new(192, 168, 1, 1);
        Record::from_rdata(name, ttl, rdata).into_record_rdata()
    }

    #[test]
    fn test_sqlite_configuration_serde() {
        crate::subscribe();

        // Test deserialization with no path (default)
        let json = "{}";
        let config: SqliteConfiguration = serde_json::from_str(json).unwrap();
        assert!(config.path.is_none());

        // Test deserialization with path
        let json = r#"{"path": "/tmp/test.db"}"#;
        let config: SqliteConfiguration = serde_json::from_str(json).unwrap();
        assert_eq!(config.path, Some(Utf8PathBuf::from("/tmp/test.db")));
    }

    #[tokio::test]
    async fn test_sqlite_catalog_new() {
        crate::subscribe();

        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let catalog = SqliteStore::new(connection.into()).await.unwrap();

        // Should be created successfully
        assert!(catalog.manager.get().await.is_ok());
    }

    #[tokio::test]
    async fn test_sqlite_catalog_new_in_memory() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();

        // Should be created successfully with migrations applied
        assert!(catalog.manager.get().await.is_ok());
    }

    #[tokio::test]
    async fn test_sqlite_catalog_new_from_config_in_memory() {
        crate::subscribe();

        let config = SqliteConfiguration {
            path: None,
            busy_timeout: None,
        };
        let catalog = SqliteStore::new_from_config(&config).await.unwrap();

        // Should be created successfully
        assert!(catalog.manager.get().await.is_ok());
    }

    #[tokio::test]
    async fn test_sqlite_catalog_new_from_config_with_file() {
        crate::subscribe();

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = SqliteConfiguration {
            path: Some(Utf8PathBuf::from_path_buf(db_path).unwrap()),
            ..Default::default()
        };

        let catalog = SqliteStore::new_from_config(&config).await.unwrap();

        // Should be created successfully
        assert!(catalog.manager.get().await.is_ok());

        // File should exist
        assert!(Path::new(config.path.as_ref().unwrap()).exists());
    }

    #[tokio::test]
    async fn test_catalog_upsert_and_get_zone() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let zone = create_test_zone("test.example.com.");
        let zone_id = zone.id();
        let expected_name = zone.name().clone();
        let expected_type = zone.zone_type();

        // Upsert zone
        let result = catalog.insert(&zone).await;
        assert!(result.is_ok());

        // Get zone back
        let retrieved_zone = catalog.get(zone_id).await.unwrap();
        assert_eq!(retrieved_zone.id(), zone_id);
        assert_eq!(retrieved_zone.name(), &expected_name);
        assert_eq!(retrieved_zone.zone_type(), expected_type);
    }

    #[tokio::test]
    async fn test_catalog_find_zone() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let zone = create_test_zone("test.example.com.");
        let zone_name = LowerName::from(zone.name().clone());
        let expected_name = zone.name().clone();

        // Upsert zone
        catalog.insert(&zone).await.unwrap();

        // Find zone by name
        let found_zones = catalog.find(&zone_name).await.unwrap().unwrap();
        assert_eq!(found_zones.len(), 1);
        assert_eq!(found_zones[0].name(), &expected_name);
    }

    #[tokio::test]
    async fn test_catalog_find_nonexistent_zone() {
        crate::subscribe();
        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let nonexistent_name =
            LowerName::from(Name::from_utf8("nonexistent.example.com.").unwrap());

        // Find nonexistent zone
        let found_zones = catalog.find(&nonexistent_name).await.unwrap();
        assert!(found_zones.is_none());
    }

    #[tokio::test]
    async fn test_catalog_delete_zone() {
        crate::subscribe();
        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let zone = create_test_zone("test.example.com.");
        let zone_id = zone.id();

        // Upsert zone
        catalog.insert(&zone).await.unwrap();

        // Verify zone exists
        assert!(catalog.get(zone_id).await.is_ok());

        // Delete zone
        let result = catalog.delete(zone_id).await;
        assert!(result.is_ok());

        // Verify zone no longer exists
        assert!(catalog.get(zone_id).await.is_err());
    }

    #[tokio::test]
    async fn test_catalog_list_zones() {
        crate::subscribe();
        let catalog = SqliteStore::new_in_memory().await.unwrap();

        // Start with empty list
        let root = LowerName::new(&Name::root());
        let initial_list = catalog.list(&root).await.unwrap();
        assert!(initial_list.is_empty());

        // Add a zone
        let zone = create_test_zone("test.example.com.");
        let zone_name = zone.name().clone();
        catalog.insert(&zone).await.unwrap();

        let root = LowerName::new(&Name::root());
        // List should contain the zone
        let zone_list = catalog.list(&root).await.unwrap();
        assert_eq!(zone_list.len(), 1);
        assert_eq!(zone_list[0], zone_name);
    }

    #[tokio::test]
    async fn test_catalog_multiple_zones() {
        crate::subscribe();
        let catalog = SqliteStore::new_in_memory().await.unwrap();

        // Create multiple zones
        let zone1 = create_test_zone("test.example.org.");
        let zone1_name = zone1.name().clone();
        let zone2 = {
            let name = Name::from_utf8("another.example.com.").unwrap();
            let soa = rdata::SOA::new(
                name.clone(),
                Name::from_utf8("admin.another.example.com.").unwrap(),
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
        catalog.insert(&zone1).await.unwrap();
        catalog.insert(&zone2).await.unwrap();

        // List should contain both zones
        let root = LowerName::new(&Name::root());
        let zone_list = catalog.list(&root).await.unwrap();
        assert_eq!(zone_list.len(), 2);
        assert!(zone_list.contains(&zone1_name));
        assert!(zone_list.contains(&zone2_name));

        let zone_list = catalog.list(&zone1_name.clone().into()).await.unwrap();
        assert_eq!(zone_list.len(), 1);
        assert!(zone_list.contains(&zone1_name));
        assert!(!zone_list.contains(&zone2_name));
    }

    #[tokio::test]
    async fn test_catalog_chained_zones() {
        crate::subscribe();
        let catalog = SqliteStore::new_in_memory().await.unwrap();

        // Create multiple zones
        let zone1 = create_test_zone("test.example.com.");
        let zone2 = create_test_zone("test.example.org.");
        let name = zone1.origin().clone();
        catalog
            .upsert(name.clone(), &vec![zone1.into(), zone2.into()])
            .await
            .unwrap();

        // List should contain both zones
        let root = LowerName::new(&Name::root());
        let zone_list = catalog.list(&root).await.unwrap();
        assert_eq!(zone_list.len(), 2);
        assert!(zone_list.contains(&name.into()));
    }

    #[tokio::test]
    async fn test_catalog_zone_with_records() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let mut zone = create_test_zone("test.example.com.");
        let a_record = create_test_a_record();

        // Add record to zone
        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();
        let zone_id = zone.id();

        // Upsert zone with records
        catalog.insert(&zone).await.unwrap();

        // Retrieve zone and verify records
        let retrieved_zone = catalog.get(zone_id).await.unwrap();
        assert_eq!(retrieved_zone.records().count(), 2); // SOA + A record

        // Verify A record exists
        let a_records: Vec<_> = retrieved_zone
            .records()
            .filter(|r| r.record_type() == RecordType::A)
            .collect();
        assert_eq!(a_records.len(), 1);
    }

    #[tokio::test]
    async fn test_catalog_concurrent_access() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let zone = create_test_zone("test.example.com.");
        let zone_name = LowerName::from(zone.name().clone());

        // Test that the catalog can handle concurrent access via Arc<Mutex<Connection>>
        let catalog_clone = catalog.clone();

        // Upsert in original
        catalog.insert(&zone).await.unwrap();

        // Read from clone
        let found_zones = catalog_clone.find(&zone_name).await.unwrap().unwrap();
        assert_eq!(found_zones.len(), 1);
    }

    #[tokio::test]
    async fn test_catalog_debug_format() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let debug_string = format!("{catalog:?}");
        assert!(debug_string.contains("Sqlite"));
    }

    #[tokio::test]
    async fn test_zone_update_serial_number() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let mut zone = create_test_zone("test.example.com.");
        let a_record = create_test_a_record();

        // Add record with serial 1
        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();
        let zone_id = zone.id();
        catalog.insert(&zone).await.unwrap();

        // Retrieve zone and add same record with serial 2 (simulating an update)
        let mut retrieved_zone = catalog.get(zone_id).await.unwrap();
        retrieved_zone
            .upsert(a_record, SerialNumber::from(2))
            .unwrap();
        catalog.insert(&retrieved_zone).await.unwrap();

        // Retrieve and verify the zone was updated
        let final_zone = catalog.get(zone_id).await.unwrap();
        assert_eq!(final_zone.records().count(), 2); // SOA + A record (not duplicated)
    }

    #[tokio::test]
    async fn test_zone_name_case_insensitive_search() {
        crate::subscribe();

        let catalog = SqliteStore::new_in_memory().await.unwrap();
        let zone = create_test_zone("test.example.com.");
        let expected_name = zone.name().clone();

        catalog.insert(&zone).await.unwrap();

        // Search with different case
        let upper_name = LowerName::from(Name::from_utf8("TEST.EXAMPLE.COM.").unwrap());
        let found_zones = catalog.find(&upper_name).await.unwrap().unwrap();
        assert_eq!(found_zones.len(), 1);
        assert_eq!(found_zones[0].name(), &expected_name);
    }
}
