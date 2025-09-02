//! DNS query caching layer for walnut-dns.
//!
//! This module provides a caching layer for DNS queries and responses, helping to reduce
//! the load on upstream DNS servers and improve response times for frequently requested
//! domains. The cache stores both successful DNS lookups and NXDOMAIN responses with
//! configurable TTL bounds.
//!
//! # Architecture
//!
//! The cache system consists of several key components:
//!
//! - [`DnsCache`] - The core cache implementation that stores and retrieves DNS queries
//! - [`CacheConfig`] - Configuration for TTL bounds per record type
//! - [`CachedQuery`] - Wrapper for cached DNS query results (successful or NXDOMAIN)
//! - [`DnsCacheService`] - Tower service layer for transparent caching
//!
//! # Usage
//!
//! ```rust,ignore
//! use walnut_dns::cache::{DnsCache, CacheConfig};
//! use walnut_dns::database::ConnectionManager;
//!
//! // Create a cache with default configuration
//! let manager = ConnectionManager::from(connection);
//! let config = CacheConfig::default();
//! let cache = DnsCache::new(manager, config).await?;
//!
//! // Insert a query result into the cache
//! cache.insert(&cached_query, Utc::now()).await?;
//!
//! // Retrieve from cache
//! let result = cache.get(query, Utc::now()).await?;
//! ```

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hickory_proto::op::Query;

use monarch_db::MonarchDB;

use thiserror::Error;

use crate::database::{ConnectionManager, query::QueryPersistence};
use crate::database::{MONARCH, Result};
use crate::rr::TimeToLive;

pub use self::config::CacheConfig;
pub use self::lookup::{CacheTimestamp, CachedQuery, EntryMeta, Lookup, NxDomain};
pub use self::service::{DnsCacheLayer, DnsCacheService};

mod config;
mod lookup;
mod service;

/// Errors that can occur during cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Timeout occurred while waiting for a database connection.
    #[error("Timed Out waiting for SQLite connection")]
    TimedOut,
    /// Database operation failed.
    #[error("SQLite: {0}")]
    Database(#[from] rusqlite::Error),
}

#[cfg(feature = "pool")]
impl From<bb8::RunError<rusqlite::Error>> for CacheError {
    fn from(error: bb8::RunError<rusqlite::Error>) -> Self {
        match error {
            bb8::RunError::User(sql_error) => sql_error.into(),
            bb8::RunError::TimedOut => CacheError::TimedOut,
        }
    }
}

/// A DNS query cache that stores successful lookups and NXDOMAIN responses.
///
/// The cache uses SQLite as its backing store and provides configurable TTL bounds
/// for different record types. It automatically handles database migrations and
/// connection management.
///
/// # Examples
///
/// ```rust,ignore
/// let manager = ConnectionManager::from(connection);
/// let config = CacheConfig::default();
/// let cache = DnsCache::new(manager, config).await?;
///
/// // Cache a successful lookup
/// cache.insert(&cached_query, Utc::now()).await?;
///
/// // Retrieve from cache
/// if let Some(result) = cache.get(query, Utc::now()).await? {
///     // Use cached result
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DnsCache {
    manager: ConnectionManager,
    config: Arc<CacheConfig>,
}

impl DnsCache {
    /// Creates a new DNS cache with the given connection manager and configuration.
    ///
    /// This method initializes the database schema by running any necessary migrations
    /// through the provided connection manager.
    ///
    /// # Arguments
    ///
    /// * `manager` - Database connection manager for SQLite operations
    /// * `config` - Cache configuration specifying TTL bounds
    ///
    /// # Returns
    ///
    /// A new `DnsCache` instance ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if database migrations fail or if the connection cannot be established.
    pub async fn new(manager: ConnectionManager, config: CacheConfig) -> Result<Self> {
        let db = MonarchDB::from(MONARCH);
        {
            let mut connection = manager.get().await?;
            db.migrations(&mut connection).prepare()?;
        };

        Ok(Self {
            manager,
            config: Arc::new(config),
        })
    }

    /// Inserts a successful DNS lookup into the cache.
    ///
    /// The TTL is clamped to the configured bounds for the record type to prevent
    /// excessively short or long cache times.
    async fn insert_query(
        &self,
        lookup: &Lookup,
        now: DateTime<Utc>,
        ttl: TimeToLive,
    ) -> Result<(), CacheError> {
        let rng = self.config.positive_ttl(lookup.query().query_type());

        let mut connection = self.manager.get().await?;

        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            qx.insert_lookup(lookup, now.into(), ttl.clamp(*rng.start(), *rng.end()))?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Inserts an NXDOMAIN response into the cache.
    ///
    /// The TTL is clamped to the configured negative TTL bounds for the record type.
    async fn insert_nxdomain(
        &self,
        nxdomain: &NxDomain,
        now: DateTime<Utc>,
        ttl: TimeToLive,
    ) -> Result<(), CacheError> {
        let rng = self.config.negative_ttl(nxdomain.query().query_type());

        let mut connection = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            qx.insert_nxdomain(nxdomain, now.into(), ttl.clamp(*rng.start(), *rng.end()))?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Inserts a cached query (either successful lookup or NXDOMAIN) into the cache.
    ///
    /// This method automatically determines whether the query represents a successful
    /// lookup or an NXDOMAIN response and calls the appropriate internal method.
    ///
    /// # Arguments
    ///
    /// * `query` - The cached query result to store
    /// * `now` - Current timestamp for TTL calculations
    ///
    /// # Errors
    ///
    /// Returns a `CacheError` if the database operation fails.
    pub async fn insert(&self, query: &CachedQuery, now: DateTime<Utc>) -> Result<(), CacheError> {
        match query.lookup() {
            Ok(lookup) => self.insert_query(lookup, now, lookup.ttl(now)).await,
            Err(nx_domain) => {
                self.insert_nxdomain(
                    nx_domain,
                    now,
                    nx_domain.negative_ttl().unwrap_or(TimeToLive::MIN),
                )
                .await
            }
        }
    }

    /// Retrieves a cached query result if available and not expired.
    ///
    /// Searches the cache for a matching query and returns the result if found
    /// and still valid at the given timestamp.
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query to look up
    /// * `now` - Current timestamp to check expiration
    ///
    /// # Returns
    ///
    /// * `Ok(Some(cached_query))` - If a valid cached result is found
    /// * `Ok(None)` - If no matching or valid cached result exists
    /// * `Err(cache_error)` - If a database error occurs
    ///
    /// # Errors
    ///
    /// Returns a `CacheError` if the database operation fails.
    pub async fn get(
        &self,
        query: Query,
        now: DateTime<Utc>,
    ) -> Result<Option<CachedQuery>, CacheError> {
        let mut connection = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            let entry = match qx.find(query, now.into()) {
                Ok(entry) => Ok(Some(entry)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(err),
            }?;
            tx.commit()?;
            Ok(entry)
        })
    }

    /// Removes expired entries from the cache.
    ///
    /// This method should be called periodically to prevent the cache from
    /// growing indefinitely with expired entries.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp to determine which entries have expired
    ///
    /// # Errors
    ///
    /// Returns a `CacheError` if the database operation fails.
    pub async fn cleanup(&self, now: DateTime<Utc>) -> Result<(), CacheError> {
        let mut connection = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            qx.remove_expired(now.into())?;
            tx.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rr::QueryID;
    use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
    use std::str::FromStr;

    async fn create_test_cache() -> DnsCache {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let manager = ConnectionManager::from(connection);
        let config = CacheConfig::default();
        DnsCache::new(manager, config).await.unwrap()
    }

    #[tokio::test]
    async fn test_cache_insert_and_get_lookup() {
        let cache = create_test_cache().await;
        let now = Utc::now();

        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        let record = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A::new(192, 168, 1, 1)),
        );
        let lookup = Lookup::new(
            QueryID::new(),
            query.clone(),
            vec![record.into()],
            CacheTimestamp::from(now + chrono::Duration::seconds(300)),
        );
        let cached_query = CachedQuery::new(Ok(lookup));

        cache.insert(&cached_query, now).await.unwrap();

        let result = cache.get(query, now).await.unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.query_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_cache_insert_and_get_nxdomain() {
        let cache = create_test_cache().await;
        let now = Utc::now();

        let query = Query::query(Name::from_str("nonexistent.com.").unwrap(), RecordType::A);
        let nxdomain = NxDomain::new(
            QueryID::new(),
            query.clone(),
            vec![],
            hickory_proto::op::ResponseCode::NXDomain,
            CacheTimestamp::from(now + chrono::Duration::seconds(300)),
        );
        let cached_query = CachedQuery::new(Err(nxdomain));

        cache.insert(&cached_query, now).await.unwrap();

        let result = cache.get(query, now).await.unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert!(retrieved.lookup().is_err());
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache = create_test_cache().await;
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(3600);

        let query = Query::query(Name::from_str("expired.com.").unwrap(), RecordType::A);
        let lookup = Lookup::new(
            QueryID::new(),
            query.clone(),
            vec![],
            CacheTimestamp::from(past),
        );
        let cached_query = CachedQuery::new(Ok(lookup));

        cache.insert(&cached_query, past).await.unwrap();

        let result_before = cache.get(query.clone(), now).await.unwrap();
        assert!(result_before.is_none());

        cache.cleanup(now).await.unwrap();

        let result_after = cache.get(query, now).await.unwrap();
        assert!(result_after.is_none());
    }

    #[test]
    fn test_cache_error_display() {
        let timeout_error = CacheError::TimedOut;
        assert_eq!(
            timeout_error.to_string(),
            "Timed Out waiting for SQLite connection"
        );

        let db_error = CacheError::Database(rusqlite::Error::InvalidColumnIndex(5));
        assert!(db_error.to_string().contains("SQLite:"));
    }
}
