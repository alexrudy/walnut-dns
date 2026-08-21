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
//! - [`DnsCache`] - The core cache implementation trait that stores and retrieves DNS queries
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

use chrono::{DateTime, Utc};
use hickory_proto::op::Query;

use crate::database::Result;

pub use self::config::CacheConfig;
pub use self::service::{DnsCacheLayer, DnsCacheService};
pub use crate::lookup::{CacheTimestamp, EntryMeta, QueryLookup};

mod config;
mod lookup;
mod service;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Trait to be implemented by caching backends
#[async_trait::async_trait]
pub trait DnsCache {
    /// Inserts a query result into the cache.
    async fn insert(&self, lookup: &QueryLookup, now: DateTime<Utc>) -> Result<(), BoxError>;

    /// Retrieves a query result from the cache.
    async fn get(&self, query: Query, now: DateTime<Utc>) -> Result<Option<QueryLookup>, BoxError>;

    /// Cleans up the cache by removing old entries. This is allowed to do nothing.
    #[expect(unused_variables)]
    async fn cleanup(&self, now: DateTime<Utc>) -> Result<(), BoxError> {
        Ok(())
    }
}
