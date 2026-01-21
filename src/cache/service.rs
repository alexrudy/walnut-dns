//! Tower service layer for transparent DNS query caching.
//!
//! This module provides a Tower service layer that transparently caches DNS queries
//! and responses.

use std::task::{Context, Poll};

use chrono::Utc;
use futures::future::BoxFuture;
use hickory_proto::{
    op::ResponseCode,
    xfer::{DnsRequest, DnsResponse},
};

use crate::client::DnsClientError;

use super::DnsCache;

/// Tower layer for adding DNS caching to a service.
///
/// This layer wraps any DNS service and adds caching functionality.
/// It can be used in a service stack to provide transparent caching
/// without modifying the underlying service implementation.
///
/// # Examples
///
/// ```rust,ignore
/// use tower::ServiceBuilder;
///
/// let cache_layer = DnsCacheLayer::new(cache);
/// let service = ServiceBuilder::new()
///     .layer(cache_layer)
///     .service(dns_service);
/// ```
#[derive(Debug, Clone)]
pub struct DnsCacheLayer {
    cache: DnsCache,
}

impl From<DnsCache> for DnsCacheLayer {
    fn from(cache: DnsCache) -> Self {
        Self { cache }
    }
}

impl<S> tower::Layer<S> for DnsCacheLayer {
    type Service = DnsCacheService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsCacheService {
            service: inner,
            cache: self.cache.clone(),
        }
    }
}

/// A DNS service with caching capabilities.
///
/// This service wraps another DNS service and provides transparent caching.
/// On cache hits, it returns cached responses without calling the underlying service.
/// On cache misses, it forwards the request to the underlying service and caches
/// the response for future requests.
///
/// # Type Parameters
///
/// * `S` - The underlying DNS service type
#[derive(Debug, Clone)]
pub struct DnsCacheService<S> {
    service: S,
    cache: DnsCache,
}

impl<S> DnsCacheService<S> {
    /// Creates a new caching DNS service.
    ///
    /// # Arguments
    ///
    /// * `service` - The underlying DNS service to wrap
    /// * `cache` - The DNS cache to use for storing responses
    pub fn new(service: S, cache: DnsCache) -> Self {
        Self { service, cache }
    }

    /// Converts a cache error to a DNS client error.
    fn cache_error(error: super::CacheError) -> DnsClientError {
        DnsClientError::Cache(error.into())
    }

    /// Caches a DNS response if it should be cached.
    ///
    /// Only caches responses that have either successful (NoError) answers
    /// or negative (NXDomain) responses.
    async fn cache_response(
        cache: &DnsCache,
        response: &DnsResponse,
    ) -> Result<(), DnsClientError> {
        let now = Utc::now();

        match response.response_code() {
            ResponseCode::NoError | ResponseCode::NXDomain => {
                let lookup: crate::lookup::Lookup = response.clone().try_into()?;
                cache
                    .insert(&lookup, now)
                    .await
                    .map_err(Self::cache_error)?;
            }
            _ => {
                // Don't cache other response codes
            }
        }

        Ok(())
    }
}

impl<S> tower::Service<DnsRequest> for DnsCacheService<S>
where
    S: tower::Service<DnsRequest, Response = DnsResponse, Error = DnsClientError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    /// Handles a DNS request with caching logic.
    ///
    /// This method implements the core caching behavior:
    /// 1. Check cache for existing valid response
    /// 2. Return cached response if found (cache hit)
    /// 3. Forward request to underlying service if not cached (cache miss)
    /// 4. Cache the response for future requests
    ///
    /// # Arguments
    ///
    /// * `req` - The DNS request to process
    ///
    /// # Returns
    ///
    /// A future that resolves to either a cached or freshly retrieved DNS response.
    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let cache = self.cache.clone();
        let service = self.service.clone();
        let mut service = std::mem::replace(&mut self.service, service);
        Box::pin(async move {
            // Check cache first
            match cache
                .get(
                    req.query().expect("no query in DnsRequest").clone(),
                    Utc::now(),
                )
                .await
            {
                Ok(Some(answer)) => {
                    // Cache hit - return cached response
                    tracing::trace!("cache hit, reconstructing answer message");
                    let mut msg: hickory_proto::op::Message = answer.into();
                    msg.set_id(req.id());
                    Ok(
                        DnsResponse::from_message(msg)
                            .expect("protocol error from cached response"),
                    )
                }
                Err(error) => Err(Self::cache_error(error)),
                Ok(None) => {
                    // Cache miss - forward to underlying service
                    tracing::trace!("cache miss, query not available");

                    let response = service.call(req).await?;

                    // Cache the response for future requests
                    Self::cache_response(&cache, &response).await?;

                    Ok(response)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;
    use std::sync::Arc;

    async fn create_test_cache() -> DnsCache {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let manager = crate::database::ConnectionManager::from(connection);
        let config = CacheConfig::default();
        DnsCache::new(manager, config).await.unwrap()
    }

    #[tokio::test]
    async fn test_cache_construction() {
        let cache = create_test_cache().await;
        assert!(Arc::strong_count(&cache.config) >= 1);
    }

    #[test]
    fn test_cache_layer_construction() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let manager = crate::database::ConnectionManager::from(connection);
        let cache = DnsCache {
            manager,
            config: Arc::new(CacheConfig::default()),
        };
        let _layer = DnsCacheLayer::from(cache);
    }
}
