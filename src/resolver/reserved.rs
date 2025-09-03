//! Resolver for reserved names

use std::{
    collections::BTreeMap,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use hickory_proto::{
    op::{Query, ResponseCode},
    rr::{
        Name, RData, RecordType,
        domain::usage::{self, ResolverUsage, ZoneUsage},
        rdata::{A, AAAA, PTR},
    },
    xfer::{DnsRequest, DnsResponse},
};
use once_cell::sync::Lazy;
use std::pin::Pin;

use super::Lookup;
use crate::client::DnsClientError;

/// An opaque future type for reserved names service responses.
///
/// This type wraps the internal future implementation to avoid exposing
/// implementation details in the public API.
pub struct ReservedNamesFuture {
    inner: BoxFuture<'static, Result<DnsResponse, DnsClientError>>,
}

impl std::future::Future for ReservedNamesFuture {
    type Output = Result<DnsResponse, DnsClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

static LOCALHOST_PTR: Lazy<RData> =
    Lazy::new(|| RData::PTR(PTR(Name::from_ascii("localhost.").unwrap())));
static LOCALHOST_V4: Lazy<RData> = Lazy::new(|| RData::A(A::new(127, 0, 0, 1)));
static LOCALHOST_V6: Lazy<RData> = Lazy::new(|| RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageArea {
    User,
    Application,
    Resolver,
    Cache,
    Auth,
    Op,
    Registry,
}

#[derive(Clone)]
pub struct ReservedNamesResolver {
    names: BTreeMap<Name, &'static ZoneUsage>,
}

impl std::fmt::Debug for ReservedNamesResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReservedNamesResolver")
            .field("names_count", &self.names.len())
            .finish()
    }
}

impl ReservedNamesResolver {
    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
        }
    }

    /// Add a new reserved name to this resolver
    pub fn insert(&mut self, usage: &'static ZoneUsage) {
        self.names.insert(usage.name().clone(), usage);
    }

    pub fn default_reserved_local_names() -> Self {
        let mut resolver = Self::new();
        resolver.insert(&usage::LOCALHOST);
        resolver.insert(&usage::DEFAULT);
        resolver.insert(&usage::ONION);
        resolver.insert(&usage::INVALID);
        resolver.insert(&usage::IN_ADDR_ARPA_127);
        resolver.insert(&usage::IP6_ARPA_1);
        resolver.insert(&usage::LOCAL);
        resolver
    }

    fn get(&self, mut name: Name) -> Option<&'static ZoneUsage> {
        loop {
            tracing::trace!("Looking for {name}");
            if let Some(&usage) = self.names.get(&name) {
                return Some(usage);
            }
            if name.is_root() {
                return None;
            }
            name = name.base_name();
        }
    }

    fn check_resolver_usage(&self, query: Query, usage: &'static ZoneUsage) -> Lookup {
        match usage.resolver() {
            ResolverUsage::Loopback => match query.query_type() {
                RecordType::A => Lookup::from_rdata(query, LOCALHOST_V4.clone()),
                RecordType::AAAA => Lookup::from_rdata(query, LOCALHOST_V6.clone()),
                RecordType::PTR => Lookup::from_rdata(query, LOCALHOST_PTR.clone()),
                _ => Lookup::no_records(query, ResponseCode::NoError),
            },
            ResolverUsage::Normal | ResolverUsage::LinkLocal | ResolverUsage::NxDomain => {
                Lookup::no_records(query, ResponseCode::NXDomain)
            }
        }
    }

    /// Resolve a query for reserved names.
    ///
    /// This method checks if the query is for a reserved name and returns an appropriate
    /// response based on the reserved name's usage specification.
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query to resolve
    ///
    /// # Returns
    ///
    /// * `Some(lookup)` - If the query is for a reserved name
    /// * `None` - If the query is not for a reserved name and should be forwarded
    pub fn resolve(&self, query: Query) -> Option<Lookup> {
        let usage = self.get(query.name().clone())?;

        // Check if this usage area should handle this query
        // For reserved names, we always provide a response based on the resolver usage
        Some(self.check_resolver_usage(query, usage))
    }
}

/// Tower layer for adding reserved names resolution to a service.
///
/// This layer wraps any DNS service and provides reserved names handling.
/// It can be used in a service stack to intercept reserved name queries
/// before they reach the underlying service.
///
/// # Examples
///
/// ```rust,ignore
/// use tower::ServiceBuilder;
///
/// let resolver = ReservedNamesResolver::default_reserved_local_names(UsageArea::Resolver);
/// let reserved_layer = ReservedNamesLayer::from(resolver);
/// let service = ServiceBuilder::new()
///     .layer(reserved_layer)
///     .service(dns_service);
/// ```
#[derive(Debug, Clone)]
pub struct ReservedNamesLayer {
    resolver: ReservedNamesResolver,
}

impl From<ReservedNamesResolver> for ReservedNamesLayer {
    fn from(resolver: ReservedNamesResolver) -> Self {
        Self { resolver }
    }
}

impl<S> tower::Layer<S> for ReservedNamesLayer {
    type Service = ReservedNamesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ReservedNamesService {
            service: inner,
            resolver: self.resolver.clone(),
        }
    }
}

/// A DNS service with reserved names resolution capabilities.
///
/// This service wraps another DNS service and provides reserved names handling.
/// For reserved name queries, it returns appropriate responses without calling
/// the underlying service. For normal queries, it forwards them to the underlying service.
///
/// # Type Parameters
///
/// * `S` - The underlying DNS service type
#[derive(Debug, Clone)]
pub struct ReservedNamesService<S> {
    service: S,
    resolver: ReservedNamesResolver,
}

impl<S> ReservedNamesService<S> {
    /// Creates a new reserved names DNS service.
    ///
    /// # Arguments
    ///
    /// * `service` - The underlying DNS service to wrap
    /// * `resolver` - The reserved names resolver to use
    pub fn new(service: S, resolver: ReservedNamesResolver) -> Self {
        Self { service, resolver }
    }
}

impl<S> tower::Service<DnsRequest> for ReservedNamesService<S>
where
    S: tower::Service<DnsRequest, Response = DnsResponse, Error = DnsClientError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = ReservedNamesFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    /// Handles a DNS request with reserved names resolution.
    ///
    /// This method implements the core reserved names behavior:
    /// 1. Check if query is for a reserved name
    /// 2. Return reserved name response if found
    /// 3. Forward request to underlying service if not reserved
    ///
    /// # Arguments
    ///
    /// * `req` - The DNS request to process
    ///
    /// # Returns
    ///
    /// A future that resolves to either a reserved name response or forwarded response.
    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let resolver = self.resolver.clone();
        let service = self.service.clone();
        let mut service = std::mem::replace(&mut self.service, service);

        ReservedNamesFuture {
            inner: Box::pin(async move {
                let query = req.query().expect("no query in DnsRequest").clone();

                // Check for reserved names first
                if let Some(lookup) = resolver.resolve(query) {
                    // Reserved name hit - return direct response
                    tracing::trace!("Reserved name hit for {}", lookup.name());
                    let mut msg: hickory_proto::op::Message = lookup.into();
                    msg.set_id(req.id());
                    Ok(DnsResponse::from_message(msg)
                        .expect("protocol error from reserved name response"))
                } else {
                    // Not a reserved name - forward to underlying service
                    tracing::trace!("Not a reserved name, forwarding to underlying service");
                    service.call(req).await
                }
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    #[test]
    fn test_reserved_resolver_construction() {
        let resolver = ReservedNamesResolver::new();
        assert!(resolver.names.is_empty());
    }

    #[test]
    fn test_default_reserved_local_names() {
        let resolver = ReservedNamesResolver::default_reserved_local_names();
        assert!(!resolver.names.is_empty());

        // Check that localhost is included
        let localhost = Name::from_str("localhost.").unwrap();
        assert!(resolver.get(localhost).is_some());
    }

    #[test]
    fn test_resolve_localhost_a() {
        let resolver = ReservedNamesResolver::default_reserved_local_names();
        let query = Query::query(Name::from_str("localhost.").unwrap(), RecordType::A);

        let result = resolver.resolve(query.clone());
        assert!(result.is_some());

        let lookup = result.unwrap();
        assert_eq!(lookup.query(), &query);
        assert!(lookup.is_success());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_resolve_localhost_aaaa() {
        let resolver = ReservedNamesResolver::default_reserved_local_names();
        let query = Query::query(Name::from_str("localhost.").unwrap(), RecordType::AAAA);

        let result = resolver.resolve(query.clone());
        assert!(result.is_some());

        let lookup = result.unwrap();
        assert_eq!(lookup.query(), &query);
        assert!(lookup.is_success());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_resolve_localhost_ptr() {
        let resolver = ReservedNamesResolver::default_reserved_local_names();
        let query = Query::query(
            Name::from_str("1.0.0.127.in-addr.arpa.").unwrap(),
            RecordType::PTR,
        );

        let result = resolver.resolve(query.clone());
        assert!(result.is_some());

        let lookup = result.unwrap();
        assert_eq!(lookup.query(), &query);
        assert!(lookup.is_success());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_resolve_invalid_domain() {
        let resolver = ReservedNamesResolver::default_reserved_local_names();
        let query = Query::query(Name::from_str("test.invalid.").unwrap(), RecordType::A);

        let result = resolver.resolve(query.clone());
        assert!(result.is_some());

        let lookup = result.unwrap();
        assert_eq!(lookup.query(), &query);
        assert!(lookup.is_nxdomain());
    }

    #[test]
    fn test_resolve_normal_domain() {
        let mut resolver = ReservedNamesResolver::new();
        // Don't add DEFAULT which matches everything
        resolver.insert(&usage::LOCALHOST);
        resolver.insert(&usage::INVALID);

        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);

        let result = resolver.resolve(query);
        assert!(result.is_none()); // Should forward to upstream
    }

    #[test]
    fn test_get_hierarchical_lookup() {
        let resolver = ReservedNamesResolver::default_reserved_local_names();

        // Test that subdomain lookups work
        let subdomain = Name::from_str("test.localhost.").unwrap();
        let usage = resolver.get(subdomain);
        assert!(usage.is_some());
        assert_eq!(
            usage.unwrap().name(),
            &Name::from_str("localhost.").unwrap()
        );
    }

    #[test]
    fn test_reserved_names_layer_construction() {
        let resolver = ReservedNamesResolver::new();
        let _layer = ReservedNamesLayer::from(resolver);
    }

    #[tokio::test]
    async fn test_reserved_names_service_localhost() {
        use hickory_proto::op::Message;
        use tower::Service;

        // Create a mock service that should never be called for localhost
        let mock_service = tower::service_fn(|_req: DnsRequest| async move {
            panic!("Mock service should not be called for localhost queries");
        });

        let resolver = ReservedNamesResolver::default_reserved_local_names();
        let mut service = ReservedNamesService::new(mock_service, resolver);

        // Create a localhost A query
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_str("localhost.").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(msg, hickory_proto::xfer::DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answer_count() > 0);
    }

    #[tokio::test]
    async fn test_reserved_names_service_forward() {
        use hickory_proto::op::Message;
        use tower::Service;

        // Create a mock service that returns NXDOMAIN
        let mock_service = tower::service_fn(|req: DnsRequest| async move {
            let mut response_msg = Message::new();
            response_msg.set_id(req.id());
            response_msg.set_response_code(ResponseCode::NXDomain);
            Ok(DnsResponse::from_message(response_msg).unwrap())
        });

        let mut resolver = ReservedNamesResolver::new();
        // Don't add DEFAULT which matches everything
        resolver.insert(&usage::LOCALHOST);
        resolver.insert(&usage::INVALID);

        let mut service = ReservedNamesService::new(mock_service, resolver);

        // Create a normal domain query that should be forwarded
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(msg, hickory_proto::xfer::DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_reserved_names_service_invalid_domain() {
        use hickory_proto::op::Message;
        use tower::Service;

        // Create a mock service that should never be called for invalid domains
        let mock_service = tower::service_fn(|_req: DnsRequest| async move {
            panic!("Mock service should not be called for invalid domain queries");
        });

        let resolver = ReservedNamesResolver::default_reserved_local_names();
        let mut service = ReservedNamesService::new(mock_service, resolver);

        // Create an invalid domain query
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_str("test.invalid.").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(msg, hickory_proto::xfer::DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }
}
