//! Hosts file resolver for DNS queries
//!
//! This module provides a resolver that looks up DNS queries in the local hosts file
//! before falling back to upstream DNS servers. It uses hickory-resolver's Hosts
//! implementation to parse and query the system hosts file.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use hickory_proto::{
    op::Query,
    xfer::{DnsRequest, DnsResponse},
};
use hickory_resolver::Hosts;

use super::Lookup;
use crate::client::DnsClientError;

/// An opaque future type for hosts service responses.
///
/// This type wraps the internal future implementation to avoid exposing
/// implementation details in the public API.
pub struct HostsFuture {
    inner: BoxFuture<'static, Result<DnsResponse, DnsClientError>>,
}

impl std::future::Future for HostsFuture {
    type Output = Result<DnsResponse, DnsClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// A resolver that queries the local hosts file for DNS entries.
///
/// This resolver checks the system hosts file (typically `/etc/hosts` on Unix systems)
/// for hostname entries before falling back to upstream DNS resolution. It provides
/// a way to handle local hostname mappings defined in the hosts file.
///
/// # Examples
///
/// ```rust,ignore
/// let hosts_resolver = HostsResolver::from_system().unwrap();
/// let query = Query::query(Name::from_str("localhost").unwrap(), RecordType::A);
/// if let Some(lookup) = hosts_resolver.resolve(query) {
///     // Found in hosts file
/// }
/// ```
#[derive(Debug)]
pub struct HostsResolver {
    hosts: Arc<Hosts>,
}

impl Clone for HostsResolver {
    fn clone(&self) -> Self {
        Self {
            hosts: Arc::clone(&self.hosts),
        }
    }
}

impl From<Arc<Hosts>> for HostsResolver {
    fn from(hosts: Arc<Hosts>) -> Self {
        Self { hosts }
    }
}

impl HostsResolver {
    /// Creates a new hosts resolver by reading the system hosts file.
    ///
    /// This method attempts to read and parse the system hosts file
    /// (typically `/etc/hosts` on Unix systems).
    ///
    /// # Returns
    ///
    /// A new `HostsResolver` instance configured with the system hosts file.
    ///
    /// # Errors
    ///
    /// Returns an error if the hosts file cannot be read or parsed.
    pub fn from_system() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let hosts = Hosts::from_system()?;
        Ok(Self {
            hosts: Arc::new(hosts),
        })
    }

    /// Creates a new hosts resolver with a custom hosts configuration.
    ///
    /// # Arguments
    ///
    /// * `hosts` - The hosts configuration to use
    pub fn new(hosts: Hosts) -> Self {
        Self {
            hosts: Arc::new(hosts),
        }
    }

    /// Creates an empty hosts resolver.
    ///
    /// This can be useful for testing or when you want to manually
    /// add hosts entries using a custom Hosts instance.
    pub fn empty() -> Self {
        Self {
            hosts: Arc::new(Hosts::default()),
        }
    }

    /// Resolve a query against the hosts file.
    ///
    /// This method checks if the query can be resolved using entries
    /// from the hosts file. It uses hickory-resolver's Hosts lookup functionality.
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query to resolve
    ///
    /// # Returns
    ///
    /// * `Some(lookup)` - If the query was found in the hosts file
    /// * `None` - If the query was not found and should be forwarded
    pub fn resolve(&self, query: Query) -> Option<Lookup> {
        // Use hickory-resolver's hosts lookup which returns their Lookup type
        if let Some(hickory_lookup) = self.hosts.lookup_static_host(&query) {
            // Convert hickory-resolver's Lookup to our Lookup type
            self.convert_hickory_lookup(query, hickory_lookup)
        } else {
            None
        }
    }

    /// Convert hickory-resolver's Lookup to our internal Lookup type.
    fn convert_hickory_lookup(
        &self,
        query: Query,
        hickory_lookup: hickory_resolver::lookup::Lookup,
    ) -> Option<Lookup> {
        let records: Vec<crate::rr::Record> = hickory_lookup
            .record_iter()
            .map(|record| record.clone().into())
            .collect();

        if !records.is_empty() {
            Some(Lookup::from_records(query, records))
        } else {
            None
        }
    }
}

/// Tower layer for adding hosts file resolution to a service.
///
/// This layer wraps any DNS service and provides hosts file lookup functionality.
/// It can be used in a service stack to intercept queries that can be resolved
/// from the local hosts file before they reach the underlying service.
///
/// # Examples
///
/// ```rust,ignore
/// use tower::ServiceBuilder;
///
/// let hosts_resolver = HostsResolver::from_system().unwrap();
/// let hosts_layer = HostsLayer::from(hosts_resolver);
/// let service = ServiceBuilder::new()
///     .layer(hosts_layer)
///     .service(dns_service);
/// ```
#[derive(Debug, Clone)]
pub struct HostsLayer {
    resolver: HostsResolver,
}

impl From<HostsResolver> for HostsLayer {
    fn from(resolver: HostsResolver) -> Self {
        Self { resolver }
    }
}

impl<S> tower::Layer<S> for HostsLayer {
    type Service = HostsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HostsService {
            service: inner,
            resolver: self.resolver.clone(),
        }
    }
}

/// A DNS service with hosts file resolution capabilities.
///
/// This service wraps another DNS service and provides hosts file lookup functionality.
/// For queries that can be resolved from the hosts file, it returns appropriate responses
/// without calling the underlying service. For other queries, it forwards them to the
/// underlying service.
///
/// # Type Parameters
///
/// * `S` - The underlying DNS service type
#[derive(Debug, Clone)]
pub struct HostsService<S> {
    service: S,
    resolver: HostsResolver,
}

impl<S> HostsService<S> {
    /// Creates a new hosts file DNS service.
    ///
    /// # Arguments
    ///
    /// * `service` - The underlying DNS service to wrap
    /// * `resolver` - The hosts file resolver to use
    pub fn new(service: S, resolver: HostsResolver) -> Self {
        Self { service, resolver }
    }
}

impl<S> tower::Service<DnsRequest> for HostsService<S>
where
    S: tower::Service<DnsRequest, Response = DnsResponse, Error = DnsClientError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = HostsFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    /// Handles a DNS request with hosts file resolution.
    ///
    /// This method implements the core hosts file lookup behavior:
    /// 1. Check if query can be resolved from hosts file
    /// 2. Return hosts file response if found
    /// 3. Forward request to underlying service if not found
    ///
    /// # Arguments
    ///
    /// * `req` - The DNS request to process
    ///
    /// # Returns
    ///
    /// A future that resolves to either a hosts file response or forwarded response.
    fn call(&mut self, req: DnsRequest) -> Self::Future {
        // Don't clone the resolver - use a reference to avoid losing data
        let query = req.query().expect("no query in DnsRequest").clone();

        // Check hosts file first using the current resolver
        if let Some(lookup) = self.resolver.resolve(query) {
            // Hosts file hit - return direct response immediately
            tracing::trace!("Hosts file hit for {}", lookup.name());
            let mut msg: hickory_proto::op::Message = lookup.into();
            msg.set_id(req.id());
            let response =
                DnsResponse::from_message(msg).expect("protocol error from hosts file response");

            HostsFuture {
                inner: Box::pin(async move { Ok(response) }),
            }
        } else {
            // Not found in hosts file - forward to underlying service
            tracing::trace!("Not found in hosts file, forwarding to underlying service");
            let service = self.service.clone();
            let mut service = std::mem::replace(&mut self.service, service);

            HostsFuture {
                inner: Box::pin(async move { service.call(req).await }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::ResponseCode,
        rr::{Name, RecordType},
    };
    use std::str::FromStr;

    fn create_test_hosts_with_data() -> HostsResolver {
        use hickory_proto::rr::{
            RData,
            rdata::{A, AAAA},
        };
        use hickory_resolver::lookup::Lookup as HickoryLookup;

        let mut hosts = Hosts::default();

        // Add localhost A record (127.0.0.1)
        let localhost_name = Name::from_str("localhost.").unwrap();
        let localhost_a_query = Query::query(localhost_name.clone(), RecordType::A);
        let localhost_a_lookup =
            HickoryLookup::from_rdata(localhost_a_query, RData::A(A::new(127, 0, 0, 1)));
        hosts.insert(localhost_name.clone(), RecordType::A, localhost_a_lookup);

        // Add localhost AAAA record (::1)
        let localhost_aaaa_query = Query::query(localhost_name.clone(), RecordType::AAAA);
        let localhost_aaaa_lookup = HickoryLookup::from_rdata(
            localhost_aaaa_query,
            RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
        );
        hosts.insert(
            localhost_name.clone(),
            RecordType::AAAA,
            localhost_aaaa_lookup,
        );

        // Add test.local A record (192.168.1.100)
        let test_local_name = Name::from_str("test.local.").unwrap();
        let test_local_query = Query::query(test_local_name.clone(), RecordType::A);
        let test_local_lookup =
            HickoryLookup::from_rdata(test_local_query, RData::A(A::new(192, 168, 1, 100)));
        hosts.insert(test_local_name, RecordType::A, test_local_lookup);

        HostsResolver::new(hosts)
    }

    #[test]
    fn test_hosts_resolver_basic_construction() {
        let resolver = HostsResolver::empty();
        let _cloned = resolver.clone(); // Test Clone implementation
        let _layer = HostsLayer::from(resolver); // Test layer construction
    }

    #[test]
    fn test_hosts_resolver_unsupported_record_types() {
        let resolver = create_test_hosts_with_data();

        // Test that unsupported record types return None even for localhost
        for record_type in [
            RecordType::MX,
            RecordType::TXT,
            RecordType::NS,
            RecordType::CNAME,
        ] {
            let query = Query::query(Name::from_str("localhost.").unwrap(), record_type);
            let result = resolver.resolve(query);
            // Should return None for unsupported record types
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_hosts_resolver_localhost_a_record() {
        let resolver = create_test_hosts_with_data();

        // Test A record query for localhost (we know this is in our test data)
        let a_query = Query::query(Name::from_str("localhost.").unwrap(), RecordType::A);
        let a_result = resolver.resolve(a_query.clone());

        // Should definitely find localhost A record in our test data
        assert!(a_result.is_some());
        let lookup = a_result.unwrap();
        assert_eq!(lookup.query(), &a_query);
        assert!(lookup.is_success());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_hosts_resolver_localhost_aaaa_record() {
        let resolver = create_test_hosts_with_data();

        // Test AAAA record query for localhost (we know this is in our test data)
        let aaaa_query = Query::query(Name::from_str("localhost.").unwrap(), RecordType::AAAA);
        let aaaa_result = resolver.resolve(aaaa_query.clone());

        // Should definitely find localhost AAAA record in our test data
        assert!(aaaa_result.is_some());
        let lookup = aaaa_result.unwrap();
        assert_eq!(lookup.query(), &aaaa_query);
        assert!(lookup.is_success());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_hosts_resolver_test_local_record() {
        let resolver = create_test_hosts_with_data();

        // Test A record query for test.local (we know this is in our test data)
        let query = Query::query(Name::from_str("test.local.").unwrap(), RecordType::A);
        let result = resolver.resolve(query.clone());

        // Should definitely find test.local A record in our test data
        assert!(result.is_some());
        let lookup = result.unwrap();
        assert_eq!(lookup.query(), &query);
        assert!(lookup.is_success());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_hosts_resolver_missing_entry() {
        let resolver = create_test_hosts_with_data();

        // Test query for hostname not in our test data
        let query = Query::query(Name::from_str("nonexistent.local.").unwrap(), RecordType::A);
        let result = resolver.resolve(query);

        // Should return None for entries not in hosts file
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_hosts_service_localhost_a_resolution() {
        use hickory_proto::op::Message;
        use tower::Service;

        let resolver = create_test_hosts_with_data();

        // Create a mock service that should NOT be called for localhost
        let mock_service = tower::service_fn(|_req: DnsRequest| async move {
            panic!("Mock service should not be called for hosts file entries");
        });

        let mut service = HostsService::new(mock_service, resolver);

        // Test localhost A record from hosts file (we know this exists in test data)
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_str("localhost.").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(msg, hickory_proto::xfer::DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answer_count(), 1);
    }

    #[tokio::test]
    async fn test_hosts_service_test_local_resolution() {
        use hickory_proto::op::Message;
        use tower::Service;

        let resolver = create_test_hosts_with_data();

        // Verify test.local is actually in our test data
        let test_query = Query::query(Name::from_str("test.local.").unwrap(), RecordType::A);
        let direct_result = resolver.resolve(test_query.clone());

        if direct_result.is_none() {
            // If test.local isn't resolving, there's an issue with our test setup
            panic!("test.local should be in test hosts data but was not found");
        }

        // Create a mock service that should NOT be called for test.local
        let mock_service = tower::service_fn(|_req: DnsRequest| async move {
            panic!("Mock service should not be called for hosts file entries");
        });

        let mut service = HostsService::new(mock_service, resolver);

        // Test test.local A record from hosts file
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_str("test.local.").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(msg, hickory_proto::xfer::DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answer_count(), 1);
    }

    #[tokio::test]
    async fn test_hosts_service_forwarding_behavior() {
        use hickory_proto::op::Message;
        use tower::Service;

        // Create a mock service that returns NXDOMAIN for forwarded queries
        let mock_service = tower::service_fn(|req: DnsRequest| async move {
            let mut response_msg = Message::new();
            response_msg.set_id(req.id());
            response_msg.set_response_code(ResponseCode::NXDomain);
            Ok(DnsResponse::from_message(response_msg).unwrap())
        });

        let resolver = create_test_hosts_with_data();
        let mut service = HostsService::new(mock_service, resolver);

        // Test queries that should be forwarded
        let forwarded_queries = [
            ("unknown.example.com.", RecordType::A), // Not in hosts file
            ("localhost.", RecordType::MX),          // MX not supported by hosts
            ("test.local.", RecordType::TXT),        // TXT not supported by hosts
            ("test.local.", RecordType::AAAA),       // AAAA not added for test.local
        ];

        for (hostname, record_type) in forwarded_queries {
            let mut msg = Message::new();
            msg.add_query(Query::query(Name::from_str(hostname).unwrap(), record_type));
            let request = DnsRequest::new(msg, hickory_proto::xfer::DnsRequestOptions::default());

            let response = service.call(request).await.unwrap();
            assert_eq!(response.response_code(), ResponseCode::NXDomain);
        }
    }
}
