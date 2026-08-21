//! Hosts file resolver for DNS queries
//!
//! This module provides a resolver that looks up DNS queries in the local hosts file
//! before falling back to upstream DNS servers. It uses hickory-resolver's Hosts
//! implementation to parse and query the system hosts file.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use futures::future::BoxFuture;
use hickory_proto::op::Query;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, RecordType};
use tracing::warn;

use super::QueryLookup;
use crate::cache::CacheTimestamp;
use crate::{
    client::DnsClientError,
    messages::{DnsRequest, DnsResponse, Message},
};
use walnut_proto::rr::QueryID;
use walnut_proto::rr::Record;
use walnut_proto::rr::TimeToLive;

fn lookup_with_max_ttl(query: Query, records: Vec<Record>) -> QueryLookup {
    QueryLookup::new(
        QueryID::new(),
        query,
        records,
        ResponseCode::NoError,
        CacheTimestamp::now() + TimeToLive::DAY,
    )
}

#[derive(Debug, Default)]
struct LookupType {
    /// represents the A record type
    a: Option<QueryLookup>,
    /// represents the AAAA record type
    aaaa: Option<QueryLookup>,
}

/// Configuration for the local hosts file
#[derive(Debug, Default)]
pub struct Hosts {
    /// Name -> RDatas map
    by_name: HashMap<Name, LookupType>,
}

impl Hosts {
    /// Creates a new configuration from the system hosts file,
    /// only works for Windows and Unix-like OSes,
    /// will return empty configuration on others
    #[cfg(any(unix, windows))]
    pub fn from_system() -> io::Result<Self> {
        Self::from_file(hosts_path())
    }

    /// Creates a default configuration for non Windows or Unix-like OSes
    #[cfg(not(any(unix, windows)))]
    pub fn from_system() -> io::Result<Self> {
        Ok(Hosts::default())
    }

    /// parse configuration from `path`
    #[cfg(any(unix, windows))]
    pub(crate) fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut hosts = Self::default();
        hosts.read_hosts_conf(file)?;
        Ok(hosts)
    }

    /// Look up the addresses for the given host from the system hosts file.
    pub fn lookup_static_host(&self, query: &Query) -> Option<QueryLookup> {
        if self.by_name.is_empty() {
            return None;
        }

        let mut name = query.name().clone();
        name.set_fqdn(true);
        match query.query_type() {
            RecordType::A | RecordType::AAAA => {
                let val = self.by_name.get(&name)?;

                match query.query_type() {
                    RecordType::A => val.a.clone(),
                    RecordType::AAAA => val.aaaa.clone(),
                    _ => None,
                }
            }
            RecordType::PTR => {
                let ip = name.parse_arpa_name().ok()?;

                let ip_addr = ip.addr();
                let records = self
                    .by_name
                    .iter()
                    .filter(|(_, v)| match ip_addr {
                        IpAddr::V4(ip) => match v.a.as_ref() {
                            Some(lookup) => lookup.records().iter().any(|r| {
                                r.rdata().ip_addr().map(|it| it == ip).unwrap_or_default()
                            }),
                            None => false,
                        },
                        IpAddr::V6(ip) => match v.aaaa.as_ref() {
                            Some(lookup) => lookup.records().iter().any(|r| {
                                r.rdata().ip_addr().map(|it| it == ip).unwrap_or_default()
                            }),
                            None => false,
                        },
                    })
                    .map(|(n, _)| {
                        Record::from_rdata(
                            name.clone(),
                            TimeToLive::DAY,
                            RData::PTR(PTR(n.clone())),
                        )
                    })
                    .collect::<Vec<Record>>();

                if records.is_empty() {
                    return None;
                }

                Some(lookup_with_max_ttl(query.clone(), records))
            }
            _ => None,
        }
    }

    /// Insert a new Lookup for the associated `Name` and `RecordType`
    pub fn insert(&mut self, mut name: Name, record_type: RecordType, mut lookup: QueryLookup) {
        assert!(record_type == RecordType::A || record_type == RecordType::AAAA);

        name.set_fqdn(true);
        let lookup_type = self.by_name.entry(name.clone()).or_default();

        let new_lookup = {
            let old_lookup = match record_type {
                RecordType::A => lookup_type.a.get_or_insert_with(|| {
                    let query = Query::query(name.clone(), record_type);
                    lookup_with_max_ttl(query, Default::default())
                }),
                RecordType::AAAA => lookup_type.aaaa.get_or_insert_with(|| {
                    let query = Query::query(name.clone(), record_type);
                    lookup_with_max_ttl(query, Default::default())
                }),
                _ => {
                    tracing::warn!("unsupported IP type from Hosts file: {:#?}", record_type);
                    return;
                }
            };

            //TODO: This clone could be removed with more ergonomic lookups.
            lookup.records_mut().merge(old_lookup.records.clone());
            lookup
        };

        // replace the appended version
        match record_type {
            RecordType::A => lookup_type.a = Some(new_lookup),
            RecordType::AAAA => lookup_type.aaaa = Some(new_lookup),
            _ => tracing::warn!("unsupported IP type from Hosts file"),
        }
    }

    /// parse configuration from `src`
    pub fn read_hosts_conf(&mut self, src: impl io::Read) -> io::Result<()> {
        use std::io::{BufRead, BufReader};

        // lines in the src should have the form `addr host1 host2 host3 ...`
        // line starts with `#` will be regarded with comments and ignored,
        // also empty line also will be ignored,
        // if line only include `addr` without `host` will be ignored,
        // the src will be parsed to map in the form `Name -> LookUp`.

        for (line_index, line) in BufReader::new(src).lines().enumerate() {
            let line = line?;

            // Remove byte-order mark if present
            let line = if line_index == 0 && line.starts_with('\u{feff}') {
                // BOM is 3 bytes
                &line[3..]
            } else {
                &line
            };

            // Remove comments from the line
            let line = match line.split_once('#') {
                Some((line, _)) => line,
                None => line,
            }
            .trim();

            if line.is_empty() {
                continue;
            }

            let mut iter = line.split_whitespace();
            let addr = match iter.next() {
                Some(addr) => match IpAddr::from_str(addr) {
                    Ok(addr) => RData::from(addr),
                    Err(_) => {
                        warn!("could not parse an IP from hosts file ({addr:?})");
                        continue;
                    }
                },
                None => continue,
            };

            for domain in iter {
                let domain = domain.to_lowercase();
                let Ok(mut name) = Name::from_str(&domain) else {
                    continue;
                };

                name.set_fqdn(true);
                let record = Record::from_rdata(name.clone(), TimeToLive::DAY, addr.clone());
                match addr {
                    RData::A(..) => {
                        let query = Query::query(name.clone(), RecordType::A);
                        let lookup = lookup_with_max_ttl(query, vec![record]);
                        self.insert(name.clone(), RecordType::A, lookup);
                    }
                    RData::AAAA(..) => {
                        let query = Query::query(name.clone(), RecordType::AAAA);
                        let lookup = lookup_with_max_ttl(query, vec![record]);
                        self.insert(name.clone(), RecordType::AAAA, lookup);
                    }
                    _ => {
                        warn!("unsupported IP type from Hosts file: {:#?}", addr);
                        continue;
                    }
                };

                // TODO: insert reverse lookup as well.
            }
        }

        Ok(())
    }
}

#[cfg(unix)]
fn hosts_path() -> &'static str {
    "/etc/hosts"
}

#[cfg(windows)]
fn hosts_path() -> std::path::PathBuf {
    let system_root =
        std::env::var_os("SystemRoot").expect("Environment variable SystemRoot not found");
    let system_root = Path::new(&system_root);
    system_root.join("System32\\drivers\\etc\\hosts")
}

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
    pub fn resolve(&self, query: Query) -> Option<QueryLookup> {
        self.hosts.lookup_static_host(&query)
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
            let mut msg: Message = lookup.into();
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
    use crate::messages::DnsRequestOptions;

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

        let mut hosts = Hosts::default();

        // Add localhost A record (127.0.0.1)
        let localhost_name = Name::from_str("localhost.").unwrap();
        let localhost_a_query = Query::query(localhost_name.clone(), RecordType::A);
        let localhost_a_lookup =
            QueryLookup::from_rdata(localhost_a_query, RData::A(A::new(127, 0, 0, 1)));
        hosts.insert(localhost_name.clone(), RecordType::A, localhost_a_lookup);

        // Add localhost AAAA record (::1)
        let localhost_aaaa_query = Query::query(localhost_name.clone(), RecordType::AAAA);
        let localhost_aaaa_lookup = QueryLookup::from_rdata(
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
            QueryLookup::from_rdata(test_local_query, RData::A(A::new(192, 168, 1, 100)));
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
        use crate::messages::Message;
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
        let request = DnsRequest::new(msg, DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answer_count(), 1);
    }

    #[tokio::test]
    async fn test_hosts_service_test_local_resolution() {
        use crate::messages::Message;
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
        let request = DnsRequest::new(msg, DnsRequestOptions::default());

        let response = service.call(request).await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answer_count(), 1);
    }

    #[tokio::test]
    async fn test_hosts_service_forwarding_behavior() {
        use crate::messages::Message;
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
            let request = DnsRequest::new(msg, DnsRequestOptions::default());

            let response = service.call(request).await.unwrap();
            assert_eq!(response.response_code(), ResponseCode::NXDomain);
        }
    }

    use std::env;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_read_hosts_conf() {
        let path = format!("{}/tests/data/hosts", env!("CARGO_MANIFEST_DIR"));
        let hosts = Hosts::from_file(path).unwrap();

        let name = Name::from_str("localhost.").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::A))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();

        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::LOCALHOST.into())]);

        let rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::AAAA))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();

        assert_eq!(
            rdatas,
            vec![RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into())]
        );

        let name = Name::from_str("broadcasthost").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::A))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();
        assert_eq!(
            rdatas,
            vec![RData::A(Ipv4Addr::new(255, 255, 255, 255).into())]
        );

        let name = Name::from_str("example.com").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::A))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(10, 0, 1, 102).into())]);

        let name = Name::from_str("a.example.com").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::A))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(10, 0, 1, 111).into())]);

        let name = Name::from_str("b.example.com").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::A))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(10, 0, 1, 111).into())]);

        let name = Name::from_str("111.1.0.10.in-addr.arpa.").unwrap();
        let mut rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::PTR))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();
        rdatas.sort_by_key(|r| r.as_ptr().as_ref().map(|p| p.0.clone()));
        assert_eq!(
            rdatas,
            vec![
                RData::PTR(PTR("a.example.com.".parse().unwrap())),
                RData::PTR(PTR("b.example.com.".parse().unwrap()))
            ]
        );

        let name = Name::from_str(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        )
        .unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name, RecordType::PTR))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.rdata())
            .map(ToOwned::to_owned)
            .collect::<Vec<RData>>();
        assert_eq!(
            rdatas,
            vec![RData::PTR(PTR("localhost.".parse().unwrap())),]
        );
    }
}
