use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(feature = "tls")]
use std::path::Path;
use std::str::FromStr;
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::Duration;
// use std::time::Duration;

use chateau::server::Server;
#[cfg(feature = "tls")]
use chateau::server::conn::tls::TlsAcceptor;
#[cfg(feature = "tls")]
use chateau::services::SharedService;
use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, OPT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
#[cfg(feature = "tls")]
use hickory_proto::rustls::default_provider;

#[cfg(feature = "tls")]
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
#[cfg(feature = "tls")]
use walnut_dns::client::DnsRequestMiddleware;
use walnut_dns::client::nameserver::{ConnectionConfig, NameserverConfig};
#[cfg(feature = "tls")]
use walnut_dns::client::nameserver::{NameServerConnection, Nameserver};
use walnut_dns::client::{Client, ClientConfiguration};
use walnut_dns::messages::Message;
use walnut_dns::rr::Zone;
use walnut_dns::server::stream::DnsOverStream;
use walnut_dns::server::udp::{DnsOverUdp, UdpListener};
use walnut_dns::{Catalog, SqliteStore};

mod support;
use support::examples::create_example;
use support::subscribe;
use walnut_dns::ZoneInfo as _;

#[tokio::test]
#[allow(clippy::uninlined_format_args)]
async fn test_server_www_udp() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = tokio::time::timeout(Duration::from_secs(5), UdpSocket::bind(&addr))
        .await
        .expect("bind timeout")
        .unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let (tx, shutdown) = oneshot::channel();

    let server = tokio::spawn(server_thread_udp(udp_socket, shutdown));
    let client = tokio::spawn(client_thread_www(lazy_udp_client(ipaddr)));

    let client_result = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("client timeout");
    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server timeout")
        .unwrap();
}

#[tokio::test]
#[allow(clippy::uninlined_format_args)]
async fn test_server_www_tcp() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let tcp_listener = TcpListener::bind(&addr).await.unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listener on port: {}", ipaddr);
    let (tx, shutdown) = oneshot::channel();

    let server = tokio::spawn(server_thread_tcp(tcp_listener, shutdown));
    let client = tokio::spawn(client_thread_www(lazy_tcp_client(ipaddr)));

    let client_result = client.await;
    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_unknown_type() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {ipaddr}");
    let (tx, shutdown) = oneshot::channel();

    let server = tokio::spawn(server_thread_udp(udp_socket, shutdown));
    let client = lazy_udp_client(ipaddr).await;

    let client_result = client
        .lookup(
            Query::query(
                Name::from_str("www.example.com.").unwrap(),
                RecordType::Unknown(65535),
            ),
            Default::default(),
        )
        .await
        .expect("query failed for unknown");

    assert_eq!(client_result.response_code(), ResponseCode::NoError);
    assert_eq!(
        client_result.queries().first().unwrap().query_type(),
        RecordType::Unknown(65535)
    );
    assert!(client_result.answers().is_empty());
    assert!(!client_result.name_servers().is_empty());
    // SOA should be the first record in the response
    assert_eq!(
        client_result
            .name_servers()
            .first()
            .expect("no SOA present")
            .record_type(),
        RecordType::SOA
    );

    tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_form_error_on_multiple_queries() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {ipaddr}");
    let (tx, shutdown) = oneshot::channel();

    let server = tokio::spawn(server_thread_udp(udp_socket, shutdown));
    let client = lazy_udp_client(ipaddr).await;

    // build the message
    let query_a = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let query_aaaa = Query::query(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::AAAA,
    );
    let mut message: Message = Message::new();
    message
        .add_query(query_a)
        .add_query(query_aaaa)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);

    let client_result = client
        .send(message, Default::default())
        .await
        .expect("query failed");

    assert_eq!(client_result.response_code(), ResponseCode::FormErr);

    tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_no_response_on_response() {
    use tower::Service as _;
    use walnut_dns::error::HickoryError;
    use walnut_dns::messages::Protocol;
    use walnut_dns::messages::server::Incoming;

    subscribe();

    // A message whose header marks it as a response rather than a query. Per RFC 1035 a server must
    // never reply to a response, to avoid infinite packet loops between servers.
    //
    // We drive the catalog service directly instead of going over a socket: "the server sends
    // nothing back" cannot be observed with a request/response client, which would simply wait for
    // a reply that never arrives. At the service level the refusal surfaces as an error, which is
    // what the server's connection loop then swallows without emitting a response.
    let mut catalog = new_catalog().await;

    let query_a = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .add_query(query_a);

    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353));
    let request = Incoming::new(message, peer, Protocol::Udp);

    let result = catalog.call(request).await;

    assert!(
        matches!(result, Err(HickoryError::ResponseAsRequest)),
        "server must not produce a response for a response message, got: {result:?}"
    );
}

#[allow(unused)]
fn read_file(path: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut bytes = vec![];

    let mut file = File::open(path).unwrap_or_else(|_| panic!("failed to open file: {path}"));
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("failed to read file: {path}"));
    bytes
}

#[tokio::test]
#[cfg(feature = "tls")]
async fn test_server_www_tls() {
    use std::env;

    subscribe();

    let dns_name = "ns.example.com.";

    let server_path = Path::new(env!("CARGO_MANIFEST_PATH")).parent().unwrap();
    println!("using server src path: {}", server_path.display());

    let ca = read_certs(server_path.join("tests/test-data/ca.pem")).unwrap();
    let cert_chain = read_certs(server_path.join("tests/test-data/cert.pem")).unwrap();

    let key = PrivateKeyDer::from_pem_file(server_path.join("tests/test-data/cert.key")).unwrap();

    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider()).unwrap();
    let server_cert_resolver = SingleCertAndKey::from(certified_key);

    // Server address
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let tcp_listener = TcpListener::bind(&addr).await.unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listener on port: {ipaddr}");
    let (tx, shutdown) = oneshot::channel();

    let server = tokio::spawn(server_thread_tls(
        tcp_listener,
        shutdown,
        Arc::new(server_cert_resolver),
    ));

    let client = tokio::spawn(client_thread_www(lazy_tls_client(
        ipaddr,
        dns_name.to_string(),
        ca,
    )));

    let client_result = client.await;

    assert!(client_result.is_ok(), "client failed: {client_result:?}");
    tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tls")]
async fn test_server_www_https() {
    use std::env;

    subscribe();

    let dns_name = "ns.example.com.";

    let server_path = Path::new(env!("CARGO_MANIFEST_PATH")).parent().unwrap();
    println!("using server src path: {}", server_path.display());

    let ca = read_certs(server_path.join("tests/test-data/ca.pem")).unwrap();
    let cert_chain = read_certs(server_path.join("tests/test-data/cert.pem")).unwrap();

    let key = PrivateKeyDer::from_pem_file(server_path.join("tests/test-data/cert.key")).unwrap();

    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider()).unwrap();
    let server_cert_resolver = SingleCertAndKey::from(certified_key);

    // Server address
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let tcp_listener = TcpListener::bind(&addr).await.unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listener on port: {ipaddr}");
    let (tx, shutdown) = oneshot::channel();

    let server = tokio::spawn(server_thread_https(
        tcp_listener,
        shutdown,
        Arc::new(server_cert_resolver),
    ));

    let client = tokio::spawn(client_thread_www(lazy_https_client(
        ipaddr,
        dns_name.to_string(),
        ca,
    )));

    let client_result = client.await;

    assert!(client_result.is_ok(), "client failed: {client_result:?}");
    tx.send(()).unwrap();
    server.await.unwrap();
}

async fn lazy_udp_client(addr: SocketAddr) -> Client {
    let mut conn_config = ConnectionConfig::udp();
    conn_config.port = addr.port();
    let ns = NameserverConfig::single(addr.ip(), conn_config);
    let cfg = ClientConfiguration::from(ns);

    let client = Client::new(cfg);
    client
}

async fn lazy_tcp_client(addr: SocketAddr) -> Client {
    let mut conn_config = ConnectionConfig::tcp();
    conn_config.port = addr.port();
    let ns = NameserverConfig::single(addr.ip(), conn_config);
    let cfg = ClientConfiguration::from(ns);
    let client = Client::new(cfg);
    client
}

#[cfg(feature = "tls")]
fn read_certs(cert_path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, pem::Error> {
    CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()
}

#[cfg(feature = "tls")]
async fn lazy_tls_client(
    ipaddr: SocketAddr,
    dns_name: String,
    cert_chain: Vec<CertificateDer<'static>>,
) -> Client {
    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(cert_chain);
    assert_eq!(ignored, 0, "bad certificate!");

    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let conn = NameServerConnection::build_tls(
        ipaddr,
        Default::default(),
        Arc::new(config),
        dns_name.into(),
        None,
    );

    let mut ns = Nameserver::empty(ipaddr.ip());
    ns.push_connection(conn);

    let svc = SharedService::new(DnsRequestMiddleware::new(ns));

    Client::from_service(svc, 2048)
}

#[cfg(feature = "tls")]
async fn lazy_https_client(
    ipaddr: SocketAddr,
    dns_name: String,
    cert_chain: Vec<CertificateDer<'static>>,
) -> Client {
    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(cert_chain);
    assert_eq!(ignored, 0, "bad certificate!");

    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let conn = NameServerConnection::build_https(
        ipaddr,
        Default::default(),
        Arc::new(config),
        dns_name.into(),
        "/dns-query".into(),
        None,
    );

    let mut ns = Nameserver::empty(ipaddr.ip());
    ns.push_connection(conn);

    let svc = SharedService::new(DnsRequestMiddleware::new(ns));

    Client::from_service(svc, 2048)
}

async fn client_thread_www(future: impl Future<Output = Client>) {
    let name = Name::from_str("www.example.com.").unwrap();

    let client = future.await;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.lookup(
            Query::query(name.clone(), RecordType::A),
            Default::default(),
        ),
    )
    .await
    .expect("timeout querying")
    .expect("error querying");

    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "got an error: {:?}",
        response.response_code()
    );
    assert!(response.header().authoritative());

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.record_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(address) = *record.data() {
        assert_eq!(address, A::new(93, 184, 215, 14))
    } else {
        panic!();
    }
}

async fn new_catalog() -> Catalog<Zone> {
    let example = create_example();
    let origin = example.origin().clone();

    let catalog = Catalog::new(SqliteStore::new_in_memory().await.unwrap());

    catalog.upsert(origin, vec![example]).await.unwrap();
    catalog
}

async fn server_thread_udp(udp_socket: UdpSocket, shutdown: oneshot::Receiver<()>) {
    let catalog = new_catalog().await;
    let server = Server::builder()
        .with_shared_service(catalog)
        .with_tokio()
        .with_acceptor(UdpListener::new(udp_socket.into()))
        .with_protocol(DnsOverUdp::new())
        .with_graceful_shutdown(async move {
            let _ = shutdown.await;
        });

    server.await.unwrap();
}

#[allow(unused)]
async fn server_thread_tcp(tcp_listener: TcpListener, shutdown: oneshot::Receiver<()>) {
    let catalog = new_catalog().await;

    let server = Server::builder()
        .with_shared_service(catalog)
        .with_tokio()
        .with_protocol(DnsOverStream::tcp())
        .with_acceptor(tcp_listener)
        .with_graceful_shutdown(async move {
            let _ = shutdown.await;
        });
    server.await.unwrap();
}

#[cfg(feature = "tls")]
async fn server_thread_tls(
    tls_listener: TcpListener,
    shutdown: oneshot::Receiver<()>,
    cert_chain: Arc<dyn ResolvesServerCert>,
) {
    let catalog = new_catalog().await;
    let mut tls_config = ServerConfig::builder_with_provider(default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(cert_chain);
    tls_config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = TlsAcceptor::new(Arc::new(tls_config), tls_listener);

    Server::builder()
        .with_acceptor(acceptor)
        .with_shared_service(catalog)
        .with_tokio()
        .with_protocol(DnsOverStream::tls())
        .with_graceful_shutdown(async move {
            shutdown.await.ok();
        })
        .await
        .unwrap();
}

#[cfg(feature = "h2")]
async fn server_thread_https(
    listener: TcpListener,
    shutdown: oneshot::Receiver<()>,
    cert_chain: Arc<dyn ResolvesServerCert>,
) {
    use hyperdriver::server::ServerProtocolExt as _;
    use walnut_dns::services::http::DnsOverHttpLayer;

    let catalog = new_catalog().await;
    let mut tls_config = ServerConfig::builder_with_provider(default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(cert_chain);
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    hyperdriver::Server::builder::<http::Request<hyperdriver::Body>>()
        .with_acceptor(
            hyperdriver::server::conn::Acceptor::new(listener).with_tls(tls_config.into()),
        )
        .with_http2()
        .with_tokio()
        .with_shared_service(
            tower::ServiceBuilder::new()
                .layer(DnsOverHttpLayer::new(http::Version::HTTP_2))
                .service(catalog),
        )
        .with_graceful_shutdown(async move {
            shutdown.await.ok();
        })
        .await
        .unwrap()
}

/// This test checks the behavior of the server when it receives a query with too many OPT RRs.
///
/// RFC 6891 section 6.1.1 says that "If a query message with more than one OPT RR is received, a
/// FORMERR (RCODE=1) MUST be returned."
#[tokio::test]
async fn edns_multiple_opt_rr() {
    subscribe();

    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = udp_socket.local_addr().unwrap();
    let (tx, shutdown) = oneshot::channel();
    let server = tokio::spawn(server_thread_udp(udp_socket, shutdown));

    let mut message = Message::new();
    message.add_query(Query::query(Name::root(), RecordType::NS));
    message.add_additional(Record::from_rdata(
        Name::root(),
        0,
        RData::OPT(OPT::new(vec![])),
    ));
    message.add_additional(Record::from_rdata(
        Name::root(),
        0,
        RData::OPT(OPT::new(vec![])),
    ));
    let message_bytes = message.to_vec().unwrap();

    // We cannot use UdpClientStream, because it tries to parse the request message. This would fail
    // because of the duplicate OPT records.
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client_socket
        .send_to(&message_bytes, local_addr)
        .await
        .unwrap();
    let mut response_buf = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        client_socket.recv_buf_from(&mut response_buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = Message::from_vec(&response_buf).unwrap();

    dbg!(&response);
    assert_eq!(message.header().id(), response.header().id());
    assert_eq!(response.response_code(), ResponseCode::FormErr);

    tx.send(()).unwrap();
    server.await.unwrap();
}
