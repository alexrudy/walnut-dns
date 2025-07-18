use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
// use std::time::Duration;

use chateau::server::Server;
use chateau::server::conn::tls::TlsAcceptor;
use futures::TryStreamExt;
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, OPT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::rustls::default_provider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsMultiplexer};
use rustls::ServerConfig;
use rustls::{
    ClientConfig, RootCertStore,
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
use walnut_dns::rr::Zone;
use walnut_dns::server::stream::DnsOverStream;
use walnut_dns::server::udp::{DnsOverUdp, UdpListener};
use walnut_dns::{Catalog, SqliteStore};

mod support;
use support::examples::create_example;
use support::subscribe;
use walnut_dns::ZoneInfo as _;
use walnut_dns::authority::ZoneAuthority;

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
    let mut client = lazy_udp_client(ipaddr).await;

    let client_result = client
        .query(
            Name::from_str("www.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::Unknown(65535),
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

    let mut client_result = client
        .send(message)
        .try_collect::<Vec<_>>()
        .await
        .expect("query failed");

    assert_eq!(client_result.len(), 1);
    let client_result = client_result.pop().expect("there should be one response");

    assert_eq!(client_result.response_code(), ResponseCode::FormErr);

    tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_no_response_on_response() {
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
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .add_query(query_a);

    let client_result = client.send(message).try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(client_result.len(), 0);

    tx.send(()).unwrap();
    server.await.unwrap();
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
#[allow(clippy::uninlined_format_args)]
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

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    tx.send(()).unwrap();
    server.await.unwrap();
}

async fn lazy_udp_client(addr: SocketAddr) -> Client {
    let conn = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
    let (client, driver) = Client::connect(conn).await.expect("failed to connect");
    tokio::spawn(driver);
    client
}

async fn lazy_tcp_client(addr: SocketAddr) -> Client {
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::default());
    let multiplexer = DnsMultiplexer::new(stream, sender, None);
    let (client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

fn read_certs(cert_path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, pem::Error> {
    CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()
}

async fn lazy_tls_client(
    ipaddr: SocketAddr,
    dns_name: String,
    cert_chain: Vec<CertificateDer<'static>>,
) -> Client {
    use hickory_proto::rustls::tls_client_connect_with_bind_addr;

    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(cert_chain);
    assert_eq!(ignored, 0, "bad certificate!");

    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let (tls_client_stream, handle) = tls_client_connect_with_bind_addr(
        ipaddr,
        None,
        dns_name,
        Arc::new(config),
        TokioRuntimeProvider::default(),
    );

    let multiplexer = DnsMultiplexer::new(Box::pin(tls_client_stream), handle, None);
    let (client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

async fn client_thread_www(future: impl Future<Output = Client>) {
    let name = Name::from_str("www.example.com.").unwrap();

    let mut client = future.await;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.query(name.clone(), DNSClass::IN, RecordType::A),
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

async fn new_catalog() -> Catalog<ZoneAuthority<Zone>> {
    let example = create_example();
    let origin = example.origin().clone();

    let catalog = Catalog::new(SqliteStore::new_in_memory().await.unwrap());

    catalog
        .upsert(origin, vec![ZoneAuthority::new(example)])
        .await
        .unwrap();
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

async fn server_thread_tls(
    tls_listener: TcpListener,
    shutdown: oneshot::Receiver<()>,
    cert_chain: Arc<dyn ResolvesServerCert>,
) {
    let catalog = new_catalog().await;
    let mut tls_config = ServerConfig::builder()
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
