use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use chateau::client::conn::ConnectionError;
use chateau::client::conn::dns::{SocketAddrs, StaticResolver};
use chateau::client::conn::protocol::framed::FramedProtocol;
use chateau::client::conn::service::ClientExecutorService;
#[cfg(feature = "tls")]
use chateau::client::conn::transport::StaticHostTlsTransport;
use chateau::client::conn::transport::tcp::{
    SimpleTcpTransport, TcpConnectionError, TcpTransportConfig,
};
use chateau::client::{ConnectionManagerService, pool::manager::ConnectionManagerConfig};
use chateau::services::SharedService;
use futures::future::BoxFuture;
use serde::Deserialize;

use crate::client::DnsClientError;
use crate::client::udp::{DnsUdpProtocol, DnsUdpTransport};
use crate::codec::CodecError;
use crate::{client::codec::TaggedMessage, codec::DnsCodec};

use super::ConnectionPolicy;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn into_dns_error<T, P, S>(error: ConnectionError<T, P, S>) -> DnsClientError
where
    T: Into<BoxError>,
    P: Into<BoxError>,
    S: Into<BoxError>,
{
    match error {
        ConnectionError::Connecting(error) => DnsClientError::Transport(error.into()),
        ConnectionError::Handshaking(error) => DnsClientError::Protocol(error.into()),
        ConnectionError::Service(error) => DnsClientError::Service(error.into()),
        ConnectionError::Unavailable => {
            DnsClientError::Unavailable("UDP Connection not possible".into())
        }
        ConnectionError::Key(_) => unreachable!("No key used by manager"),
        _ => panic!("unknown error type"),
    }
}

/// A single connection to a nameserver
#[derive(Debug, Clone)]
pub struct NameServerConnection {
    service: SharedService<TaggedMessage, TaggedMessage, DnsClientError>,
    config: Arc<ConnectionConfig>,
    address: SocketAddr,
}

impl NameServerConnection {
    pub fn protocol(&self) -> hickory_proto::xfer::Protocol {
        self.config.protocol.protocol()
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl NameServerConnection {
    pub fn from_config(address: IpAddr, config: &ConnectionConfig) -> Self {
        match &config.protocol {
            ProtocolConfig::Udp => Self::new_udp(address, config),
            ProtocolConfig::Tcp => Self::new_tcp(address, config),
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { server_name } => {
                let server_name = server_name.clone();
                Self::new_tls(address, config, server_name)
            }
            #[cfg(feature = "h2")]
            ProtocolConfig::Https {
                server_name,
                endpoint,
            } => {
                let server_name = server_name.clone();
                let endpoint = endpoint.clone();
                Self::new_https(address, config, server_name, endpoint)
            }
        }
    }

    fn new_udp(address: IpAddr, config: &ConnectionConfig) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let codec: DnsCodec<TaggedMessage, TaggedMessage> =
            DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Udp);

        let transport = DnsUdpTransport::new(bind, addr);
        let protocol = DnsUdpProtocol::new(codec, false);

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = None;
        manager_cfg.max_idle_per_host = 1;
        manager_cfg.continue_after_preemption = false;

        let svc = tower::ServiceBuilder::new()
            .map_err(into_dns_error::<io::Error, io::Error, DnsClientError>)
            .service(ConnectionManagerService::new(
                transport,
                protocol,
                ClientExecutorService::new(),
                manager_cfg,
            ));
        Self {
            service: SharedService::new(svc),
            config: Arc::new(config.clone()),
            address: addr,
        }
    }

    fn new_tcp(address: IpAddr, config: &ConnectionConfig) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let codec: DnsCodec<TaggedMessage, TaggedMessage> =
            DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Tcp);
        let protocol = FramedProtocol::new(codec);

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = config.timeout.map(|timeout| Duration::from_secs(timeout));
        manager_cfg.max_idle_per_host = 1;
        manager_cfg.continue_after_preemption = true;

        let service = tower::ServiceBuilder::new()
            .map_err(into_dns_error::<TcpConnectionError, CodecError, CodecError>)
            .service(ConnectionManagerService::new(
                SimpleTcpTransport::new(
                    StaticResolver::new(SocketAddrs::from(addr)),
                    TcpTransportConfig::default(),
                ),
                protocol,
                ClientExecutorService::new(),
                manager_cfg,
            ));
        Self {
            service: SharedService::new(service),
            config: Arc::new(config.clone()),
            address: addr,
        }
    }

    #[cfg(feature = "tls")]
    fn new_tls(address: IpAddr, config: &ConnectionConfig, server_name: Box<str>) -> Self {
        use std::time::Duration;

        use chateau::client::conn::transport::TlsConnectionError;

        let addr = SocketAddr::new(address, config.port);
        let codec: DnsCodec<TaggedMessage, TaggedMessage> =
            DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Tls);
        let mut tlsconfig = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        tlsconfig.alpn_protocols = vec![b"dot".to_vec()];

        let transport = StaticHostTlsTransport::new(
            SimpleTcpTransport::new(
                StaticResolver::new(SocketAddrs::from(addr)),
                TcpTransportConfig::default(),
            ),
            Arc::new(tlsconfig),
            server_name,
        );
        let protocol = FramedProtocol::new(codec);

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = config.timeout.map(|timeout| Duration::from_secs(timeout));
        manager_cfg.max_idle_per_host = 1;
        manager_cfg.continue_after_preemption = true;

        let service = tower::ServiceBuilder::new()
            .map_err(
                into_dns_error::<TlsConnectionError<TcpConnectionError>, CodecError, CodecError>,
            )
            .service(ConnectionManagerService::new(
                transport,
                protocol,
                ClientExecutorService::new(),
                manager_cfg,
            ));

        Self {
            service: SharedService::new(service),
            config: Arc::new(config.clone()),
            address: addr,
        }
    }

    #[cfg(feature = "h2")]
    fn new_https(
        address: IpAddr,
        config: &ConnectionConfig,
        server_name: Box<str>,
        endpoint: Box<str>,
    ) -> Self {
        use hyperdriver::bridge::rt::TokioExecutor;
        use hyperdriver::client::conn::transport::tcp::SimpleTcpTransport;

        use crate::client::DnsOverHttpLayer;

        let addr = SocketAddr::new(address, config.port);
        let mut tlsconfig = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        tlsconfig.alpn_protocols = vec![b"h2".to_vec()];
        let resolver = StaticResolver::new(SocketAddrs::from(addr));
        let transport = StaticHostTlsTransport::new(
            SimpleTcpTransport::new(resolver, Default::default()),
            Arc::new(tlsconfig),
            server_name,
        );

        let protocol = hyperdriver::client::conn::protocol::Http2Builder::new(TokioExecutor);

        let uri = format!("https://dns/{endpoint}").parse().unwrap();

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = config.timeout.map(|timeout| Duration::from_secs(timeout));
        manager_cfg.max_idle_per_host = 1;
        manager_cfg.continue_after_preemption = true;

        let svc = tower::ServiceBuilder::new()
            .layer(DnsOverHttpLayer::new(http::Version::HTTP_2, uri))
            .service(ConnectionManagerService::new(
                transport,
                protocol,
                ClientExecutorService::new(),
                manager_cfg,
            ));

        Self {
            service: SharedService::new(svc),
            config: Arc::new(config.clone()),
            address: addr,
        }
    }
}

impl tower::Service<TaggedMessage> for NameServerConnection {
    type Response = TaggedMessage;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<TaggedMessage, DnsClientError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        self.service.call(req)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NameserverConfig {
    pub address: IpAddr,
    pub connections: Vec<ConnectionConfig>,
    #[serde(default)]
    pub policy: ConnectionPolicy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    pub protocol: ProtocolConfig,
    pub port: u16,

    /// Timeout for the connection in seconds.
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolConfig {
    Udp,
    Tcp,
    #[cfg(feature = "tls")]
    Tls {
        server_name: Box<str>,
    },
    #[cfg(feature = "h2")]
    Https {
        server_name: Box<str>,
        endpoint: Box<str>,
    },
}

impl ProtocolConfig {
    pub fn is_secure(&self) -> bool {
        match self {
            ProtocolConfig::Udp => false,
            ProtocolConfig::Tcp => false,
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { .. } => true,
            #[cfg(feature = "h2")]
            ProtocolConfig::Https { .. } => true,
        }
    }

    pub fn protocol(&self) -> hickory_proto::xfer::Protocol {
        match self {
            ProtocolConfig::Udp => hickory_proto::xfer::Protocol::Udp,
            ProtocolConfig::Tcp => hickory_proto::xfer::Protocol::Tcp,
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { .. } => hickory_proto::xfer::Protocol::Tls,
            #[cfg(feature = "h2")]
            ProtocolConfig::Https { .. } => hickory_proto::xfer::Protocol::Https,
        }
    }
}
