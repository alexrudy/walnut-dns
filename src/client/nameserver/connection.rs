use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(feature = "tls")]
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
#[cfg(feature = "tls")]
use rustls::ClientConfig;
use serde::Deserialize;

use crate::client::DnsClientError;
use crate::client::udp::{DnsUdpProtocol, DnsUdpTransport};
use crate::codec::CodecError;
use crate::codec::DnsCodec;
use crate::messages::{Message, Protocol};

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
    service: SharedService<Message, Message, DnsClientError>,
    protocol: Protocol,
    address: SocketAddr,
}

impl NameServerConnection {
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl NameServerConnection {
    pub fn from_config(address: IpAddr, config: &ConnectionConfig, bind: Option<IpAddr>) -> Self {
        match &config.protocol {
            ProtocolConfig::Udp => Self::new_udp(
                address,
                config,
                bind.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            ),
            ProtocolConfig::Tcp => Self::new_tcp(
                address,
                config,
                bind.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            ),
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { server_name } => {
                let server_name = server_name.clone();
                Self::new_tls(
                    address,
                    config,
                    server_name,
                    bind.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
                )
            }
            #[cfg(all(feature = "h2", feature = "tls"))]
            ProtocolConfig::Https {
                server_name,
                endpoint,
            } => {
                let server_name = server_name.clone();
                let endpoint = endpoint.clone();
                Self::new_https(
                    address,
                    config,
                    server_name,
                    endpoint,
                    bind.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
                )
            }
        }
    }

    fn new_udp(address: IpAddr, config: &ConnectionConfig, bind: IpAddr) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let bind = SocketAddr::new(bind, 0);
        let codec: DnsCodec<Message, Message> = DnsCodec::new_for_protocol(Protocol::Udp);

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
            protocol: Protocol::Udp,
            address: addr,
        }
    }

    fn new_tcp(address: IpAddr, config: &ConnectionConfig, bind: IpAddr) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let codec: DnsCodec<Message, Message> = DnsCodec::new_for_protocol(Protocol::Tcp);
        let protocol = FramedProtocol::new(codec);

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = config.timeout.map(Duration::from_secs);
        manager_cfg.max_idle_per_host = 1;
        manager_cfg.continue_after_preemption = true;

        let mut tcp_config = TcpTransportConfig::default();
        if !bind.is_unspecified() {
            match bind {
                IpAddr::V4(addr) => {
                    tcp_config.local_address_ipv4 = Some(addr);
                }
                IpAddr::V6(addr) => {
                    tcp_config.local_address_ipv6 = Some(addr);
                }
            }
        }

        let service = tower::ServiceBuilder::new()
            .map_err(into_dns_error::<TcpConnectionError, CodecError, CodecError>)
            .service(ConnectionManagerService::new(
                SimpleTcpTransport::new(StaticResolver::new(SocketAddrs::from(addr)), tcp_config),
                protocol,
                ClientExecutorService::new(),
                manager_cfg,
            ));
        Self {
            service: SharedService::new(service),
            protocol: Protocol::Tcp,
            address: addr,
        }
    }

    #[cfg(feature = "tls")]
    pub fn build_tls(
        addr: SocketAddr,
        tcp_config: TcpTransportConfig,
        tls_config: Arc<ClientConfig>,
        server_name: Box<str>,
        timeout: Option<u64>,
    ) -> Self {
        use chateau::client::conn::transport::TlsConnectionError;

        let codec: DnsCodec<Message, Message> = DnsCodec::new_for_protocol(Protocol::Tls);
        let protocol = FramedProtocol::new(codec);

        let transport = StaticHostTlsTransport::new(
            SimpleTcpTransport::new(StaticResolver::new(SocketAddrs::from(addr)), tcp_config),
            tls_config,
            server_name,
        );

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = timeout.map(Duration::from_secs);
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
            protocol: Protocol::Tls,
            address: addr,
        }
    }

    #[cfg(feature = "tls")]
    fn new_tls(
        address: IpAddr,
        config: &ConnectionConfig,
        server_name: Box<str>,
        bind: IpAddr,
    ) -> Self {
        use std::time::Duration;

        use chateau::client::conn::transport::TlsConnectionError;

        let addr = SocketAddr::new(address, config.port);
        let codec: DnsCodec<Message, Message> = DnsCodec::new_for_protocol(Protocol::Tls);
        let mut tlsconfig = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        tlsconfig.alpn_protocols = vec![b"dot".to_vec()];

        let mut tcp_config = TcpTransportConfig::default();
        if !bind.is_unspecified() {
            match bind {
                IpAddr::V4(addr) => {
                    tcp_config.local_address_ipv4 = Some(addr);
                }
                IpAddr::V6(addr) => {
                    tcp_config.local_address_ipv6 = Some(addr);
                }
            }
        }
        let transport = StaticHostTlsTransport::new(
            SimpleTcpTransport::new(StaticResolver::new(SocketAddrs::from(addr)), tcp_config),
            Arc::new(tlsconfig),
            server_name,
        );
        let protocol = FramedProtocol::new(codec);

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = config.timeout.map(Duration::from_secs);
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
            protocol: Protocol::Tls,
            address: addr,
        }
    }

    #[cfg(all(feature = "h2", feature = "tls"))]
    pub fn build_https(
        address: SocketAddr,
        tcp_config: TcpTransportConfig,
        tls_config: Arc<ClientConfig>,
        server_name: Box<str>,
        endpoint: Box<str>,
        timeout: Option<u64>,
    ) -> Self {
        use hyperdriver::bridge::rt::TokioExecutor;
        use hyperdriver::client::conn::transport::tcp::SimpleTcpTransport;

        use crate::client::DnsOverHttpLayer;

        let transport = StaticHostTlsTransport::new(
            SimpleTcpTransport::new(StaticResolver::new(SocketAddrs::from(address)), tcp_config),
            tls_config,
            server_name,
        );
        let protocol = hyperdriver::client::conn::protocol::Http2Builder::new(TokioExecutor);

        let uri = format!("https://dns/{endpoint}").parse().unwrap();

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = timeout.map(Duration::from_secs);
        manager_cfg.max_idle_per_host = 1;
        manager_cfg.continue_after_preemption = true;

        let service = tower::ServiceBuilder::new()
            .layer(DnsOverHttpLayer::new(http::Version::HTTP_2, uri))
            .service(ConnectionManagerService::new(
                transport,
                protocol,
                ClientExecutorService::new(),
                manager_cfg,
            ));

        Self {
            service: SharedService::new(service),
            protocol: Protocol::Https,
            address,
        }
    }

    #[cfg(all(feature = "h2", feature = "tls"))]
    fn new_https(
        address: IpAddr,
        config: &ConnectionConfig,
        server_name: Box<str>,
        endpoint: Box<str>,
        bind: IpAddr,
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

        let mut tcp_config = TcpTransportConfig::default();
        if !bind.is_unspecified() {
            match bind {
                IpAddr::V4(addr) => {
                    tcp_config.local_address_ipv4 = Some(addr);
                }
                IpAddr::V6(addr) => {
                    tcp_config.local_address_ipv6 = Some(addr);
                }
            }
        }

        let resolver = StaticResolver::new(SocketAddrs::from(addr));
        let transport = StaticHostTlsTransport::new(
            SimpleTcpTransport::new(resolver, tcp_config),
            Arc::new(tlsconfig),
            server_name,
        );

        let protocol = hyperdriver::client::conn::protocol::Http2Builder::new(TokioExecutor);

        let uri = format!("https://dns/{endpoint}").parse().unwrap();

        let mut manager_cfg = ConnectionManagerConfig::default();
        manager_cfg.idle_timeout = config.timeout.map(Duration::from_secs);
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
            protocol: Protocol::Https,
            address: addr,
        }
    }
}

impl tower::Service<Message> for NameServerConnection {
    type Response = Message;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<Message, DnsClientError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
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

impl NameserverConfig {
    pub fn new(
        address: IpAddr,
        connections: Vec<ConnectionConfig>,
        policy: ConnectionPolicy,
    ) -> Self {
        Self {
            address,
            connections,
            policy,
        }
    }

    pub fn single(address: IpAddr, connection: ConnectionConfig) -> Self {
        Self::new(address, vec![connection], ConnectionPolicy::default())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    pub protocol: ProtocolConfig,
    pub port: u16,

    /// Timeout for the connection in seconds.
    pub timeout: Option<u64>,
}

impl ConnectionConfig {
    pub fn new(protocol: ProtocolConfig, port: u16, timeout: Option<u64>) -> Self {
        Self {
            protocol,
            port,
            timeout,
        }
    }

    pub fn udp() -> Self {
        Self::new(ProtocolConfig::Udp, 53, None)
    }

    pub fn tcp() -> Self {
        Self::new(ProtocolConfig::Tcp, 53, None)
    }

    #[cfg(feature = "tls")]
    pub fn tls(server_name: impl Into<Box<str>>) -> Self {
        Self::new(
            ProtocolConfig::Tls {
                server_name: server_name.into(),
            },
            853,
            None,
        )
    }

    #[cfg(all(feature = "h2", feature = "tls"))]
    pub fn https(server_name: impl Into<Box<str>>, endpoint: impl Into<Box<str>>) -> Self {
        Self::new(
            ProtocolConfig::Https {
                server_name: server_name.into(),
                endpoint: endpoint.into(),
            },
            443,
            None,
        )
    }
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
    #[cfg(all(feature = "h2", feature = "tls"))]
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
            #[cfg(all(feature = "h2", feature = "tls"))]
            ProtocolConfig::Https { .. } => true,
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            ProtocolConfig::Udp => Protocol::Udp,
            ProtocolConfig::Tcp => Protocol::Tcp,
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { .. } => Protocol::Tls,
            #[cfg(all(feature = "h2", feature = "tls"))]
            ProtocolConfig::Https { .. } => Protocol::Https,
        }
    }
}
