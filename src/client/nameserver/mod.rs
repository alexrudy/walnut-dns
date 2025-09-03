use std::cmp;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use chateau::client::conn::protocol::framed::FramedProtocol;
#[cfg(feature = "tls")]
use chateau::client::conn::transport::StaticHostTlsTransport;
use chateau::client::conn::transport::tcp::TcpTransport;
use serde::Deserialize;

mod connection;
mod pool;

use self::connection::SharedNameserverService;
pub use self::connection::{ConnectionStatus, NameserverConnection};
pub use self::pool::NameserverPool;
use super::{
    connection::{DnsConnector, DnsConnectorService},
    udp::{DnsUdpProtocol, DnsUdpTransport},
};
use crate::{client::codec::TaggedMessage, codec::DnsCodec};

#[derive(Debug, Clone)]
pub struct NameServerConnection {
    service: SharedNameserverService,

    #[allow(dead_code)]
    config: Arc<ConnectionConfig>,
}

impl NameServerConnection {
    pub fn from_config(address: IpAddr, config: ConnectionConfig) -> Self {
        match &config.protocol {
            ProtocolConfig::Udp => Self::new_udp(address, config),
            ProtocolConfig::Tcp => Self::new_tcp(address, config),
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { server_name } => {
                let server_name = server_name.clone();
                Self::new_tls(address, config, server_name)
            } // #[cfg(feature = "h2")]
              // ProtocolConfig::Https {
              //     server_name,
              //     endpoint,
              // } => Self::new_https(address, config, server_name, endpoint),
        }
    }

    fn new_udp(address: IpAddr, config: ConnectionConfig) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let codec: DnsCodec<TaggedMessage, TaggedMessage> =
            DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Udp);

        let transport = DnsUdpTransport::new(bind);
        let protocol = DnsUdpProtocol::new(codec, false);

        let connector = DnsConnector::new(addr, transport, protocol);
        let svc = DnsConnectorService::new(connector, hickory_proto::xfer::Protocol::Udp);
        Self {
            service: SharedNameserverService::new(svc),
            config: Arc::new(config),
        }
    }

    fn new_tcp(address: IpAddr, config: ConnectionConfig) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let codec: DnsCodec<TaggedMessage, TaggedMessage> =
            DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Tcp);
        let protocol = FramedProtocol::new(codec);
        let connector = DnsConnector::new(addr, TcpTransport::default(), protocol);
        let svc = DnsConnectorService::new(connector, hickory_proto::xfer::Protocol::Tcp);
        Self {
            service: SharedNameserverService::new(svc),
            config: Arc::new(config),
        }
    }

    #[cfg(feature = "tls")]
    fn new_tls(address: IpAddr, config: ConnectionConfig, server_name: Box<str>) -> Self {
        let addr = SocketAddr::new(address, config.port);
        let codec: DnsCodec<TaggedMessage, TaggedMessage> =
            DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Tls);
        let mut tlsconfig = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        tlsconfig.alpn_protocols = vec![b"dot".to_vec()];

        let transport =
            StaticHostTlsTransport::new(TcpTransport::default(), Arc::new(tlsconfig), server_name);
        let protocol = FramedProtocol::new(codec);
        let connector = DnsConnector::new(addr, transport, protocol);
        let svc = DnsConnectorService::new(connector, hickory_proto::xfer::Protocol::Tcp);
        Self {
            service: SharedNameserverService::new(svc),
            config: Arc::new(config),
        }
    }

    // #[cfg(feature = "h2")]
    // fn new_https(
    //     address: IpAddr,
    //     config: NameServerConfig,
    //     server_name: Box<str>,
    //     endpoint: Box<str>,
    // ) -> Self {
    //     use hyperdriver::bridge::rt::TokioExecutor;

    //     let addr = SocketAddr::new(address, config.port);
    //     let codec: DNSCodec<TaggedMessage, TaggedMessage> =
    //         DNSCodec::new_for_protocol(hickory_proto::xfer::Protocol::Https);
    //     let mut tlsconfig = rustls::ClientConfig::builder()
    //         .with_root_certificates(rustls::RootCertStore {
    //             roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    //         })
    //         .with_no_client_auth();
    //     tlsconfig.alpn_protocols = vec![b"h2".to_vec()];

    //     let transport =
    //         StaticHostTlsTransport::new(TcpTransport::default(), Arc::new(tlsconfig), server_name);

    //     let protocol = hyper::client::conn::http2::Builder::new(TokioExecutor);
    //     let connector = DNSConnector::new(addr, transport, protocol);
    //     let svc = DNSConnectorService::new(connector, hickory_proto::xfer::Protocol::Https);
    //     Self {
    //         service: SharedNameserverService::new(svc),
    //         config: Arc::new(config),
    //     }
    // }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NameserverConfig {
    pub address: IpAddr,
    pub connections: Vec<ConnectionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    pub protocol: ProtocolConfig,
    pub port: u16,
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
    // #[cfg(feature = "h2")]
    // Https {
    //     server_name: Box<str>,
    //     endpoint: Box<str>,
    // },
}

impl ProtocolConfig {
    #[allow(dead_code)]
    pub fn is_secure(&self) -> bool {
        match self {
            ProtocolConfig::Udp => false,
            ProtocolConfig::Tcp => false,
            #[cfg(feature = "tls")]
            ProtocolConfig::Tls { .. } => true,
        }
    }
}

impl cmp::PartialEq for ProtocolConfig {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl cmp::Eq for ProtocolConfig {}

impl cmp::Ord for ProtocolConfig {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        use ProtocolConfig::*;
        #[allow(unreachable_patterns)]
        match (self, other) {
            (Udp, Udp) => cmp::Ordering::Equal,
            (Udp, _) => cmp::Ordering::Greater,
            (_, Udp) => cmp::Ordering::Less,
            (Tcp, Tcp) => cmp::Ordering::Equal,
            (Tcp, _) => cmp::Ordering::Greater,
            (_, Tcp) => cmp::Ordering::Less,
            #[cfg(feature = "tls")]
            (Tls { .. }, Tls { .. }) => cmp::Ordering::Equal,
        }
    }
}

impl cmp::PartialOrd for ProtocolConfig {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct SecureProtocol(ProtocolConfig);

impl From<ProtocolConfig> for SecureProtocol {
    fn from(value: ProtocolConfig) -> Self {
        SecureProtocol(value)
    }
}

impl From<SecureProtocol> for ProtocolConfig {
    fn from(value: SecureProtocol) -> Self {
        value.0
    }
}
