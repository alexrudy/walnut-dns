use std::sync::Arc;

use chateau::services::SharedService;
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Header, Message, Query, ResponseCode};
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use serde::Deserialize;
use tower::ServiceExt;

use crate::cache::{DnsCache, DnsCacheService};
use crate::codec::CodecError;

pub use self::codec::{DnsCodecLayer, DnsCodecService};
pub use self::messages::{DnsRequestLayer, DnsRequestMiddleware};
use self::nameserver::{NameServerConnection, NameserverConfig, NameserverPool};

mod codec;
mod connection;
pub mod messages;
// mod http;
pub mod nameserver;
mod udp;

type DnsService = chateau::services::SharedService<DnsRequest, DnsResponse, DnsClientError>;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfiguration {
    #[serde(default)]
    max_payload_len: u16,
    nameserver: Vec<NameserverConfig>,
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        ClientConfiguration {
            max_payload_len: 2048,
            nameserver: Vec::new(),
        }
    }
}

/// A DNS Client
#[derive(Debug, Clone)]
pub struct Client {
    inner: DnsService,
    config: Arc<ClientConfiguration>,
}

impl Client {
    pub fn new(configuration: ClientConfiguration) -> Client {
        let mut connections = Vec::new();
        for ns in &configuration.nameserver {
            for connection in &ns.connections {
                connections.push(NameServerConnection::from_config(
                    ns.address,
                    connection.clone(),
                ))
            }
        }

        let svc = NameserverPool::new(connections, Default::default());
        Client {
            inner: SharedService::new(DnsRequestMiddleware::new(svc)),
            config: Arc::new(ClientConfiguration::default()),
        }
    }

    pub fn with_cache(self, cache: DnsCache) -> Self {
        Self {
            inner: SharedService::new(DnsCacheService::new(self.inner, cache)),
            config: self.config,
        }
    }

    pub fn lookup(
        &self,
        mut query: Query,
        options: DnsRequestOptions,
    ) -> tower::util::Oneshot<DnsService, DnsRequest> {
        use rand::prelude::*;

        let mut rng = rand::rng();
        let mut message = Message::new();
        message.set_id(rng.random());
        let mut original_query = None;

        if options.case_randomization {
            original_query = Some(query.clone());
            query.name.randomize_label_case();
        }

        message
            .add_query(query)
            .set_recursion_desired(options.recursion_desired);

        // Extended dns
        if options.use_edns {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(self.config.max_payload_len)
                .set_version(0)
                .set_dnssec_ok(options.edns_set_dnssec_ok);
        }

        let request = DnsRequest::new(message, options).with_original_query(original_query);
        self.inner.clone().oneshot(request)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsClientError {
    #[error("DNS Protocol: {0}")]
    DnsProtocol(#[from] ProtoError),

    #[error("Invalid response for message {}: {}", .0.id(), .1)]
    Response(Header, ResponseCode),

    #[cfg(feature = "h2")]
    #[error("Http Request Error: {0}")]
    Http(#[from] hyper::Error),

    #[error(transparent)]
    Service(Box<dyn std::error::Error + Send + Sync>),

    #[error("Transport Error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Protocol Error: {0}")]
    Protocol(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Connection closed")]
    Closed,

    #[error("Unavailalbe: {0}")]
    Unavailable(String),

    #[error("Cache: {0}")]
    Cache(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<CodecError> for DnsClientError {
    fn from(value: CodecError) -> Self {
        match value {
            CodecError::DropMessage(proto_error, _) | CodecError::Protocol(proto_error) => {
                DnsClientError::DnsProtocol(proto_error)
            }
            CodecError::FailedMessage(header, response_code) => {
                DnsClientError::Response(header, response_code)
            }
            CodecError::IO(_) => DnsClientError::Closed,
        }
    }
}
