use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use chateau::services::SharedService;
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Header, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use pin_project::pin_project;
use serde::Deserialize;
use tower::ServiceExt;

use crate::cache::{DnsCache, DnsCacheService};
use crate::codec::CodecError;
use crate::rr::RecordSet;

pub use self::codec::{DnsCodecLayer, DnsCodecService};
#[cfg(feature = "h2")]
pub use self::http::{DnsOverHttp, DnsOverHttpLayer, DnsOverHttpsFuture};
pub use self::messages::{DnsRequestLayer, DnsRequestMiddleware};
use self::nameserver::{NameServerConnection, NameserverConfig, NameserverPool};

mod codec;
mod connection;
#[cfg(feature = "h2")]
mod http;
mod messages;
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

    pub fn lookup(&self, mut query: Query, options: DnsRequestOptions) -> ClientResponseFuture {
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
        ClientResponseFuture(self.inner.clone().oneshot(request))
    }

    pub fn notify<R>(
        &self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
        rrset: Option<R>,
        options: DnsRequestOptions,
    ) -> ClientResponseFuture
    where
        R: Into<RecordSet>,
    {
        use rand::prelude::*;

        // build the message
        let mut rng = rand::rng();
        let mut message = Message::new();
        message.set_id(rng.random());
        message
            // 3.3. NOTIFY is similar to QUERY in that it has a request message with
            // the header QR flag "clear" and a response message with QR "set".  The
            // response message contains no useful information, but its reception by
            // the Primary is an indication that the Secondary has received the NOTIFY
            // and that the Primary Zone Server can remove the Secondary from any retry queue for
            // this NOTIFY event.
            .set_op_code(OpCode::Notify);

        // Extended dns
        if options.use_edns {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(self.config.max_payload_len)
                .set_version(0);
        }

        // add the query
        let mut query: Query = Query::new();
        query
            .set_name(name)
            .set_query_class(query_class)
            .set_query_type(query_type);
        message.add_query(query);

        // add the notify message, see https://tools.ietf.org/html/rfc1996, section 3.7
        if let Some(rrset) = rrset {
            message.add_answers(rrset.into().into_hickory_iter());
        }

        let request = DnsRequest::new(message, options);
        ClientResponseFuture(self.inner.clone().oneshot(request))
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

#[pin_project]
pub struct ClientResponseFuture(#[pin] tower::util::Oneshot<DnsService, DnsRequest>);

impl fmt::Debug for ClientResponseFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientResponseFuture").finish()
    }
}

impl Future for ClientResponseFuture {
    type Output = Result<DnsResponse, DnsClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().0.poll(cx)
    }
}
