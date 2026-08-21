use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use chateau::services::SharedService;
use hickory_proto::op::{Edns, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use pin_project::pin_project;
use serde::Deserialize;
use tower::ServiceExt;

use crate::cache::{DnsCache, DnsCacheService};
use crate::messages::{DnsRequest, DnsRequestOptions, DnsResponse, Message};
use walnut_proto::rr::RecordSet;

pub use self::error::DnsClientError;
#[cfg(feature = "h2")]
pub use self::http::{DnsOverHttp, DnsOverHttpLayer, DnsOverHttpsFuture};
pub use self::messages::{DnsRequestLayer, DnsRequestMiddleware, ResponseAdapter};
use self::nameserver::{Nameserver, NameserverConfig, Pool, PoolConfig};
pub use self::udp::{
    DnsUdpConnection, DnsUdpConnectionConfiguration, DnsUdpProtocol, DnsUdpTransport,
};

mod error;
#[cfg(feature = "h2")]
mod http;
mod messages;
pub mod nameserver;
mod udp;

pub(crate) type DnsService =
    chateau::services::SharedService<DnsRequest, DnsResponse, DnsClientError>;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfiguration {
    #[serde(default)]
    max_payload_len: u16,
    nameserver: Vec<NameserverConfig>,
    #[serde(default)]
    pool: PoolConfig,
    #[serde(default)]
    bind: Option<IpAddr>,
}

impl From<NameserverConfig> for ClientConfiguration {
    fn from(config: NameserverConfig) -> Self {
        ClientConfiguration {
            nameserver: vec![config],
            ..Default::default()
        }
    }
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        ClientConfiguration {
            max_payload_len: 2048,
            nameserver: Vec::new(),
            pool: PoolConfig::default(),
            bind: None,
        }
    }
}

#[derive(Debug, Clone)]
struct ClientSettings {
    max_payload_len: u16,
}

impl From<ClientConfiguration> for ClientSettings {
    fn from(value: ClientConfiguration) -> Self {
        ClientSettings {
            max_payload_len: value.max_payload_len,
        }
    }
}

/// A DNS Client
#[derive(Debug, Clone)]
pub struct Client {
    inner: DnsService,
    config: Arc<ClientSettings>,
}

impl Client {
    pub fn new(configuration: ClientConfiguration) -> Client {
        let config = Arc::new(ClientSettings {
            max_payload_len: configuration.max_payload_len,
        });
        let svc = Pool::new(
            configuration
                .nameserver
                .into_iter()
                .map(|ns| Nameserver::new(ns, configuration.bind))
                .collect(),
            configuration.pool,
        );
        Client {
            inner: SharedService::new(DnsRequestMiddleware::new(svc)),
            config,
        }
    }

    pub fn with_cache<C>(self, cache: C) -> Self
    where
        C: DnsCache + Clone + Send + Sync + 'static,
    {
        Self {
            inner: SharedService::new(DnsCacheService::new(self.inner, cache)),
            config: self.config,
        }
    }

    pub fn from_service(service: DnsService, max_payload_len: u16) -> Self {
        Self {
            inner: service,
            config: Arc::new(ClientSettings { max_payload_len }),
        }
    }

    /// Send a message, with options. We assume that the options have already been applied to the message.
    pub fn send(&self, message: Message, options: DnsRequestOptions) -> ClientResponseFuture {
        let request = DnsRequest::new(message, options);
        ClientResponseFuture(self.inner.clone().oneshot(request))
    }

    #[tracing::instrument(skip_all, fields(dns.label=%query.name, dns.type=%query.query_type, dns.id=tracing::field::Empty))]
    pub fn lookup(&self, mut query: Query, options: DnsRequestOptions) -> ClientResponseFuture {
        use rand::prelude::*;

        let mut rng = rand::rng();
        let mut message = Message::new();
        message.set_id(rng.random());
        tracing::Span::current().record("dns.id", tracing::field::display(message.id()));

        let mut original_query = None;

        if options.case_randomization {
            tracing::trace!("randomizing label case");
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
            message.add_answers(rrset.into());
        }

        let request = DnsRequest::new(message, options);
        ClientResponseFuture(self.inner.clone().oneshot(request))
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

#[derive(Debug, Clone)]
pub struct QuickClient(pub Client);

impl From<Client> for QuickClient {
    fn from(client: Client) -> Self {
        Self(client)
    }
}

impl QuickClient {
    pub async fn query(
        &self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> Result<DnsResponse, DnsClientError> {
        let mut query = Query::query(name, query_type);
        query.set_query_class(query_class);
        self.0.lookup(query, Default::default()).await
    }
}
