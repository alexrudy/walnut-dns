use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use chateau::client::conn::ConnectionError;
use chateau::client::conn::dns::StaticResolver;
use chateau::client::conn::protocol::framed::FramedConnection;
use chateau::services::ResolvedAddressableLayer;
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Header, Message, Query, ResponseCode};
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tower::ServiceExt;
use tracing::trace;

use crate::codec::{CodecError, DNSCodec};

use self::codec::{CodecStreamAdapter, DnsCodecLayer};

mod codec;

type DNSService = chateau::services::SharedService<DnsRequest, DnsResponse, DNSClientError>;

pub async fn client(address: SocketAddr) -> Result<DNSService, io::Error> {
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let socket = UdpSocket::bind(bind).await?;
    let codec: DNSCodec<Message> = DNSCodec::new_for_protocol(hickory_proto::xfer::Protocol::Udp);

    let protocol = FramedConnection::new(CodecStreamAdapter::new(UdpFramed::new(socket, codec)));

    let driver = protocol.driver();
    tokio::spawn(async move { driver.await });
    trace!("spawned driver");
    Ok(tower::ServiceBuilder::new()
        .layer(chateau::services::SharedService::layer())
        .map_err(|error| match error {
            ConnectionError::Resolving(e) => match e {},
            ConnectionError::Connecting(e) => match e {},
            ConnectionError::Handshaking(e) => match e {},
            ConnectionError::Service(svc) => svc,
            _ => panic!("Unprocessable"),
        })
        .layer(ResolvedAddressableLayer::new(StaticResolver::new(address)))
        .layer(DnsCodecLayer::new())
        .service(protocol))
}

#[derive(Debug, Clone)]
pub struct ClientConfiguration {
    max_payload_len: u16,
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        ClientConfiguration {
            max_payload_len: 2048,
        }
    }
}

/// A DNS Client
#[derive(Debug, Clone)]
pub struct Client {
    inner: DNSService,
    config: Arc<ClientConfiguration>,
}

impl Client {
    pub async fn new_udp_client(address: SocketAddr) -> io::Result<Client> {
        let svc = client(address).await?;
        Ok(Client {
            inner: svc,
            config: Arc::new(ClientConfiguration::default()),
        })
    }

    pub fn lookup(
        &self,
        mut query: Query,
        options: DnsRequestOptions,
    ) -> tower::util::Oneshot<DNSService, DnsRequest> {
        let mut message = Message::new();
        message.set_id(12345u16);
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
pub enum DNSClientError {
    #[error("Protocol: {0}")]
    Protocol(#[from] ProtoError),

    #[error("Invalid response for message {}: {}", .0.id(), .1)]
    Response(Header, ResponseCode),

    #[error("Connection closed")]
    Closed,
}

impl From<CodecError> for DNSClientError {
    fn from(value: CodecError) -> Self {
        match value {
            CodecError::DropMessage(proto_error) => DNSClientError::Protocol(proto_error),
            CodecError::FailedMessage(header, response_code) => {
                DNSClientError::Response(header, response_code)
            }
            CodecError::IO(_) => DNSClientError::Closed,
        }
    }
}
