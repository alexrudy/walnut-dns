use std::future::ready;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};

use chateau::client::codec::{FramedProtocol, Tagged};
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt, TryStreamExt, future::BoxFuture};
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Header, Message, Query, ResponseCode};
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tower::ServiceExt;

use crate::codec::{CodecError, DNSCodec};

struct DnsCodecItem {
    message: Message,
    address: SocketAddr,
}

impl Tagged for DnsCodecItem {
    type Tag = u16;
    fn tag(&self) -> Self::Tag {
        self.message.id()
    }
}

type DNSService = chateau::services::SharedService<DnsRequest, DnsResponse, DNSClientError>;

pub async fn client(address: SocketAddr) -> Result<DNSService, io::Error> {
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let socket = UdpSocket::bind(bind).await?;
    let codec = DNSCodec::new_for_protocol(hickory_proto::xfer::Protocol::Udp);
    let (sink, stream) = UdpFramed::new(socket, codec).split();
    let sink = sink.with(|req: DnsCodecItem| ready(Ok((req.message, req.address))));
    let stream = stream
        .map(|res| {
            res.and_then(|(md, addr)| match md {
                crate::codec::MessageDecoded::Message(message) => Ok((message, addr)),
                crate::codec::MessageDecoded::Failed(header, response_code) => {
                    Err(CodecError::FailedMessage(header, response_code))
                }
            })
        })
        .map_ok(|(message, address)| DnsCodecItem { message, address });

    let joined = Joined::new(stream, sink);
    let protocol = FramedProtocol::new(joined);

    tokio::spawn(protocol.driver());

    Ok(tower::ServiceBuilder::new()
        .layer(chateau::services::SharedService::layer())
        .layer_fn(|svc| UdpAddressService {
            inner: svc,
            address,
        })
        .service(protocol))
}

#[pin_project::pin_project]
#[derive(Debug, Clone)]
pub struct Joined<St, Si> {
    #[pin]
    stream: St,
    #[pin]
    sink: Si,
}

impl<St, Si> Joined<St, Si> {
    pub fn new(stream: St, sink: Si) -> Self {
        Self { stream, sink }
    }
}

impl<St, Si, I> Sink<I> for Joined<St, Si>
where
    Si: Sink<I>,
{
    type Error = Si::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        self.project().sink.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close(cx)
    }
}

impl<St, Si> Stream for Joined<St, Si>
where
    St: Stream,
{
    type Item = St::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx)
    }
}

#[derive(Debug, Clone)]
pub struct UdpAddressService<S> {
    inner: S,
    address: SocketAddr,
}

impl<S> tower::Service<DnsRequest> for UdpAddressService<S>
where
    S: tower::Service<DnsCodecItem, Response = DnsCodecItem, Error = CodecError>,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;

    type Error = DNSClientError;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let (message, _) = req.into_parts();
        let future = self.inner.call(DnsCodecItem {
            message,
            address: self.address,
        });
        Box::pin(async move {
            future
                .map(|r| {
                    r.and_then(|DnsCodecItem { message, .. }| {
                        DnsResponse::from_message(message).map_err(CodecError::DropMessage)
                    })
                })
                .await
                .map_err(Into::into)
        })
    }
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
