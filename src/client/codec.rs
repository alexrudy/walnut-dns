use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use chateau::client::conn::protocol::framed::Tagged;
use hickory_proto::{
    ProtoError,
    op::Message,
    serialize::binary::{BinDecodable, BinEncodable},
    xfer::{DnsRequest, DnsResponse},
};

use crate::codec::{CodecError, DnsMessage};

use super::DnsClientError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedMessage(Message);

impl Tagged for TaggedMessage {
    type Tag = u16;

    fn tag(&self) -> Self::Tag {
        self.0.id()
    }
}

impl From<DnsRequest> for TaggedMessage {
    fn from(request: DnsRequest) -> Self {
        let (message, _) = request.into_parts();
        message.into()
    }
}

impl TryFrom<TaggedMessage> for DnsResponse {
    type Error = ProtoError;

    fn try_from(message: TaggedMessage) -> Result<Self, Self::Error> {
        DnsResponse::from_message(message.into())
    }
}

impl From<TaggedMessage> for Message {
    fn from(tagged: TaggedMessage) -> Self {
        tagged.0
    }
}

impl From<Message> for TaggedMessage {
    fn from(message: Message) -> Self {
        TaggedMessage(message)
    }
}

impl Deref for TaggedMessage {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TaggedMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DnsMessage for TaggedMessage {
    fn header(&self) -> &hickory_proto::op::Header {
        self.0.header()
    }

    fn extensions(&self) -> Option<&hickory_proto::op::Edns> {
        self.0.extensions().as_ref()
    }
}

impl BinEncodable for TaggedMessage {
    fn emit(
        &self,
        encoder: &mut hickory_proto::serialize::binary::BinEncoder<'_>,
    ) -> Result<(), ProtoError> {
        self.0.emit(encoder)
    }
}

impl<'a> BinDecodable<'a> for TaggedMessage {
    fn read(
        decoder: &mut hickory_proto::serialize::binary::BinDecoder<'a>,
    ) -> Result<Self, ProtoError> {
        Message::read(decoder).map(TaggedMessage)
    }
}

/// A layer which converts requests and responses to [`DnsCodecItem`]
/// for inner services.
///
/// This is designed to be paired with [`CodecStreamAdapter`] which wraps
/// a Framed protocol codec so that it accepts and returns [`DnsCodecItem`]
/// instead of the inner types.
#[derive(Clone, Default)]
pub struct DnsCodecLayer {
    _priv: (),
}

impl fmt::Debug for DnsCodecLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCodecLayer").finish()
    }
}

impl DnsCodecLayer {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> tower::Layer<S> for DnsCodecLayer {
    type Service = DnsCodecService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsCodecService::new(inner)
    }
}

/// A service which converts requests and responses to [`DnsCodecItem`]
/// for inner services.
///
/// This is designed to be paired with [`CodecStreamAdapter`] which wraps
/// a Framed protocol codec so that it accepts and returns [`DnsCodecItem`]
/// instead of the inner types.
#[derive(Debug, Clone)]
pub struct DnsCodecService<S> {
    inner: S,
}

impl<S> DnsCodecService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> tower::Service<(DnsRequest, SocketAddr)> for DnsCodecService<S>
where
    S: tower::Service<
            (TaggedMessage, SocketAddr),
            Response = (TaggedMessage, SocketAddr),
            Error = CodecError,
        >,
{
    type Response = (DnsResponse, SocketAddr);

    type Error = DnsClientError;

    type Future = DnsCodecFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, (req, address): (DnsRequest, SocketAddr)) -> Self::Future {
        let future = self.inner.call((req.into(), address));
        DnsCodecFuture { future }
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct DnsCodecFuture<F> {
    #[pin]
    future: F,
}

impl<F> Future for DnsCodecFuture<F>
where
    F: Future<Output = Result<(TaggedMessage, SocketAddr), CodecError>>,
{
    type Output = Result<(DnsResponse, SocketAddr), DnsClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(self.project().future.poll(cx)) {
            Ok((message, address)) => Poll::Ready(
                DnsResponse::try_from(message)
                    .map(|response| (response, address))
                    .map_err(Into::into),
            ),
            Err(CodecError::DropMessage(proto_error, _))
            | Err(CodecError::Protocol(proto_error)) => {
                Poll::Ready(Err(DnsClientError::DnsProtocol(proto_error)))
            }
            Err(CodecError::FailedMessage(header, response_code)) => {
                Poll::Ready(Err(DnsClientError::Response(header, response_code)))
            }
            Err(CodecError::IO(_)) => Poll::Ready(Err(DnsClientError::Closed)),
        }
    }
}
