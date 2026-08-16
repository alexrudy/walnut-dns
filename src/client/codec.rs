use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use chateau::client::conn::protocol::framed::Tagged;
use hickory_proto::{
    ProtoError,
    serialize::binary::{BinDecodable, BinEncodable},
};

use crate::codec::{CodecError, DnsMessage};
use crate::messages::{DnsRequest, DnsRequestOptions, DnsResponse, Message};

use super::DnsClientError;

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
