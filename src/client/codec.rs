use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};

use chateau::client::conn::protocol::framed::Tagged;
use futures::{Sink, Stream};
use hickory_proto::{
    op::Message,
    xfer::{DnsRequest, DnsResponse},
};

use crate::codec::{CodecError, MessageDecoded};

use super::DNSClientError;

pub struct DnsCodecItem {
    message: Message,
    address: SocketAddr,
}

impl Tagged for DnsCodecItem {
    type Tag = u16;
    fn tag(&self) -> Self::Tag {
        self.message.id()
    }
}

pub struct DnsCodecLayer {
    _priv: (),
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
    S: tower::Service<DnsCodecItem, Response = DnsCodecItem, Error = CodecError>,
{
    type Response = (DnsResponse, SocketAddr);

    type Error = DNSClientError;

    type Future = DnsCodecFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, (req, address): (DnsRequest, SocketAddr)) -> Self::Future {
        let (message, _) = req.into_parts();
        let future = self.inner.call(DnsCodecItem { message, address });
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
    F: Future<Output = Result<DnsCodecItem, CodecError>>,
{
    type Output = Result<(DnsResponse, SocketAddr), DNSClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(self.project().future.poll(cx)) {
            Ok(DnsCodecItem { message, address }) => Poll::Ready(
                DnsResponse::from_message(message)
                    .map(|response| (response, address))
                    .map_err(Into::into),
            ),
            Err(CodecError::DropMessage(proto_error)) => {
                Poll::Ready(Err(DNSClientError::Protocol(proto_error)))
            }
            Err(CodecError::FailedMessage(header, response_code)) => {
                Poll::Ready(Err(DNSClientError::Response(header, response_code)))
            }
            Err(CodecError::IO(_)) => Poll::Ready(Err(DNSClientError::Closed)),
        }
    }
}

#[derive(Debug, Clone)]
#[pin_project::pin_project]
pub struct CodecStreamAdapter<C> {
    #[pin]
    framed: C,
}

impl<C> CodecStreamAdapter<C> {
    pub fn new(framed: C) -> Self {
        Self { framed }
    }
}

impl<C> Sink<DnsCodecItem> for CodecStreamAdapter<C>
where
    C: Sink<(Message, SocketAddr), Error = CodecError>,
{
    type Error = CodecError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: DnsCodecItem) -> Result<(), Self::Error> {
        let DnsCodecItem { message, address } = item;
        self.project().framed.start_send((message, address))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_close(cx)
    }
}

impl<C> Stream for CodecStreamAdapter<C>
where
    C: Stream<Item = Result<(MessageDecoded<Message>, SocketAddr), CodecError>>
        + Sink<(Message, SocketAddr)>,
{
    type Item = Result<DnsCodecItem, CodecError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().framed.poll_next(cx).map(|item| {
            item.map(|result| match result {
                Ok((MessageDecoded::Message(message), address)) => {
                    Ok(DnsCodecItem { message, address })
                }
                Ok((MessageDecoded::Failed(hdr, code), _)) => {
                    Err(CodecError::FailedMessage(hdr, code))
                }
                Err(error) => Err(error),
            })
        })
    }
}
