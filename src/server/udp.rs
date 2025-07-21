use std::borrow::Borrow;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::{fmt, io};

use chateau::server::{Accept, Protocol};
use futures::Sink;
use futures::Stream;
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_server::authority::MessageRequest;
use hickory_server::server::Request;
use tokio_util::udp::UdpFramed;
use tracing::trace;

use crate::codec::{CodecError, DNSCodec, DNSRequest};
use crate::error::HickoryError;

use super::connection::DNSConnection;

#[derive(Debug, Clone, Default)]
pub struct DnsOverUdp {
    _priv: (),
}

impl DnsOverUdp {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> Protocol<S, UdpSocket, Request> for DnsOverUdp
where
    S: tower::Service<Request, Response = Message, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = Message;

    type Error = HickoryError;

    type Connection = DNSConnection<S, DNSFramedUdp>;

    fn serve_connection(&self, stream: UdpSocket, service: S) -> Self::Connection {
        let codec = UdpFramed::new(
            stream,
            DNSCodec::new_for_protocol(hickory_proto::xfer::Protocol::Udp),
        );
        DNSConnection::new(service, DNSFramedUdp::new(codec))
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct DNSFramedUdp {
    #[pin]
    framed: UdpFramed<DNSCodec<MessageRequest>, UdpSocket>,
}

impl DNSFramedUdp {
    pub fn new(framed: UdpFramed<DNSCodec<MessageRequest>, UdpSocket>) -> Self {
        Self { framed }
    }
}

impl Sink<(Message, SocketAddr)> for DNSFramedUdp {
    type Error = ProtoError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: (Message, SocketAddr)) -> Result<(), Self::Error> {
        self.project().framed.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_close(cx)
    }
}

impl Stream for DNSFramedUdp {
    type Item = Result<DNSRequest, CodecError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().framed.poll_next(cx).map(|r| {
            r.map(|r| {
                r.map(|(msg, addr)| msg.with_address(addr, hickory_proto::xfer::Protocol::Udp))
            })
        })
    }
}

#[derive(Debug)]
pub struct UdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Borrow<tokio::net::UdpSocket> for UdpSocket {
    fn borrow(&self) -> &tokio::net::UdpSocket {
        &self.inner
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            done.send(()).ok();
        }
    }
}

pub struct UdpListener {
    socket: Arc<tokio::net::UdpSocket>,
    done: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl UdpListener {
    pub fn new(socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self { socket, done: None }
    }
}

impl From<tokio::net::UdpSocket> for UdpListener {
    fn from(value: tokio::net::UdpSocket) -> Self {
        Self::new(Arc::new(value))
    }
}

impl fmt::Debug for UdpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpListener")
            .field("socket", &*self.socket)
            .finish()
    }
}

impl Accept for UdpListener {
    type Connection = UdpSocket;

    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Connection, Self::Error>> {
        if let Some(rx) = self.done.as_mut() {
            ready!(Pin::new(rx).poll(cx));
            trace!("Last connection has closed, ready to start a new one");
        }

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.done = Some(Box::pin(async move {
            rx.await.ok();
        }));

        Poll::Ready(Ok(UdpSocket {
            inner: self.socket.clone(),
            done: Some(tx),
        }))
    }
}
