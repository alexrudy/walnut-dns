use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use chateau::server::{Connection, Protocol};
use chateau::stream::udp::UdpConnection;
use hickory_proto::xfer::SerialMessage;

use crate::error::HickoryError;

use super::request::SerializedRequest;

#[derive(Debug, Clone, Default)]
pub struct DnsOverUdp {
    _priv: (),
}

impl DnsOverUdp {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> Protocol<S, UdpConnection, SerializedRequest> for DnsOverUdp
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError> + 'static,
{
    type Response = SerialMessage;

    type Error = HickoryError;

    type Connection = DnsOverUdpConnection<S>;

    fn serve_connection(&self, mut stream: UdpConnection, service: S) -> Self::Connection {
        let msg = stream.take().unwrap();
        let (data, addr) = msg.into_parts();
        let smsg = SerialMessage::from_parts(data.into(), addr);
        DnsOverUdpConnection::new(service, smsg, stream)
    }
}

#[pin_project::pin_project(project=ResponseStateProj)]
enum ResponseState<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    Oneshot(#[pin] tower::util::Oneshot<S, SerializedRequest>),
    Sending { data: Bytes, addr: SocketAddr },
    Idle,
}

#[pin_project::pin_project]
pub struct DnsOverUdpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    cancelled: bool,

    #[pin]
    state: ResponseState<S>,

    responder: UdpConnection,
}

impl<S> DnsOverUdpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    pub fn new(service: S, msg: SerialMessage, responder: UdpConnection) -> Self {
        Self {
            cancelled: false,
            state: ResponseState::Oneshot(tower::util::Oneshot::new(
                service,
                SerializedRequest::new(msg, hickory_proto::xfer::Protocol::Udp),
            )),
            responder,
        }
    }
}

impl<S> Future for DnsOverUdpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    type Output = Result<(), HickoryError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cancelled {
            return Poll::Ready(Err(HickoryError::Closed));
        }
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                ResponseStateProj::Oneshot(future) => match ready!(future.poll(cx)) {
                    Ok(msg) => {
                        let (data, addr) = msg.into_parts();
                        this.state.set(ResponseState::Sending {
                            data: Bytes::from(data),
                            addr,
                        });
                    }
                    Err(error) => {
                        return Poll::Ready(Err(error));
                    }
                },
                ResponseStateProj::Sending { data, addr } => {
                    match ready!(this.responder.socket().poll_send_to(cx, &data, *addr)) {
                        Ok(n) => {
                            data.advance(n);
                            if data.is_empty() {
                                this.state.set(ResponseState::Idle);
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Err(error) => return Poll::Ready(Err(HickoryError::Send(error))),
                    }
                }
                ResponseStateProj::Idle => return Poll::Ready(Err(HickoryError::Closed)),
            }
        }
    }
}

impl<S> Connection for DnsOverUdpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    fn graceful_shutdown(self: Pin<&mut Self>) {
        *self.project().cancelled = true;
    }
}
