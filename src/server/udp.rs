use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use chateau::{
    server::{Connection, Protocol},
    stream::udp::{UdpConnection, UdpResponder},
};
use hickory_proto::xfer::SerialMessage;

use crate::error::HickoryError;

use super::request::SerializedRequest;

#[derive(Debug, Clone, Default)]
pub struct UdpProtocol {
    _priv: (),
}

impl UdpProtocol {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> Protocol<S, UdpConnection, SerializedRequest> for UdpProtocol
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError> + 'static,
{
    type Response = SerialMessage;

    type Error = HickoryError;

    type Connection = DnsUdpResponder<S>;

    fn serve_connection(&self, stream: UdpConnection, service: S) -> Self::Connection {
        let (msg, responder) = stream.into_parts();
        let (data, addr) = msg.into_parts();
        let smsg = SerialMessage::from_parts(data.into(), addr);
        DnsUdpResponder::new(service, smsg, responder)
    }
}

#[pin_project::pin_project]
pub struct DnsUdpResponder<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    cancelled: bool,

    #[pin]
    oneshot: tower::util::Oneshot<S, SerializedRequest>,

    responder: Option<UdpResponder>,
}

impl<S> DnsUdpResponder<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    pub fn new(service: S, msg: SerialMessage, responder: UdpResponder) -> Self {
        Self {
            cancelled: false,
            oneshot: tower::util::Oneshot::new(
                service,
                SerializedRequest::new(msg, hickory_proto::xfer::Protocol::Udp),
            ),
            responder: Some(responder),
        }
    }
}

impl<S> Future for DnsUdpResponder<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    type Output = Result<(), HickoryError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cancelled {
            return Poll::Ready(Err(HickoryError::Closed));
        }
        let this = self.project();
        match ready!(this.oneshot.poll(cx)) {
            Ok(msg) => {
                this.responder
                    .take()
                    .expect("Connection polled after completion")
                    .send(msg.into_parts());
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<S> Connection for DnsUdpResponder<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    fn graceful_shutdown(self: Pin<&mut Self>) {
        *self.project().cancelled = true;
    }
}
