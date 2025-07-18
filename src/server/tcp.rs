//! TCP Protocol for DNS

use chateau::server::Protocol;
use chateau::stream::tcp::TcpStream;
use hickory_proto::op::Message;
use hickory_server::server::Request;

use crate::error::HickoryError;

use super::connection::{DNSConnection, DNSFramedStream};

#[derive(Debug, Default)]
pub struct DnsOverTcp {
    _priv: (),
}

impl DnsOverTcp {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> Protocol<S, TcpStream, Request> for DnsOverTcp
where
    S: tower::Service<Request, Response = Message, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = Message;
    type Error = HickoryError;

    type Connection = DNSConnection<S, DNSFramedStream<TcpStream>>;

    fn serve_connection(&self, stream: TcpStream, service: S) -> Self::Connection {
        DNSConnection::streamed(service, stream, hickory_proto::xfer::Protocol::Tcp)
    }
}
