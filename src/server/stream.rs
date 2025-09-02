//! TCP Protocol for DNS

use std::marker::PhantomData;
use std::net::SocketAddr;

use chateau::{info::HasConnectionInfo, server::Protocol};
use hickory_proto::op::Message;
use hickory_server::server::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::HickoryError;

use super::connection::{DnsConnection, DnsFramedStream};

#[derive(Debug, Default)]
pub struct DnsOverStream<IO> {
    protocol: hickory_proto::xfer::Protocol,
    stream: PhantomData<fn(IO)>,
}

impl<IO> DnsOverStream<IO> {
    pub fn tcp() -> Self {
        Self {
            protocol: hickory_proto::xfer::Protocol::Tcp,
            stream: PhantomData,
        }
    }

    #[cfg(feature = "tls")]
    pub fn tls() -> Self {
        Self {
            protocol: hickory_proto::xfer::Protocol::Tls,
            stream: PhantomData,
        }
    }
}

impl<S, IO> Protocol<S, IO, Request> for DnsOverStream<IO>
where
    IO: AsyncRead + AsyncWrite + HasConnectionInfo + 'static,
    IO::Addr: Into<SocketAddr> + Clone,
    S: tower::Service<Request, Response = Message, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = Message;
    type Error = HickoryError;

    type Connection = DnsConnection<S, DnsFramedStream<IO>>;

    fn serve_connection(&self, stream: IO, service: S) -> Self::Connection {
        DnsConnection::streamed(service, stream, self.protocol)
    }
}
