//! TCP Protocol for DNS

use std::marker::PhantomData;
use std::net::SocketAddr;

use chateau::{info::HasConnectionInfo, server::Protocol};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::messages::{Message, Protocol as DnsProtocol};
use crate::{error::HickoryError, messages::server::Incoming};

use super::connection::{DnsConnection, DnsFramedStream};

#[derive(Debug, Default)]
pub struct DnsOverStream<IO> {
    protocol: DnsProtocol,
    stream: PhantomData<fn(IO)>,
}

impl<IO> DnsOverStream<IO> {
    pub fn tcp() -> Self {
        Self {
            protocol: DnsProtocol::Tcp,
            stream: PhantomData,
        }
    }

    #[cfg(feature = "tls")]
    pub fn tls() -> Self {
        Self {
            protocol: DnsProtocol::Tls,
            stream: PhantomData,
        }
    }
}

impl<S, IO> Protocol<S, IO, Incoming<Message>> for DnsOverStream<IO>
where
    IO: AsyncRead + AsyncWrite + HasConnectionInfo + 'static,
    IO::Addr: Into<SocketAddr> + Clone,
    S: tower::Service<Incoming<Message>, Response = Message, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = Message;
    type Error = HickoryError;

    type Connection = DnsConnection<S, DnsFramedStream<IO>>;

    fn serve_connection(&self, stream: IO, service: S) -> Self::Connection {
        DnsConnection::streamed(service, stream, self.protocol)
    }
}

pub struct DnsOverStreamUnprotected<IO> {
    inner: DnsOverStream<IO>,
}

impl<IO> DnsOverStreamUnprotected<IO> {
    pub fn tcp() -> Self {
        Self {
            inner: DnsOverStream::tcp(),
        }
    }

    #[cfg(feature = "tls")]
    pub fn tls() -> Self {
        Self {
            inner: DnsOverStream::tls(),
        }
    }
}

impl<S, IO> Protocol<S, IO, Incoming<Message>> for DnsOverStreamUnprotected<IO>
where
    IO: AsyncRead + AsyncWrite + 'static,
    S: tower::Service<Incoming<Message>, Response = Message, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = Message;
    type Error = HickoryError;

    type Connection = DnsConnection<S, DnsFramedStream<IO>>;

    fn serve_connection(&self, stream: IO, service: S) -> Self::Connection {
        DnsConnection::streamed_unprotected(service, stream, self.inner.protocol)
    }
}
