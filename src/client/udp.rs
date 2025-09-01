use std::{
    future::Ready,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use crate::codec::DNSCodec;
use chateau::{
    client::conn::{
        Connection,
        protocol::framed::{FramedConnection, ResponseFuture},
    },
    info::HasConnectionInfo,
};
use futures::future::BoxFuture;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::udp::UdpFramed;

use super::{
    DNSClientError,
    codec::TaggedMessage,
    nameserver::{ConnectionStatus, NameserverConnection},
};

#[derive(Clone)]
enum Bind {
    Address(SocketAddr),
    Socket(Arc<UdpSocket>),
}

#[derive(Clone)]
pub struct DnsUdpTransport {
    bind: Arc<Mutex<Bind>>,
}

impl DnsUdpTransport {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind: Arc::new(Mutex::new(Bind::Address(bind))),
        }
    }
}

impl tower::Service<SocketAddr> for DnsUdpTransport {
    type Response = DnsUdpAddressed;

    type Error = io::Error;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: SocketAddr) -> Self::Future {
        let bind = self.bind.clone();
        Box::pin(async move {
            let mut inner = bind.lock().await;
            let socket = match &*inner {
                Bind::Address(socket_addr) => {
                    let udp_socket = Arc::new(UdpSocket::bind(*socket_addr).await?);
                    *inner = Bind::Socket(udp_socket.clone());
                    udp_socket
                }
                Bind::Socket(udp_socket) => udp_socket.clone(),
            };
            Ok(DnsUdpAddressed {
                socket,
                destination: req,
            })
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsUdpAddressed {
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
}

impl HasConnectionInfo for DnsUdpAddressed {
    type Addr = SocketAddr;

    fn info(&self) -> chateau::info::ConnectionInfo<Self::Addr> {
        chateau::info::ConnectionInfo {
            local_addr: self.socket.local_addr().unwrap(),
            remote_addr: self.destination,
        }
    }
}

#[derive(Clone)]
pub struct DnsUdpProtocol {
    codec: DNSCodec<TaggedMessage, TaggedMessage>,
    spawn: bool,
}

impl DnsUdpProtocol {
    pub fn new(codec: DNSCodec<TaggedMessage, TaggedMessage>, spawn: bool) -> Self {
        Self { codec, spawn }
    }
}

impl tower::Service<DnsUdpAddressed> for DnsUdpProtocol {
    type Response = DnsUdpConnection;

    type Error = std::io::Error;

    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: DnsUdpAddressed) -> Self::Future {
        let connection = FramedConnection::new(UdpFramed::new(req.socket, self.codec.clone()));
        if self.spawn {
            let driver = connection.driver();
            tokio::task::spawn(driver.into_future());
        }
        std::future::ready(Ok(DnsUdpConnection {
            connection,
            destination: req.destination,
        }))
    }
}

type FramedDNSConnection = FramedConnection<
    UdpFramed<DNSCodec<TaggedMessage, TaggedMessage>, Arc<UdpSocket>>,
    (TaggedMessage, SocketAddr),
    (TaggedMessage, SocketAddr),
>;

pub struct DnsUdpConnection {
    connection: FramedDNSConnection,
    destination: SocketAddr,
}

impl tower::Service<TaggedMessage> for DnsUdpConnection {
    type Response = TaggedMessage;

    type Error = DNSClientError;

    type Future = DNSUdpConnectionFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        tower::Service::poll_ready(&mut self.connection, cx)
            .map_err(|error| DNSClientError::Protocol(error.into()))
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        DNSUdpConnectionFuture(self.connection.send((req, self.destination)))
    }
}

impl Connection<TaggedMessage> for DnsUdpConnection {
    type Response = TaggedMessage;

    type Error = DNSClientError;

    type Future = DNSUdpConnectionFuture;

    fn send_request(&mut self, request: TaggedMessage) -> Self::Future {
        DNSUdpConnectionFuture(self.connection.send((request, self.destination)))
    }
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connection
            .poll_ready(cx)
            .map_err(|error| DNSClientError::Protocol(error.into()))
    }
}

impl NameserverConnection for DnsUdpConnection {
    fn status(&self) -> ConnectionStatus {
        ConnectionStatus::Connected
    }

    fn protocol(&self) -> hickory_proto::xfer::Protocol {
        hickory_proto::xfer::Protocol::Udp
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct DNSUdpConnectionFuture(
    #[pin]
    ResponseFuture<
        UdpFramed<DNSCodec<TaggedMessage, TaggedMessage>, Arc<UdpSocket>>,
        (TaggedMessage, SocketAddr),
        (TaggedMessage, SocketAddr),
    >,
);

impl Future for DNSUdpConnectionFuture {
    type Output = Result<TaggedMessage, DNSClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(self.project().0.poll(cx)) {
            Ok((response, _)) => Poll::Ready(Ok(response)),
            Err(error) => Poll::Ready(Err(DNSClientError::Protocol(error.into()))),
        }
    }
}
