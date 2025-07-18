use chateau::server::{NeedsAcceptor, NeedsProtocol};
use chateau::stream::udp::UdpListener;
use chateau::{rt::TokioExecutor, server::Server};
use tokio::net::UdpSocket;
use tower::Layer;
use tower::make::Shared;

use crate::Catalog;
use crate::services::serialize::{DNSEncoderDecoder, DNSEncoderDecoderLayer};

use self::request::SerializedRequest;
use self::udp::DnsOverUdp;

const DEFAULT_RECV_BUFFER_SIZE: usize = 4096;

pub mod connection;
pub mod request;
pub mod response;
pub mod tcp;
pub mod udp;

pub fn catalog_server<A>(
    catalog: Catalog<A>,
) -> Server<
    NeedsAcceptor,
    NeedsProtocol,
    Shared<DNSEncoderDecoder<Catalog<A>>>,
    SerializedRequest,
    TokioExecutor,
> {
    Server::builder()
        .with_shared_service(DNSEncoderDecoderLayer::new().layer(catalog))
        .with_tokio()
}

pub trait UdpServerExt<S, E>: Sized {
    fn with_default_udp(
        self,
        socket: UdpSocket,
    ) -> Server<UdpListener, DnsOverUdp, S, SerializedRequest, E> {
        self.with_udp(socket, DEFAULT_RECV_BUFFER_SIZE)
    }
    fn with_udp(
        self,
        socket: UdpSocket,
        recv_buffer_size: usize,
    ) -> Server<UdpListener, DnsOverUdp, S, SerializedRequest, E>;
}

impl<S, E> UdpServerExt<S, E> for Server<NeedsAcceptor, NeedsProtocol, S, SerializedRequest, E> {
    fn with_udp(
        self,
        socket: UdpSocket,
        recv_buffer_size: usize,
    ) -> Server<UdpListener, DnsOverUdp, S, SerializedRequest, E> {
        self.with_protocol(DnsOverUdp::default())
            .with_acceptor(UdpListener::new(socket, recv_buffer_size))
    }
}
