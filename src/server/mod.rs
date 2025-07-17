use chateau::server::{NeedsAcceptor, NeedsProtocol};
use chateau::stream::udp::UdpListener;
use chateau::{rt::TokioExecutor, server::Server};
use hickory_proto::xfer::SerialMessage;
use tokio::net::UdpSocket;
use tower::Layer;
use tower::make::Shared;

use crate::Catalog;
use crate::services::serialize::{DNSEncoderDecoder, DNSEncoderDecoderLayer};

use self::udp::UdpProtocol;

const DEFAULT_RECV_BUFFER_SIZE: usize = 4096;
const DEFAULT_SEND_QUEUE_SIZE: usize = 2048;

pub mod request;
pub mod response;
pub mod udp;

pub fn server<A>(
    catalog: Catalog<A>,
) -> Server<
    NeedsAcceptor,
    NeedsProtocol,
    Shared<DNSEncoderDecoder<Catalog<A>>>,
    SerialMessage,
    TokioExecutor,
> {
    Server::builder()
        .with_shared_service(DNSEncoderDecoderLayer::new().layer(catalog))
        .with_tokio()
}

pub trait UdpServerExt<S, E> {
    fn with_default_udp(
        self,
        socket: UdpSocket,
    ) -> Server<UdpListener, UdpProtocol, S, SerialMessage, E>;
}

impl<S, E> UdpServerExt<S, E> for Server<NeedsAcceptor, NeedsProtocol, S, SerialMessage, E> {
    fn with_default_udp(
        self,
        socket: UdpSocket,
    ) -> Server<UdpListener, UdpProtocol, S, SerialMessage, E> {
        self.with_protocol(UdpProtocol::default())
            .with_acceptor(UdpListener::new(
                socket,
                DEFAULT_RECV_BUFFER_SIZE,
                DEFAULT_SEND_QUEUE_SIZE,
            ))
    }
}
