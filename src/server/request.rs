use std::net::SocketAddr;

use hickory_proto::xfer::{Protocol, SerialMessage};
pub use hickory_server::server::Request;

pub struct SerializedRequest {
    inner: SerialMessage,
    protocol: Protocol,
}

impl SerializedRequest {
    pub fn new(inner: SerialMessage, protocol: Protocol) -> Self {
        Self { inner, protocol }
    }

    pub fn into_parts(self) -> (SerialMessage, Protocol) {
        (self.inner, self.protocol)
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn bytes(&self) -> &[u8] {
        self.inner.bytes()
    }

    pub fn addr(&self) -> SocketAddr {
        self.inner.addr()
    }
}
