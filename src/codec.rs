use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use hickory_proto::{
    ProtoError,
    op::{Header, Message, ResponseCode},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable as _, BinEncoder},
    xfer::Protocol,
};
use hickory_server::{authority::MessageRequest, server::Request};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error, trace};

use crate::server::response::{encode_fallback_servfail_response, max_size_for_response};

/// The wire codec for standard DNS messages defined in RFC 1035.
#[derive(Debug, Clone)]
pub struct DNSCodec {
    protocol: Protocol,
}

impl DNSCodec {
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn parse_length(&mut self, src: &mut bytes::BytesMut) -> Option<usize> {
        if src.len() < 2 {
            // Not enough data to read length marker
            return None;
        }

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&src[..2]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if src.len() < (length + 2) {
            src.reserve((length + 2) - src.len());
            // Not enough data to read entire message
            return None;
        }
        trace!("decode len={length}");
        src.advance(2);
        Some(length)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("Failed to decode message, dropping")]
    DropMessage(#[source] ProtoError),

    #[error(transparent)]
    IO(#[from] std::io::Error),
}

/// Request decoded from a codec
///
/// The Failed condition indicates that the codec errored, but was still able
/// to process enough information to send a response.
#[derive(Debug)]
pub enum CodecRequest {
    Message(MessageRequest),
    Failed(Header, ResponseCode),
}

impl CodecRequest {
    pub fn with_address(self, addr: SocketAddr, protocol: Protocol) -> DNSRequest {
        match self {
            CodecRequest::Message(message_request) => {
                DNSRequest::Message(Request::new(message_request, addr, protocol))
            }
            CodecRequest::Failed(header, response_code) => DNSRequest::Failed((
                Message::error_msg(header.id(), header.op_code(), response_code),
                addr,
            )),
        }
    }
}

/// A Request parsed from the codec, with address and protocol information
/// attached. This must be done after the codec, since the codec is agnostic
/// to the underlying protocol.
#[derive(Debug)]
pub enum DNSRequest {
    Message(Request),
    Failed((Message, SocketAddr)),
}

impl Decoder for DNSCodec {
    type Item = CodecRequest;
    type Error = CodecError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let length = match self.protocol {
            #[cfg(feature = "tls")]
            Protocol::Tls => match self.parse_length(src) {
                Some(length) => length,
                None => return Ok(None),
            },
            Protocol::Tcp => match self.parse_length(src) {
                Some(length) => length,
                None => return Ok(None),
            },
            Protocol::Udp => {
                trace!("decode udp, buffer={}", src.len());
                src.len()
            }
            p => {
                unimplemented!("Unknown protocol: {p}");
            }
        };

        if src.len() == 0 {
            // No data to decode.
            return Ok(None);
        }

        let mut decoder = BinDecoder::new(&src);
        match MessageRequest::read(&mut decoder) {
            Ok(message) => {
                src.advance(length);
                Ok(Some(CodecRequest::Message(message)))
            }
            Err(error) => {
                // Try to just parse the header, if that fails, just drop the message.
                let mut decoder = BinDecoder::new(&src);
                match Header::read(&mut decoder) {
                    Ok(header) => {
                        debug!("Failed to parse message, sending error: {error}");
                        src.advance(length);
                        return Ok(Some(CodecRequest::Failed(header, ResponseCode::FormErr)));
                    }
                    Err(_) => {
                        error!("Failed to parse header: {error}");
                        return Err(CodecError::DropMessage(error));
                    }
                };
            }
        }
    }
}

impl Encoder<Message> for DNSCodec {
    type Error = ProtoError;

    fn encode(&mut self, response: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let id = response.header().id();
        trace!(
            id,
            response_code = %response.header().response_code(),
            "encoding response",
        );
        let mut buffer = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buffer);

            // Set an appropriate maximum on the encoder.
            let max_size = max_size_for_response(self.protocol, &response);
            trace!(
                "setting response max size: {max_size} for protocol: {:?}",
                self.protocol
            );
            encoder.set_max_size(max_size);
            response.emit(&mut encoder)
        }
        .or_else(|error| {
            error!(%error, "error encoding message, sending servfail");
            encode_fallback_servfail_response(id, &mut buffer)
        })?;

        if matches!(self.protocol, Protocol::Tcp | Protocol::Tls) {
            let n = buffer.len();
            if dst.len() < (n + 2) {
                let additional = (n + 2) - dst.len();
                dst.reserve(additional);
            }
            dst.put(u16::to_be_bytes(n as u16).as_slice());
        } else {
            let n = buffer.len();
            if dst.len() < n {
                let additional = n - dst.len();
                dst.reserve(additional);
            }
        }
        dst.put(&*buffer);
        Ok(())
    }
}
