use bytes::{Buf, BufMut};
use hickory_proto::{
    ProtoError,
    op::Message,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable as _, BinEncoder},
    xfer::Protocol,
};
use hickory_server::authority::MessageRequest;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{error, trace};

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
}

impl Decoder for DNSCodec {
    type Item = MessageRequest;
    type Error = ProtoError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            // Not enough data to read length marker
            return Ok(None);
        }

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&src[..2]);
        let length = u16::from_be_bytes(length_bytes) as usize;
        src.advance(2);

        if src.len() < length {
            src.reserve(length - src.len());
            // Not enough data to read message
            return Ok(None);
        }

        let mut decoder = BinDecoder::new(&src);
        Self::Item::read(&mut decoder).map(Some)
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

        let n = buffer.len();
        if dst.len() < (n + 2) {
            let additional = (n + 2) - dst.len();
            dst.reserve(additional);
        }
        dst.put(u16::to_be_bytes(n as u16).as_slice());
        dst.put(&*buffer);

        Ok(())
    }
}
