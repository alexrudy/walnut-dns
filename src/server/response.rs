use std::net::SocketAddr;

use hickory_proto::ProtoError;
use hickory_proto::op::{Header, Message, ResponseCode};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_proto::xfer::{Protocol, SerialMessage};
use tracing::{error, trace};

/// Selects an appropriate maximum serialized size for the given response.
pub(crate) fn max_size_for_response(protocol: Protocol, response: &Message) -> u16 {
    match protocol {
        Protocol::Udp => {
            // Use EDNS, if available.
            if let Some(edns) = response.extensions() {
                edns.max_payload()
            } else {
                // No EDNS, use the recommended max from RFC6891.
                hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
            }
        }
        _ => u16::MAX,
    }
}

pub(crate) fn encode_response(
    response: Message,
    protocol: Protocol,
    dst: SocketAddr,
) -> Result<SerialMessage, ProtoError> {
    let id = response.header().id();
    trace!(
        id,
        response_code = %response.header().response_code(),
        "encoding response",
    );
    let mut buffer = Vec::with_capacity(512);
    let encode_result = {
        let mut encoder = BinEncoder::new(&mut buffer);

        // Set an appropriate maximum on the encoder.
        let max_size = max_size_for_response(protocol, &response);
        trace!(
            "setting response max size: {max_size} for protocol: {:?}",
            protocol
        );
        encoder.set_max_size(max_size);
        response.emit(&mut encoder)
    };

    encode_result.or_else(|error| {
        error!(%error, "error encoding message");
        encode_fallback_servfail_response(id, &mut buffer)
    })?;

    Ok(SerialMessage::new(buffer, dst))
}

fn encode_fallback_servfail_response(id: u16, buffer: &mut Vec<u8>) -> Result<(), ProtoError> {
    buffer.clear();
    let mut encoder = BinEncoder::new(buffer);
    encoder.set_max_size(512);
    let mut header = Header::new();
    header.set_id(id);
    header.set_response_code(ResponseCode::ServFail);
    header.emit(&mut encoder)?;
    Ok(())
}
