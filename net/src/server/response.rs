use walnut_proto::ProtocolError;
use walnut_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use walnut_proto::serialize::binary::{BinEncodable, BinEncoder};

pub(crate) fn encode_fallback_servfail_response(
    id: u16,
    buffer: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    buffer.clear();
    let mut encoder = BinEncoder::new(buffer);
    encoder.set_max_size(512);
    let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    let header = Header {
        metadata,
        counts: HeaderCounts::default(),
    };

    header.emit(&mut encoder)?;
    Ok(())
}
