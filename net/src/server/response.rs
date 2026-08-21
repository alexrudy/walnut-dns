use hickory_proto::ProtoError;
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

pub(crate) fn encode_fallback_servfail_response(
    id: u16,
    buffer: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    buffer.clear();
    let mut encoder = BinEncoder::new(buffer);
    encoder.set_max_size(512);
    let mut header = Header::new();
    header.set_id(id);
    header.set_response_code(ResponseCode::ServFail);
    header.emit(&mut encoder)?;
    Ok(())
}
