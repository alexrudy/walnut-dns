use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::{Buf, BufMut};
use chateau::client::conn::protocol::framed::Tagged;
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Header, Message, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE;
use hickory_proto::xfer::Protocol;
use hickory_server::{authority::MessageRequest, server::Request};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error, trace};

use crate::server::response::encode_fallback_servfail_response;

/// The wire codec for standard DNS messages defined in RFC 1035.
pub struct DnsCodec<Req, Res> {
    length_delimited: bool,
    max_response_size: Option<u16>,
    message: PhantomData<fn(Req) -> Res>,
}

impl<Req, Res> fmt::Debug for DnsCodec<Req, Res> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCodec")
            .field("length_delimited", &self.length_delimited)
            .field("max_response_size", &self.max_response_size)
            .finish()
    }
}

impl<Req, Res> Clone for DnsCodec<Req, Res> {
    fn clone(&self) -> Self {
        Self {
            length_delimited: self.length_delimited,
            max_response_size: self.max_response_size,
            message: PhantomData,
        }
    }
}

impl<Req, Res> DnsCodec<Req, Res> {
    pub fn new_for_protocol(protocol: Protocol) -> Self {
        let (length_delimited, max_response_size) = match protocol {
            Protocol::Tcp => (true, Some(u16::MAX)),
            #[cfg(feature = "tls")]
            Protocol::Tls => (true, Some(u16::MAX)),
            Protocol::Udp => (false, Some(MAX_RECEIVE_BUFFER_SIZE as u16)),
            #[cfg(feature = "h2")]
            Protocol::Https => (false, None),
            _ => unimplemented!("Unknown protocol"),
        };

        Self::new(length_delimited, max_response_size)
    }

    pub fn new(length_delimited: bool, max_response_size: Option<u16>) -> Self {
        Self {
            length_delimited,
            max_response_size,
            message: PhantomData,
        }
    }

    pub fn with_recovery(self) -> DnsCodecRecovery<Req, Res> {
        DnsCodecRecovery::new(self)
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
    DropMessage(#[source] ProtoError, usize),

    #[error("Invalid message: {0}")]
    Protocol(#[source] ProtoError),

    #[error("Failed to handle message {}: {}", .0.id(), .1)]
    FailedMessage(Header, ResponseCode),

    #[error(transparent)]
    IO(#[from] std::io::Error),
}

/// Request decoded from a codec
///
/// The Failed condition indicates that the codec errored, but was still able
/// to process enough information to send a response.
#[derive(Debug)]
pub enum MessageDecoded<M> {
    Message(M),
    Failed(Header, ResponseCode),
}

impl MessageDecoded<MessageRequest> {
    pub fn with_address(self, addr: SocketAddr, protocol: Protocol) -> DnsRequest {
        match self {
            MessageDecoded::Message(message_request) => {
                DnsRequest::Message(Request::new(message_request, addr, protocol))
            }
            MessageDecoded::Failed(header, response_code) => DnsRequest::Failed((
                Message::error_msg(header.id(), header.op_code(), response_code),
                addr,
            )),
        }
    }

    pub fn without_address(self, protocol: Protocol) -> DnsRequest {
        match self {
            MessageDecoded::Message(message_request) => DnsRequest::Message(Request::new(
                message_request,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                protocol,
            )),
            MessageDecoded::Failed(header, response_code) => DnsRequest::Failed((
                Message::error_msg(header.id(), header.op_code(), response_code),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )),
        }
    }
}

impl<M> Tagged for MessageDecoded<M>
where
    M: Tagged<Tag = u16>,
{
    type Tag = u16;

    fn tag(&self) -> Self::Tag {
        match self {
            MessageDecoded::Message(msg) => msg.tag(),
            MessageDecoded::Failed(header, _) => header.id(),
        }
    }
}

/// A Request parsed from the codec, with address and protocol information
/// attached. This must be done after the codec, since the codec is agnostic
/// to the underlying protocol.
#[derive(Debug)]
pub enum DnsRequest {
    Message(Request),
    Failed((Message, SocketAddr)),
}

impl<Req, Res> Decoder for DnsCodec<Req, Res>
where
    Res: for<'a> BinDecodable<'a>,
{
    type Item = Res;
    type Error = CodecError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let length = if self.length_delimited {
            match self.parse_length(src) {
                Some(length) => length,
                None => return Ok(None),
            }
        } else {
            src.len()
        };

        if src.is_empty() {
            // No data to decode.
            return Ok(None);
        }

        trace!("decode buffer={}", src.len());

        let mut decoder = BinDecoder::new(src);
        let message =
            Res::read(&mut decoder).map_err(|error| CodecError::DropMessage(error, length))?;
        src.advance(length);
        Ok(Some(message))
    }
}

pub trait DnsMessage {
    fn header(&self) -> &Header;
    fn extensions(&self) -> Option<&Edns>;
}

impl DnsMessage for Message {
    fn header(&self) -> &Header {
        self.header()
    }

    fn extensions(&self) -> Option<&Edns> {
        self.extensions().as_ref()
    }
}

impl<T, A> DnsMessage for (T, A)
where
    T: DnsMessage,
{
    fn header(&self) -> &Header {
        self.0.header()
    }

    fn extensions(&self) -> Option<&Edns> {
        self.0.extensions()
    }
}

impl<Req, Res> Encoder<Req> for DnsCodec<Req, Res>
where
    Req: DnsMessage + BinEncodable,
{
    type Error = CodecError;

    fn encode(&mut self, response: Req, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
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
            if let Some(max_size) = if self.length_delimited {
                if let Some(edns) = response.extensions() {
                    Some(edns.max_payload())
                } else {
                    self.max_response_size
                }
            } else {
                self.max_response_size
            } {
                trace!("setting response max size: {max_size}");
                encoder.set_max_size(max_size);
            }

            response.emit(&mut encoder)
        }
        .or_else(|error| {
            error!(%error, "error encoding message, sending servfail");
            encode_fallback_servfail_response(id, &mut buffer)
        })
        .map_err(CodecError::Protocol)?;

        fn write_length(dst: &mut bytes::BytesMut, n: usize) {
            if dst.len() < (n + 2) {
                let additional = (n + 2) - dst.len();
                dst.reserve(additional);
            }
            dst.put(u16::to_be_bytes(n as u16).as_slice());
        }

        if self.length_delimited {
            write_length(dst, buffer.len())
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

pub struct DnsCodecRecovery<Req, Res> {
    codec: DnsCodec<Req, Res>,
}

impl<Req, Res> DnsCodecRecovery<Req, Res> {
    pub fn new(codec: DnsCodec<Req, Res>) -> Self {
        Self { codec }
    }
}

impl<Req, Res> fmt::Debug for DnsCodecRecovery<Req, Res> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCodecRecovery")
            .field("codec", &self.codec)
            .finish()
    }
}

impl<Req, Res> Clone for DnsCodecRecovery<Req, Res> {
    fn clone(&self) -> Self {
        Self {
            codec: self.codec.clone(),
        }
    }
}

impl<Req, Res> Decoder for DnsCodecRecovery<Req, Res>
where
    Res: for<'a> BinDecodable<'a>,
{
    type Item = MessageDecoded<Res>;
    type Error = CodecError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.codec.decode(src) {
            Ok(Some(message)) => Ok(Some(MessageDecoded::Message(message))),
            Ok(None) => Ok(None),
            Err(CodecError::DropMessage(error, length)) => {
                // Try to just parse the header, if that fails, just drop the message.
                let mut decoder = BinDecoder::new(src);
                match Header::read(&mut decoder) {
                    Ok(header) => {
                        debug!("Failed to parse message, sending error: {error}");
                        src.advance(length);
                        Ok(Some(MessageDecoded::Failed(header, ResponseCode::FormErr)))
                    }
                    Err(_) => {
                        error!("Failed to parse header: {error}");
                        Err(CodecError::DropMessage(error, length))
                    }
                }
            }
            Err(error) => Err(error),
        }
    }
}

impl<Req, Res> Encoder<Req> for DnsCodecRecovery<Req, Res>
where
    Req: DnsMessage + BinEncodable,
{
    type Error = CodecError;

    fn encode(&mut self, item: Req, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        self.codec.encode(item, dst)
    }
}
