use std::{borrow::Cow, num::ParseIntError};

use thiserror::Error;

use crate::{op::header::Metadata, rr::RecordType, serialize::binary::DecodeError};

#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Format error in Message Parsing
    #[error("message format error: {error}")]
    FormError {
        /// Header of the bad Message
        header: Metadata,
        /// Error that occurred while parsing the Message
        error: Box<Self>,
    },

    /// The maximum buffer size was exceeded
    #[error("maximum buffer size exceeded: {0}")]
    MaxBufferSizeExceeded(usize),

    /// Message decoding error
    #[error("decoding error: {0}")]
    Decode(#[from] DecodeError),

    /// Not all records were able to be written
    #[error("not all records could be written, wrote: {count}")]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: u16,
    },

    /// A response was received with QR=0, indicating it was a query and not a response
    #[error("response received with incorrect QR flag")]
    NotAResponse,

    /// An url parsing error
    #[error("url parsing error")]
    UrlParsing(#[from] url::ParseError),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    Utf8(#[from] core::str::Utf8Error),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// An int parsing error
    #[error("error parsing int")]
    ParseInt(#[from] ParseIntError),

    /// Character data length exceeded the limit
    #[error("char data length exceeds {max}: {len}")]
    CharacterDataTooLong {
        /// Specified maximum
        max: usize,
        /// Actual length
        len: usize,
    },

    #[error("error parsing {type} record: {msg}")]
    RecordParseError {
        /// The type of record being parsed
        r#type: RecordType,
        /// The error message
        msg: Cow<'static, str>,
    },

    /// An error with an arbitrary message
    #[error("{0}")]
    Message(Cow<'static, str>),

    /// Crypto operation failed
    #[error("crypto error: {0}")]
    #[cfg(feature = "__dnssec")]
    Crypto(&'static str),
}

impl From<String> for ProtocolError {
    fn from(msg: String) -> Self {
        Self::Message(Cow::Owned(msg))
    }
}

impl From<&'static str> for ProtocolError {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg.into())
    }
}

impl From<(RecordType, &'static str)> for ProtocolError {
    fn from((r#type, msg): (RecordType, &'static str)) -> Self {
        ProtocolError::RecordParseError {
            r#type,
            msg: Cow::Borrowed(msg),
        }
    }
}

impl From<(RecordType, String)> for ProtocolError {
    fn from((r#type, msg): (RecordType, String)) -> Self {
        ProtocolError::RecordParseError {
            r#type,
            msg: Cow::Owned(msg),
        }
    }
}
