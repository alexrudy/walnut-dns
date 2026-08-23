use chateau::client::conn::ConnectionError;
use walnut_proto::ProtocolError;
use walnut_proto::op::{Metadata, ResponseCode};

use crate::codec::CodecError;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum DnsClientError {
    #[error("DNS Protocol: {0}")]
    DnsProtocol(#[from] ProtocolError),

    #[error("Invalid response for message {}: {}", .0.id, .1)]
    Response(Metadata, ResponseCode),

    #[cfg(feature = "h2")]
    #[error("Http Request Error: {0}")]
    Http(#[from] hyper::Error),

    #[error(transparent)]
    Service(Box<dyn std::error::Error + Send + Sync>),

    #[error("Transport Error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Protocol Error: {0}")]
    Protocol(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Connection closed")]
    Closed,

    #[error("Unavailalbe: {0}")]
    Unavailable(String),

    #[error("Cache: {0}")]
    Cache(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Too many CNAME lookups attempted: {0}")]
    CNameLimitExceeded(usize),
}

impl From<CodecError> for DnsClientError {
    fn from(value: CodecError) -> Self {
        match value {
            CodecError::DropMessage(proto_error, _) | CodecError::Protocol(proto_error) => {
                DnsClientError::DnsProtocol(proto_error)
            }
            CodecError::FailedMessage(header, response_code) => {
                DnsClientError::Response(header.metadata, response_code)
            }
            CodecError::IO(_) => DnsClientError::Closed,
        }
    }
}

impl<T, P, S> From<ConnectionError<T, P, S>> for DnsClientError
where
    T: Into<BoxError>,
    P: Into<BoxError>,
    S: Into<BoxError>,
{
    fn from(error: ConnectionError<T, P, S>) -> Self {
        match error {
            ConnectionError::Connecting(error) => DnsClientError::Transport(error.into()),
            ConnectionError::Handshaking(error) => DnsClientError::Protocol(error.into()),
            ConnectionError::Service(error) => DnsClientError::Service(error.into()),
            ConnectionError::Unavailable => {
                DnsClientError::Unavailable("UDP Connection not possible".into())
            }
            ConnectionError::Key(_) => unreachable!("No key used by manager"),
            _ => panic!("unknown error type"),
        }
    }
}
