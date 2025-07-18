use std::io;

use hickory_proto::ProtoError;
use hickory_server::authority::LookupError;
use tokio::task::JoinError;

#[derive(Debug, thiserror::Error)]
pub enum HickoryError {
    #[error("dns protocol error: {0}")]
    Protocol(#[from] ProtoError),

    #[error("udp message does not appear to be dns")]
    NotDNSMessage,

    #[error("Recieved a response as a request message")]
    ResponseAsRequest,

    #[error("Looking up zone: {0}")]
    LookupError(#[from] LookupError),

    #[error("Connection closed")]
    Closed,

    #[error("Send IO error: {0}")]
    Send(#[source] io::Error),

    #[error("Recv IO error: {0}")]
    Recv(#[source] io::Error),

    #[error("Panic: {0}")]
    Panic(JoinError),
}
