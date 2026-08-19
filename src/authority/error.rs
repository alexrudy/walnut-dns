use std::{io, sync::Arc};

use hickory_proto::{ProtoError, ProtoErrorKind, op::ResponseCode, rr::rdata::SOA};
use thiserror::Error;

use crate::rr::Record;

/// A query could not be fulfilled
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    #[error("The name exists, but not for the record requested")]
    NameExists,
    /// There was an error performing the lookup
    #[error("Error performing lookup: {0}")]
    ResponseCode(ResponseCode),
    /// Proto error
    #[error("Proto error: {0}")]
    ProtoError(#[from] ProtoError),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(io::Error),
}

impl LookupError {
    /// Returns true if the name exists, but not for the requested record type
    pub fn is_name_exists(&self) -> bool {
        matches!(self, LookupError::NameExists)
    }

    /// This is a non-existent domain name
    pub fn is_nx_domain(&self) -> bool {
        matches!(self, LookupError::ResponseCode(ResponseCode::NXDomain))
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        // Only possible in recursion or resolution, which are not yet supported.
        false
    }

    /// This query was refused
    pub fn is_refused(&self) -> bool {
        matches!(*self, Self::ResponseCode(ResponseCode::Refused))
    }

    /// Return the SOA record, if one exists
    pub fn into_soa(self) -> Option<Record<SOA>> {
        // Only possible in recursion or resolution, which are not yet supported.
        None
    }

    /// Return authority records
    pub fn authorities(&self) -> Option<Arc<[Record]>> {
        match self {
            Self::ProtoError(e) => match e.kind() {
                ProtoErrorKind::NoRecordsFound { authorities, .. } => authorities
                    .clone()
                    .map(|rrset| rrset.iter().map(|rr| Record::from(rr.clone())).collect()),
                _ => None,
            },
            _ => None,
        }
    }
}

impl From<ResponseCode> for LookupError {
    fn from(code: ResponseCode) -> Self {
        // this should never be a NoError
        debug_assert!(code != ResponseCode::NoError);
        Self::ResponseCode(code)
    }
}

impl From<io::Error> for LookupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<LookupError> for io::Error {
    fn from(e: LookupError) -> Self {
        Self::new(io::ErrorKind::Other, Box::new(e))
    }
}
