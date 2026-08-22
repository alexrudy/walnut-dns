//! Resource Record Definitions for DNS

pub mod dns_class;
pub mod domain;
mod id;
pub mod rdata;
pub mod record;
pub mod record_data;
pub mod record_type;
pub mod record_type_set;
pub mod rr_key;
pub mod rr_set;
mod sequence;
mod sql;
pub mod tsig;
pub mod ttl;
pub mod zone;

use std::fmt::Debug;
use std::fmt::Display;

use crate::serialize::binary::BinDecodable;
use crate::serialize::binary::BinDecoder;
use crate::serialize::binary::BinEncodable;
use crate::serialize::binary::DecodeError;
use crate::serialize::binary::Restrict;

pub use self::dns_class::DNSClass;
pub use self::domain::{IntoName, Label, Name};
pub use self::id::{QueryID, RecordID, ZoneID};
pub use self::record::{Record, RecordRef};
pub use self::record_data::RData;
pub use self::record_type::RecordType;
pub use self::record_type_set::RecordTypeSet;
pub use self::rr_key::RrKey;
pub use self::rr_set::RecordSetIter;
pub use self::rr_set::{Mismatch, RecordSet};
pub use self::sequence::SerialNumber;
pub use self::sql::{NameExt, SqlName};
pub use self::tsig::{TSigVerifier, TSigner};
pub use self::ttl::TimeToLive;
pub use self::zone::{Zone, ZoneType};

/// RecordData that is stored in a DNS Record.
///
/// This trait allows for generic usage of `RecordData` types inside the `Record` type. Specific RecordData types can be used to enforce compile time constraints on a Record.
pub trait RecordData: Clone + Sized + PartialEq + Eq + Display + Debug + BinEncodable {
    /// Attempts to borrow this RecordData from the RData type, if it is not the correct type the original is returned
    fn try_borrow(data: &RData) -> Option<&Self>;

    /// Get the associated RecordType for the RecordData
    fn record_type(&self) -> RecordType;

    /// Converts this RecordData into generic RecordData
    fn into_rdata(self) -> RData;

    /// RDLENGTH = 0
    fn is_update(&self) -> bool {
        false
    }
}

pub(crate) trait RecordDataDecodable<'r>: Sized {
    /// Read the RecordData from the data stream.
    ///
    /// * `decoder` - data stream from which the RData will be read
    /// * `record_type` - specifies the RecordType that has already been read from the stream
    /// * `length` - the data length that should be read from the stream for this RecordData
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> Result<Self, DecodeError>;
}

impl<'r, T> RecordDataDecodable<'r> for T
where
    T: 'r + BinDecodable<'r> + Sized,
{
    fn read_data(
        decoder: &mut BinDecoder<'r>,
        _length: Restrict<u16>,
    ) -> Result<Self, DecodeError> {
        T::read(decoder)
    }
}
