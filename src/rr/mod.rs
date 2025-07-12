//! Resource Record Definitions for DNS

mod id;
mod name;
mod record;
mod rset;
mod sequence;
mod ttl;
mod zone;

pub use self::id::{RecordID, ZoneID};
pub use self::name::{Lower, LowerRef, Name};
pub use self::record::Record;
pub use self::rset::{Mismatch, RecordSet};
pub use self::sequence::SerialNumber;
pub use self::ttl::TimeToLive;
pub use self::zone::{Zone, ZoneType};

pub trait AsHickory {
    type Hickory;
    fn as_hickory(&self) -> Self::Hickory;
}
