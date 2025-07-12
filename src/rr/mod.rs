//! Resource Record Definitions for DNS

mod id;
mod record;
mod rset;
mod sequence;
mod sql;
mod ttl;
mod zone;

pub use self::id::{RecordID, ZoneID};
pub use self::record::Record;
pub use self::rset::{Mismatch, RecordSet};
pub use self::sequence::SerialNumber;
pub use self::sql::{NameExt, SqlName};
pub use self::ttl::TimeToLive;
pub use self::zone::{Zone, ZoneType};
pub use hickory_proto::rr::{LowerName, Name};

pub trait AsHickory {
    type Hickory;
    fn as_hickory(&self) -> Self::Hickory;
}
