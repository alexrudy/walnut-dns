//! Resource Record Definitions for DNS

mod id;
mod record;
mod rset;
mod sequence;
mod sql;
mod ttl;
mod zone;

pub use self::id::{QueryID, RecordID, ZoneID};
pub use self::record::Record;
pub use self::rset::{Mismatch, RecordSet};
pub use self::sequence::SerialNumber;
pub use self::sql::{NameExt, SqlName};
pub use self::ttl::TimeToLive;
pub use self::zone::{Zone, ZoneType};

/// DNS Name with case preserved.
///
pub use hickory_proto::rr::Name;

/// DNS Name converted to the canonical lowercase form.
///
pub use hickory_proto::rr::LowerName;

/// Trait for converting walnut-dns types to their hickory-dns equivalents
///
/// This trait provides a consistent interface for converting internal types
/// to their hickory-dns counterparts, enabling compatibility with the
/// hickory-dns ecosystem.
pub trait AsHickory {
    /// The corresponding hickory-dns type
    type Hickory;

    /// Convert this type to its hickory-dns equivalent
    ///
    /// # Returns
    ///
    /// A new instance of the hickory-dns equivalent type
    fn as_hickory(&self) -> Self::Hickory;
}
