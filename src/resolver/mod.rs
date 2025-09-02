pub mod reserved;

pub use crate::lookup::Lookup;
pub use reserved::{ReservedNamesResolver, ReservedNamesLayer, ReservedNamesService, UsageArea};

pub type ResolverError = Box<dyn std::error::Error + Send + Sync>;
