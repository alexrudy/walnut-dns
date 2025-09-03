pub mod hosts;
pub mod reserved;

pub use crate::lookup::Lookup;
pub use hosts::{HostsLayer, HostsResolver, HostsService};
pub use reserved::{ReservedNamesLayer, ReservedNamesResolver, ReservedNamesService, UsageArea};

pub type ResolverError = Box<dyn std::error::Error + Send + Sync>;
