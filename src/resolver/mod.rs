mod factory;
pub mod hosts;
pub mod recursive;
pub mod reserved;

pub use crate::lookup::Lookup;
pub use factory::{NameserverService, NameserverServiceFactory};
pub use hosts::{HostsLayer, HostsResolver, HostsService};
pub use recursive::{RecursiveConfig, RecursiveLayer, RecursiveResolver, RecursiveService, RecursiveError};
pub use reserved::{ReservedNamesLayer, ReservedNamesResolver, ReservedNamesService, UsageArea};

pub type ResolverError = Box<dyn std::error::Error + Send + Sync>;
