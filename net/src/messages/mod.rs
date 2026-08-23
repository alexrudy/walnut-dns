pub mod client;
pub mod resolver;
pub mod server;

pub use self::client::{DnsRequest, DnsRequestOptions, DnsResponse, Protocol};
pub use self::resolver::DnsQuery;
