pub mod edns;
#[cfg(any(feature = "h2-ring", feature = "h2-aws-lc"))]
pub mod http;

// Needed services:
// Catalog reject responses
// Catalog Lookup -> Response Message
// Catalog Update handler
