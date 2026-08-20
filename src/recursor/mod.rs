//! Recursive DNS resolution
//!
//! Components usually include:
//!  - Caching queries
//!  - Following cnames
//!  - Following nameserver + glue when a name is not resolved.

pub mod cname;
pub mod limit;
