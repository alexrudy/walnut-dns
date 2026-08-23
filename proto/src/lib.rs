#[cfg(feature = "__dnssec")]
pub mod dnssec;
pub mod error;
pub mod op;
pub mod rr;
pub mod serialize;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use error::ProtocolError;
pub(crate) use rand::random;

/// Authoritative DNS root servers.
///
/// <https://www.iana.org/domains/root/servers>
pub const ROOTS: &[IpAddr] = &[
    // a.root-servers.net
    IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
    IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x503, 0xba3e, 0x0, 0x0, 0x0, 0x2, 0x30,
    )),
    // b.root-servers.net
    IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
    IpAddr::V6(Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0x0, 0x0, 0x0, 0x0, 0xb)),
    // c.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2, 0x0, 0x0, 0x0, 0x0, 0xc)),
    // d.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2d, 0x0, 0x0, 0x0, 0x0, 0xd)),
    // e.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0xa8, 0x0, 0x0, 0x0, 0x0, 0xe)),
    // f.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2f, 0x0, 0x0, 0x0, 0x0, 0xf)),
    // g.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)),
    IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x500, 0x12, 0x0, 0x0, 0x0, 0x0, 0xd0d,
    )),
    // h.root-servers.net
    IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x1, 0x0, 0x0, 0x0, 0x0, 0x53)),
    // i.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53)),
    // j.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)),
    IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x503, 0xc27, 0x0, 0x0, 0x0, 0x2, 0x30,
    )),
    // k.root-servers.net
    IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1)),
    // l.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x9f, 0x0, 0x0, 0x0, 0x0, 0x42)),
    // m.root-servers.net
    IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdc3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x35)),
];
