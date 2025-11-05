//! Service factory for creating DNS services for specific nameservers
//!
//! This provides a simple way to create DNS services that target specific
//! nameservers for recursive resolution.

use std::net::IpAddr;

use hickory_proto::xfer::{DnsRequest, DnsResponse};
use tower::Service;

use crate::client::{
    DnsClientError,
    nameserver::{ConnectionConfig, NameServerConnection, ProtocolConfig, NameserverPool},
    messages::DnsRequestMiddleware,
};

/// A factory for creating DNS services that target specific nameservers
#[derive(Debug, Clone)]
pub struct NameserverServiceFactory {
    connection_config: ConnectionConfig,
}

impl NameserverServiceFactory {
    /// Create a new factory with the given connection configuration
    pub fn new(connection_config: ConnectionConfig) -> Self {
        Self { connection_config }
    }

    /// Create with default UDP configuration
    pub fn with_udp() -> Self {
        Self::new(ConnectionConfig {
            protocol: ProtocolConfig::Udp,
            port: 53,
        })
    }

    /// Create a DNS service for a specific set of nameservers
    pub fn create_service(&self, nameservers: Vec<IpAddr>) -> impl Service<DnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone {
        // Create connections for each nameserver
        let connections: Vec<NameServerConnection> = nameservers
            .into_iter()
            .map(|addr| NameServerConnection::from_config(addr, self.connection_config.clone()))
            .collect();

        // Create a pool with these connections
        let pool = NameserverPool::new(connections, Default::default());
        
        // Wrap with request middleware
        DnsRequestMiddleware::new(pool)
    }

    /// Create a service for root nameservers
    pub fn create_root_service(&self) -> impl Service<DnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone {
        let root_hints = vec![
            "198.41.0.4".parse().unwrap(),    // a.root-servers.net
            "199.9.14.201".parse().unwrap(),  // b.root-servers.net
            "192.33.4.12".parse().unwrap(),   // c.root-servers.net
            "199.7.91.13".parse().unwrap(),   // d.root-servers.net
        ];
        
        self.create_service(root_hints)
    }
}

/// A simple service that can query specific nameservers
pub type NameserverService = DnsRequestMiddleware<NameserverPool>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_creation() {
        let factory = NameserverServiceFactory::with_udp();
        let nameservers = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        let _service = factory.create_service(nameservers);
    }

    #[test] 
    fn test_root_service_creation() {
        let factory = NameserverServiceFactory::with_udp();
        let _service = factory.create_root_service();
    }
}