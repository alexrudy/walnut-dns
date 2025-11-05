//! Simple nameserver service that can target specific nameservers
//!
//! This provides a lightweight service that implements Service<Message> 
//! and can be used to query specific nameservers for recursive resolution.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use hickory_proto::op::Message;
use tracing::{debug, trace};

use crate::client::DnsClientError;

use super::{ConnectionConfig, NameServerConnection, ProtocolConfig};

/// A simple service that can target specific nameservers for DNS queries
#[derive(Debug, Clone)]
pub struct SimpleNameserverService {
    /// Connection configuration template
    connection_config: Arc<ConnectionConfig>,
    /// Cache of established connections
    connections: Arc<tokio::sync::Mutex<HashMap<IpAddr, NameServerConnection>>>,
    /// The current nameserver to target
    nameserver: IpAddr,
}

impl SimpleNameserverService {
    /// Create a new service targeting a specific nameserver
    pub fn new(connection_config: ConnectionConfig, nameserver: IpAddr) -> Self {
        Self {
            connection_config: Arc::new(connection_config),
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            nameserver,
        }
    }

    /// Create with default UDP configuration for a specific nameserver  
    pub fn with_udp(nameserver: IpAddr) -> Self {
        Self::new(
            ConnectionConfig {
                protocol: ProtocolConfig::Udp,
                port: 53,
            },
            nameserver,
        )
    }

    /// Get or create a connection to the targeted nameserver
    async fn get_connection(&self) -> Result<NameServerConnection, DnsClientError> {
        let mut connections = self.connections.lock().await;
        
        if let Some(conn) = connections.get(&self.nameserver) {
            trace!("Reusing connection to {}", self.nameserver);
            return Ok(conn.clone());
        }

        debug!(
            "Creating new connection to {} with protocol {:?}", 
            self.nameserver, 
            self.connection_config.protocol
        );
        
        let connection = NameServerConnection::from_config(
            self.nameserver, 
            (*self.connection_config).clone()
        );
        connections.insert(self.nameserver, connection.clone());
        
        Ok(connection)
    }
}

impl tower::Service<Message> for SimpleNameserverService {
    type Response = Message;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<Message, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Message) -> Self::Future {
        let service = self.clone();
        
        Box::pin(async move {
            let connection = service.get_connection().await?;
            
            // Use the codec service to handle the Message -> TaggedMessage conversion
            let mut codec_svc = crate::client::codec::DnsCodecService::new(
                connection.service().clone()
            );
            
            // Forward the message
            codec_svc.call(request).await
        })
    }
}

/// A multi-nameserver service that queries specific sets of nameservers
#[derive(Debug, Clone)]
pub struct MultiTargetService {
    connection_config: Arc<ConnectionConfig>,
    nameservers: Vec<IpAddr>,
    current_index: Arc<tokio::sync::Mutex<usize>>,
}

impl MultiTargetService {
    /// Create a new service with a list of nameservers
    pub fn new(connection_config: ConnectionConfig, nameservers: Vec<IpAddr>) -> Self {
        Self {
            connection_config: Arc::new(connection_config),
            nameservers,
            current_index: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    /// Create with UDP configuration and root hints
    pub fn with_root_hints() -> Self {
        let root_hints = vec![
            "198.41.0.4".parse().unwrap(),    // a.root-servers.net
            "199.9.14.201".parse().unwrap(),  // b.root-servers.net
            "192.33.4.12".parse().unwrap(),   // c.root-servers.net
            "199.7.91.13".parse().unwrap(),   // d.root-servers.net
        ];
        
        Self::new(
            ConnectionConfig {
                protocol: ProtocolConfig::Udp,
                port: 53,
            },
            root_hints,
        )
    }

    /// Create a service targeting specific nameservers  
    pub fn for_nameservers(&self, nameservers: Vec<IpAddr>) -> Self {
        Self::new((*self.connection_config).clone(), nameservers)
    }

    /// Get the next nameserver in round-robin fashion
    async fn next_nameserver(&self) -> Result<IpAddr, DnsClientError> {
        if self.nameservers.is_empty() {
            return Err(DnsClientError::Unavailable("No nameservers configured".into()));
        }

        let mut index = self.current_index.lock().await;
        let ns = self.nameservers[*index];
        *index = (*index + 1) % self.nameservers.len();
        Ok(ns)
    }
}

impl tower::Service<Message> for MultiTargetService {
    type Response = Message;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<Message, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.nameservers.is_empty() {
            Poll::Ready(Err(DnsClientError::Unavailable("No nameservers".into())))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, request: Message) -> Self::Future {
        let service = self.clone();
        
        Box::pin(async move {
            let nameserver = service.next_nameserver().await?;
            let mut targeted_service = SimpleNameserverService::new(
                (*service.connection_config).clone(),
                nameserver,
            );
            targeted_service.call(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::{Name, RecordType}};

    #[test]
    fn test_simple_service_creation() {
        let nameserver = "8.8.8.8".parse().unwrap();
        let service = SimpleNameserverService::with_udp(nameserver);
        assert_eq!(service.nameserver, nameserver);
    }

    #[test]
    fn test_multi_target_creation() {
        let service = MultiTargetService::with_root_hints();
        assert!(!service.nameservers.is_empty());
    }
}