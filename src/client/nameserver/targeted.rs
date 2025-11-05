//! Targeted nameserver service for querying specific nameservers
//!
//! This module provides a service that can create connections to specific
//! nameservers on-demand, which is useful for recursive DNS resolution
//! where you need to query different nameservers at each step.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use hickory_proto::{
    op::Message,
    xfer::{DnsRequest, DnsResponse},
};
use tower::{Service, ServiceBuilder};
use tracing::{debug, trace};

use crate::client::{
    codec::DnsCodecService,
    messages::DnsRequestMiddleware, 
    DnsClientError,
};

use super::{ConnectionConfig, NameServerConnection, ProtocolConfig};

/// A service that can create connections to specific nameservers for DNS queries
///
/// This service is designed for recursive DNS resolution where you need to query
/// different nameservers (like root servers, TLD servers, authoritative servers)
/// at each step of the resolution process.
#[derive(Debug, Clone)]
pub struct TargetedNameserverService {
    /// Connection configuration template
    connection_config: Arc<ConnectionConfig>,
    /// Cache of established connections
    connections: Arc<tokio::sync::Mutex<HashMap<IpAddr, NameServerConnection>>>,
}

impl TargetedNameserverService {
    /// Create a new targeted nameserver service
    ///
    /// # Arguments
    /// * `connection_config` - Configuration template for creating connections
    pub fn new(connection_config: ConnectionConfig) -> Self {
        Self {
            connection_config: Arc::new(connection_config),
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Create with default UDP configuration
    pub fn with_udp() -> Self {
        Self::new(ConnectionConfig {
            protocol: ProtocolConfig::Udp,
            port: 53,
        })
    }

    /// Create with default TCP configuration
    pub fn with_tcp() -> Self {
        Self::new(ConnectionConfig {
            protocol: ProtocolConfig::Tcp,
            port: 53,
        })
    }

    /// Get or create a connection to a specific nameserver
    async fn get_connection(&self, address: IpAddr) -> Result<NameServerConnection, DnsClientError> {
        let mut connections = self.connections.lock().await;
        
        if let Some(conn) = connections.get(&address) {
            trace!("Reusing connection to {}", address);
            return Ok(conn.clone());
        }

        debug!("Creating new connection to {} with protocol {:?}", address, self.connection_config.protocol);
        
        let connection = NameServerConnection::from_config(address, (*self.connection_config).clone());
        connections.insert(address, connection.clone());
        
        Ok(connection)
    }
}

/// A service for targeting messages to specific nameservers
#[derive(Debug, Clone)]
pub struct TargetedMessageService {
    /// Connection configuration template
    connection_config: Arc<ConnectionConfig>,
    /// Cache of established connections
    connections: Arc<tokio::sync::Mutex<HashMap<IpAddr, NameServerConnection>>>,
}

impl TargetedMessageService {
    pub fn new(connection_config: ConnectionConfig) -> Self {
        Self {
            connection_config: Arc::new(connection_config),
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn with_udp() -> Self {
        Self::new(ConnectionConfig {
            protocol: ProtocolConfig::Udp,
            port: 53,
        })
    }

    /// Get or create a connection to a specific nameserver
    async fn get_connection(&self, address: IpAddr) -> Result<NameServerConnection, DnsClientError> {
        let mut connections = self.connections.lock().await;
        
        if let Some(conn) = connections.get(&address) {
            trace!("Reusing connection to {}", address);
            return Ok(conn.clone());
        }

        debug!("Creating new connection to {} with protocol {:?}", address, self.connection_config.protocol);
        
        let connection = NameServerConnection::from_config(address, (*self.connection_config).clone());
        connections.insert(address, connection.clone());
        
        Ok(connection)
    }
}

impl Service<TargetedMessage> for TargetedMessageService {
    type Response = Message;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<Message, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TargetedMessage) -> Self::Future {
        let service = self.clone();
        
        Box::pin(async move {
            let connection = service.get_connection(req.nameserver).await?;
            
            // Use the codec service to handle the Message -> TaggedMessage conversion
            let mut codec_svc = DnsCodecService::new(connection.service().clone());
            
            // Forward the message
            codec_svc.call(req.message).await
        })
    }
}

/// A Message targeted at a specific nameserver
#[derive(Clone)]
pub struct TargetedMessage {
    /// The message to send
    pub message: Message,
    /// The nameserver to send to
    pub nameserver: IpAddr,
}

impl TargetedMessage {
    pub fn new(message: Message, nameserver: IpAddr) -> Self {
        Self { message, nameserver }
    }
}

impl Service<TargetedDnsRequest> for TargetedNameserverService {
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<DnsResponse, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TargetedDnsRequest) -> Self::Future {
        let service = self.clone();
        
        Box::pin(async move {
            let connection = service.get_connection(req.nameserver).await?;
            
            // Create the targeted message service first
            let msg_service = TargetedMessageService::new((*service.connection_config).clone());
            
            // Then wrap it with DnsRequestMiddleware
            let mut svc = ServiceBuilder::new()
                .service(DnsRequestMiddleware::new(msg_service));
            
            // Forward the request
            svc.call(req.request).await
        })
    }
}

/// A DNS request targeted at a specific nameserver
#[derive(Clone)]
pub struct TargetedDnsRequest {
    /// The DNS request to send
    pub request: DnsRequest,
    /// The nameserver to send the request to
    pub nameserver: IpAddr,
}

impl TargetedDnsRequest {
    /// Create a new targeted DNS request
    pub fn new(request: DnsRequest, nameserver: IpAddr) -> Self {
        Self { request, nameserver }
    }

    /// Create a targeted request from a regular request and nameserver address
    pub fn for_nameserver(request: DnsRequest, nameserver: &str) -> Result<Self, DnsClientError> {
        let addr = nameserver.parse::<IpAddr>()
            .map_err(|e| DnsClientError::Unavailable(format!("Invalid nameserver address {}: {}", nameserver, e)))?;
        
        Ok(Self::new(request, addr))
    }
}

/// A layer that converts regular DNS requests to targeted requests using a default nameserver
#[derive(Debug, Clone)]
pub struct DefaultNameserverLayer {
    nameserver: IpAddr,
}

impl DefaultNameserverLayer {
    /// Create a layer that targets all requests to a specific nameserver
    pub fn new(nameserver: IpAddr) -> Self {
        Self { nameserver }
    }
}

impl<S> tower::Layer<S> for DefaultNameserverLayer {
    type Service = DefaultNameserverService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DefaultNameserverService {
            inner,
            nameserver: self.nameserver,
        }
    }
}

/// Service that wraps a TargetedNameserverService to accept regular DnsRequest
#[derive(Debug, Clone)]
pub struct DefaultNameserverService<S> {
    inner: S,
    nameserver: IpAddr,
}

impl<S> Service<DnsRequest> for DefaultNameserverService<S>
where
    S: Service<TargetedDnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let targeted_req = TargetedDnsRequest::new(req, self.nameserver);
        self.inner.call(targeted_req)
    }
}

/// A multi-nameserver service that can target different nameservers per request
///
/// This is useful for recursive resolution where you want to be able to specify
/// which nameservers to use for each query.
#[derive(Debug, Clone)]
pub struct MultiNameserverService {
    inner: TargetedNameserverService,
    default_nameservers: Arc<Vec<IpAddr>>,
    current_index: Arc<tokio::sync::Mutex<usize>>,
}

impl MultiNameserverService {
    /// Create a new multi-nameserver service
    pub fn new(connection_config: ConnectionConfig, default_nameservers: Vec<IpAddr>) -> Self {
        Self {
            inner: TargetedNameserverService::new(connection_config),
            default_nameservers: Arc::new(default_nameservers),
            current_index: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    /// Create with root nameservers
    pub fn with_root_hints() -> Self {
        let root_hints = vec![
            "198.41.0.4".parse().unwrap(),    // a.root-servers.net
            "199.9.14.201".parse().unwrap(),  // b.root-servers.net
            "192.33.4.12".parse().unwrap(),   // c.root-servers.net
            "199.7.91.13".parse().unwrap(),   // d.root-servers.net
            "192.203.230.10".parse().unwrap(), // e.root-servers.net
            "192.5.5.241".parse().unwrap(),   // f.root-servers.net
        ];
        
        Self::new(
            ConnectionConfig {
                protocol: ProtocolConfig::Udp,
                port: 53,
            },
            root_hints,
        )
    }

    /// Get the next nameserver in round-robin fashion
    async fn next_nameserver(&self) -> Result<IpAddr, DnsClientError> {
        if self.default_nameservers.is_empty() {
            return Err(DnsClientError::Unavailable("No nameservers configured".into()));
        }

        let mut index = self.current_index.lock().await;
        let ns = self.default_nameservers[*index];
        *index = (*index + 1) % self.default_nameservers.len();
        Ok(ns)
    }

    /// Create a service that targets a specific set of nameservers
    pub fn for_nameservers(&self, nameservers: Vec<IpAddr>) -> SpecificNameserverService {
        SpecificNameserverService {
            inner: self.inner.clone(),
            nameservers: Arc::new(nameservers),
            current_index: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }
}

impl Service<DnsRequest> for MultiNameserverService {
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<DnsResponse, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let service = self.clone();
        
        Box::pin(async move {
            let nameserver = service.next_nameserver().await?;
            let targeted_req = TargetedDnsRequest::new(req, nameserver);
            let mut inner = service.inner.clone();
            inner.call(targeted_req).await
        })
    }
}

/// Service that targets a specific set of nameservers
#[derive(Debug, Clone)]
pub struct SpecificNameserverService {
    inner: TargetedNameserverService,
    nameservers: Arc<Vec<IpAddr>>,
    current_index: Arc<tokio::sync::Mutex<usize>>,
}

impl Service<DnsRequest> for SpecificNameserverService {
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<DnsResponse, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let service = self.clone();
        
        Box::pin(async move {
            if service.nameservers.is_empty() {
                return Err(DnsClientError::Unavailable("No nameservers specified".into()));
            }

            let mut index = service.current_index.lock().await;
            let nameserver = service.nameservers[*index];
            *index = (*index + 1) % service.nameservers.len();
            drop(index);

            let targeted_req = TargetedDnsRequest::new(req, nameserver);
            let mut inner = service.inner.clone();
            inner.call(targeted_req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::{Name, RecordType}};

    #[test]
    fn test_targeted_request_creation() {
        let query = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let mut message = Message::new();
        message.add_query(query);
        
        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let nameserver = "8.8.8.8".parse().unwrap();
        
        let targeted = TargetedDnsRequest::new(request, nameserver);
        assert_eq!(targeted.nameserver, nameserver);
    }

    #[test]
    fn test_targeted_request_from_string() {
        let query = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let mut message = Message::new();
        message.add_query(query);
        
        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        
        let targeted = TargetedDnsRequest::for_nameserver(request, "8.8.8.8").unwrap();
        assert_eq!(targeted.nameserver, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_invalid_nameserver_address() {
        let query = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let mut message = Message::new();
        message.add_query(query);
        
        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        
        let result = TargetedDnsRequest::for_nameserver(request, "invalid");
        assert!(result.is_err());
    }
}