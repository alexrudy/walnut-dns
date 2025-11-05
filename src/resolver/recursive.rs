//! Recursive DNS resolver
//!
//! This module provides a recursive DNS resolver that follows the DNS resolution
//! process by starting from the root nameservers and following referrals until
//! it finds the authoritative answer or reaches a resolution failure.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::BoxFuture, FutureExt};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
    xfer::{DnsRequest, DnsResponse},
};
use tower::Service;
use tracing::{debug, error, trace, warn};

use crate::client::DnsClientError;

/// Configuration for the recursive resolver
#[derive(Debug, Clone)]
pub struct RecursiveConfig {
    /// Maximum recursion depth to prevent infinite loops
    pub max_depth: u8,
    /// Timeout for individual queries
    pub query_timeout: Duration,
    /// Whether to follow CNAME chains
    pub follow_cnames: bool,
    /// Root nameservers to start resolution from
    pub root_hints: Vec<String>,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            max_depth: 16,
            query_timeout: Duration::from_secs(5),
            follow_cnames: true,
            root_hints: vec![
                "198.41.0.4".to_string(),    // a.root-servers.net
                "199.9.14.201".to_string(),  // b.root-servers.net
                "192.33.4.12".to_string(),   // c.root-servers.net
                "199.7.91.13".to_string(),   // d.root-servers.net
                "192.203.230.10".to_string(), // e.root-servers.net
                "192.5.5.241".to_string(),   // f.root-servers.net
            ],
        }
    }
}

/// Context for tracking recursive resolution state
#[derive(Debug, Clone)]
struct ResolutionContext {
    original_query: Query,
    current_query: Query,
    depth: u8,
    max_depth: u8,
    nameservers: Vec<String>,
    cname_chain: Vec<Name>,
}

impl ResolutionContext {
    fn new(query: Query, max_depth: u8, root_hints: Vec<String>) -> Self {
        Self {
            original_query: query.clone(),
            current_query: query,
            depth: 0,
            max_depth,
            nameservers: root_hints,
            cname_chain: Vec::new(),
        }
    }

    fn next_depth(&mut self) -> Result<(), RecursiveError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            Err(RecursiveError::MaxDepthExceeded(self.max_depth))
        } else {
            Ok(())
        }
    }

    fn follow_cname(&mut self, cname: Name) -> Result<(), RecursiveError> {
        if self.cname_chain.contains(&cname) {
            return Err(RecursiveError::CnameLoop(cname));
        }
        
        self.cname_chain.push(self.current_query.name().clone());
        self.current_query = Query::query(cname, self.current_query.query_type());
        Ok(())
    }
}

/// Errors that can occur during recursive resolution
#[derive(Debug, thiserror::Error)]
pub enum RecursiveError {
    #[error("Maximum recursion depth exceeded: {0}")]
    MaxDepthExceeded(u8),
    
    #[error("CNAME loop detected for {0}")]
    CnameLoop(Name),
    
    #[error("No nameservers available")]
    NoNameservers,
    
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),
    
    #[error("Client error: {0}")]
    Client(#[from] DnsClientError),
    
    #[error("Timeout")]
    Timeout,
}

/// A recursive DNS resolver that implements the full DNS resolution algorithm
///
/// This resolver starts from the root nameservers and follows referrals until
/// it finds an authoritative answer or encounters an error. It properly handles:
/// - NS referrals with glue records
/// - CNAME following
/// - Loop detection  
/// - Authority delegation
/// - Timeout handling
#[derive(Debug, Clone)]
pub struct RecursiveResolver<S> {
    service: S,
    config: Arc<RecursiveConfig>,
}

impl<S> RecursiveResolver<S>
where
    S: Service<DnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    /// Create a new recursive resolver with the given service and configuration
    pub fn new(service: S, config: RecursiveConfig) -> Self {
        Self {
            service,
            config: Arc::new(config),
        }
    }

    /// Create a new recursive resolver with default configuration
    pub fn with_defaults(service: S) -> Self {
        Self::new(service, RecursiveConfig::default())
    }

    /// Resolve a DNS query recursively
    pub async fn resolve(&self, request: DnsRequest) -> Result<DnsResponse, RecursiveError> {
        let queries = request.queries();
        if queries.is_empty() {
            return Err(RecursiveError::ResolutionFailed("No queries in request".to_string()));
        }

        let query = queries[0].clone();
        let mut context = ResolutionContext::new(
            query,
            self.config.max_depth,
            self.config.root_hints.clone(),
        );

        self.resolve_recursive(request, &mut context).await
    }

    async fn resolve_recursive(
        &self,
        mut request: DnsRequest,
        context: &mut ResolutionContext,
    ) -> Result<DnsResponse, RecursiveError> {
        context.next_depth()?;
        
        trace!(
            depth = context.depth,
            query = %context.current_query,
            nameservers = ?context.nameservers,
            "Starting recursive resolution"
        );

        // Update request with current query
        let mut message = Message::new();
        message.set_id(request.id());
        message.add_query(context.current_query.clone());
        message.set_recursion_desired(false); // We handle recursion ourselves
        
        request = DnsRequest::new(message, request.options().clone());

        // Try to query the nameservers
        match self.query_nameservers(&request, &context.nameservers).await {
            Ok(response) => {
                return self.process_response(response, request.clone(), context).await;
            }
            Err(e) => {
                warn!(nameservers = ?context.nameservers, error = %e, "Failed to query nameservers");
                return Err(e);
            }
        }
    }

    async fn query_nameservers(
        &self,
        request: &DnsRequest,
        nameservers: &[String],
    ) -> Result<DnsResponse, RecursiveError> {
        if nameservers.is_empty() {
            return Err(RecursiveError::NoNameservers);
        }

        // Try each nameserver
        for ns in nameservers {
            trace!("Querying nameserver {}", ns);
            match self.query_single_nameserver(request, ns).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("Failed to query nameserver {}: {}", ns, e);
                    continue;
                }
            }
        }
        
        Err(RecursiveError::NoNameservers)
    }

    async fn query_single_nameserver(
        &self,
        request: &DnsRequest,
        nameserver: &str,
    ) -> Result<DnsResponse, RecursiveError> {
        // Parse nameserver address
        let nameserver_addr = nameserver.parse::<std::net::IpAddr>()
            .map_err(|_| RecursiveError::ResolutionFailed(format!("Invalid nameserver address: {}", nameserver)))?;

        // Create a service for this specific nameserver
        let mut targeted_service = self.create_nameserver_service(vec![nameserver_addr])?;
        
        // Apply timeout
        let response_future = targeted_service.call(request.clone());
        match tokio::time::timeout(self.config.query_timeout, response_future).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(RecursiveError::Client(e)),
            Err(_) => Err(RecursiveError::Timeout),
        }
    }

    fn create_nameserver_service(&self, nameservers: Vec<std::net::IpAddr>) -> Result<super::NameserverService, RecursiveError> {
        // Create a factory for creating nameserver services
        let factory = super::NameserverServiceFactory::with_udp();
        Ok(factory.create_service(nameservers))
    }

    async fn process_response(
        &self,
        response: DnsResponse,
        request: DnsRequest,
        context: &mut ResolutionContext,
    ) -> Result<DnsResponse, RecursiveError> {
        let response_code = response.response_code();
        let (message, _) = response.into_parts();
        
        match response_code {
            ResponseCode::NoError => {
                // Check if we have an answer
                if !message.answers().is_empty() {
                    let restored_response = DnsResponse::from_message(message)
                        .map_err(|e| RecursiveError::ResolutionFailed(format!("Protocol error: {}", e)))?;
                    return self.handle_answer_section(restored_response, context).await;
                }
                
                // Check for authority section (referral)
                if !message.name_servers().is_empty() {
                    let restored_response = DnsResponse::from_message(message)
                        .map_err(|e| RecursiveError::ResolutionFailed(format!("Protocol error: {}", e)))?;
                    return self.handle_authority_section(restored_response, request, context).await;
                }
                
                // No answer and no authority - this shouldn't happen
                Err(RecursiveError::ResolutionFailed("Empty response".to_string()))
            }
            ResponseCode::NXDomain => {
                let restored_response = DnsResponse::from_message(message)
                    .map_err(|e| RecursiveError::ResolutionFailed(format!("Protocol error: {}", e)))?;
                Ok(restored_response)
            }
            ResponseCode::Refused => {
                Err(RecursiveError::ResolutionFailed("Query refused".to_string()))
            }
            other => {
                Err(RecursiveError::ResolutionFailed(format!("Response code: {}", other)))
            }
        }
    }

    async fn handle_answer_section(
        &self,
        response: DnsResponse,
        context: &mut ResolutionContext,
    ) -> Result<DnsResponse, RecursiveError> {
        let response_id = {
            let (message, _) = response.clone().into_parts();
            message.id()
        };
        let (message, _) = response.into_parts();
        
        // Look for CNAME records that we need to follow
        for record in message.answers() {
            if record.record_type() == RecordType::CNAME 
                && record.name() == context.current_query.name() 
                && self.config.follow_cnames {
                
                let cname_data = record.data();
                if let Some(cname) = cname_data.as_cname() {
                    let cname_name = cname.0.clone();
                    debug!(
                        from = %record.name(),
                        to = %cname_name,
                        "Following CNAME"
                    );
                    
                    context.follow_cname(cname_name)?;
                    
                    // Create new request for CNAME target
                    let mut new_message = Message::new();
                    new_message.set_id(response_id);
                    new_message.add_query(context.current_query.clone());
                    new_message.set_recursion_desired(false);
                    
                    let options = hickory_proto::xfer::DnsRequestOptions::default();
                    let new_request = DnsRequest::new(new_message, options);
                    
                    // Reset nameservers to root for new resolution
                    context.nameservers = self.config.root_hints.clone();
                    return Box::pin(self.resolve_recursive(new_request, context)).await;
                }
            }
        }
        
        // We have a direct answer - restore the response
        let restored_response = DnsResponse::from_message(message)
            .map_err(|e| RecursiveError::ResolutionFailed(format!("Protocol error: {}", e)))?;
        Ok(restored_response)
    }

    async fn handle_authority_section(
        &self,
        response: DnsResponse,
        request: DnsRequest,
        context: &mut ResolutionContext,
    ) -> Result<DnsResponse, RecursiveError> {
        let (message, _) = response.into_parts();
        
        // Extract nameservers from authority section
        let mut new_nameservers = Vec::new();
        
        for record in message.name_servers() {
            if record.record_type() == RecordType::NS {
                let ns_data = record.data();
                if let Some(ns) = ns_data.as_ns() {
                    let ns_name = ns.0.clone();
                    // Look for glue records in additional section
                    for additional in message.additionals() {
                        if additional.name() == &ns_name && additional.record_type() == RecordType::A {
                            let a_data = additional.data();
                            if let Some(a) = a_data.as_a() {
                                new_nameservers.push(a.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        if new_nameservers.is_empty() {
            return Err(RecursiveError::ResolutionFailed(
                "No usable nameservers in referral".to_string()
            ));
        }
        
        debug!(nameservers = ?new_nameservers, "Following referral");
        context.nameservers = new_nameservers;
        
        Box::pin(self.resolve_recursive(request, context)).await
    }
}

/// An opaque future type for recursive resolver responses
pub struct RecursiveFuture {
    inner: BoxFuture<'static, Result<DnsResponse, DnsClientError>>,
}

impl std::future::Future for RecursiveFuture {
    type Output = Result<DnsResponse, DnsClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// Tower service wrapper for recursive DNS resolution
///
/// This service implements the Tower service trait and can be used in service
/// stacks with other middleware layers.
#[derive(Debug, Clone)]
pub struct RecursiveService<R, S> {
    resolver: RecursiveResolver<R>,
    inner: S,
}

impl<R, S> RecursiveService<R, S> {
    /// Create a new recursive service wrapping the given inner service
    pub fn new(resolver: RecursiveResolver<R>, inner: S) -> Self {
        Self { resolver, inner }
    }
}

impl<R, S> Service<DnsRequest> for RecursiveService<R, S>
where
    R: Service<DnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone + Send + Sync + 'static,
    R::Future: Send + 'static,
    S: Service<DnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;
    type Error = DnsClientError;
    type Future = RecursiveFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: DnsRequest) -> Self::Future {
        let resolver = self.resolver.clone();
        let mut inner = self.inner.clone();
        
        let future = async move {
            // Check if recursion is desired
            if request.recursion_desired() {
                match resolver.resolve(request.clone()).await {
                    Ok(response) => Ok(response),
                    Err(RecursiveError::Client(e)) => Err(e),
                    Err(e) => {
                        error!(error = %e, "Recursive resolution failed");
                        // Fallback to inner service
                        inner.call(request).await
                    }
                }
            } else {
                // Pass through to inner service for non-recursive queries
                inner.call(request).await
            }
        };

        RecursiveFuture {
            inner: future.boxed(),
        }
    }
}

/// Tower layer for adding recursive DNS resolution
///
/// This layer can be used in a service stack to provide recursive resolution
/// capabilities to any DNS service.
///
/// # Examples
///
/// ```rust,ignore
/// use tower::ServiceBuilder;
/// 
/// let recursive_layer = RecursiveLayer::new(nameserver_service, config);
/// let service = ServiceBuilder::new()
///     .layer(recursive_layer)
///     .service(dns_service);
/// ```
#[derive(Debug, Clone)]
pub struct RecursiveLayer<R> {
    resolver: RecursiveResolver<R>,
}

impl<R> RecursiveLayer<R>
where
    R: Service<DnsRequest, Response = DnsResponse, Error = DnsClientError> + Clone + Send + Sync + 'static,
    R::Future: Send + 'static,
{
    /// Create a new recursive layer with the given service and configuration
    pub fn new(service: R, config: RecursiveConfig) -> Self {
        Self {
            resolver: RecursiveResolver::new(service, config),
        }
    }

    /// Create a new recursive layer with default configuration
    pub fn with_defaults(service: R) -> Self {
        Self {
            resolver: RecursiveResolver::with_defaults(service),
        }
    }
}

impl<R, S> tower::Layer<S> for RecursiveLayer<R>
where
    R: Clone,
{
    type Service = RecursiveService<R, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RecursiveService::new(self.resolver.clone(), inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn test_resolution_context_creation() {
        let query = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let root_hints = vec!["192.0.2.1".to_string()];
        let context = ResolutionContext::new(query.clone(), 10, root_hints.clone());
        
        assert_eq!(context.original_query, query);
        assert_eq!(context.current_query, query);
        assert_eq!(context.depth, 0);
        assert_eq!(context.max_depth, 10);
        assert_eq!(context.nameservers, root_hints);
        assert!(context.cname_chain.is_empty());
    }

    #[test]
    fn test_depth_tracking() {
        let query = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let mut context = ResolutionContext::new(query, 2, vec![]);
        
        assert!(context.next_depth().is_ok());
        assert_eq!(context.depth, 1);
        
        assert!(context.next_depth().is_ok());
        assert_eq!(context.depth, 2);
        
        assert!(matches!(context.next_depth(), Err(RecursiveError::MaxDepthExceeded(2))));
    }

    #[test]
    fn test_cname_loop_detection() {
        let query = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let mut context = ResolutionContext::new(query, 10, vec![]);
        
        let cname1 = Name::from_ascii("alias1.example.com").unwrap();
        let cname2 = Name::from_ascii("alias2.example.com").unwrap();
        
        assert!(context.follow_cname(cname1.clone()).is_ok());
        assert!(context.follow_cname(cname2).is_ok());
        
        // This should detect the loop
        assert!(matches!(
            context.follow_cname(cname1),
            Err(RecursiveError::CnameLoop(_))
        ));
    }
}