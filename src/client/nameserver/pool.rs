use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, atomic::AtomicUsize},
    task::{Context, Poll},
    time::Duration,
};

use future_eyeballs::{EyeballConfiguration, EyeballSet, HappyEyeballsError};
use futures::future::BoxFuture;
use hickory_proto::op::Message;
use tower::ServiceExt;

use crate::client::DNSClientError;

use super::NameServerConnection;

#[derive(Debug, Clone)]
pub struct NameserverPool {
    inner: Arc<InnerPool>,
}

impl NameserverPool {
    pub fn new(mut connections: Vec<NameServerConnection>, config: PoolConfig) -> Self {
        connections.sort_by(|a, b| a.config.protocol.cmp(&b.config.protocol).reverse());
        Self {
            inner: Arc::new(InnerPool {
                servers: connections.into(),
                config: Arc::new(config),
                index: AtomicUsize::new(0),
            }),
        }
    }
}

impl tower::Service<Message> for NameserverPool {
    type Response = Message;
    type Error = DNSClientError;
    type Future = BoxFuture<'static, Result<Message, DNSClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.inner.servers.is_empty() {
            Poll::Ready(Err(DNSClientError::Unavailable("No nameservers".into())))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move { inner.send(req).await })
    }
}

pub struct PoolConfig {
    pub num_concurrent_requests: usize,
    pub attempt_delay: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            num_concurrent_requests: 1,
            attempt_delay: Duration::from_millis(150),
        }
    }
}

impl PoolConfig {
    pub fn num_concurrent_requests(&self) -> usize {
        self.num_concurrent_requests.max(1)
    }
}

struct InnerPool {
    servers: VecDeque<NameServerConnection>,
    config: Arc<PoolConfig>,
    index: AtomicUsize,
}

impl fmt::Debug for InnerPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerPool")
            .field("servers", &self.servers)
            .field("index", &self.index)
            .finish()
    }
}

impl InnerPool {
    async fn send(&self, request: Message) -> Result<Message, DNSClientError> {
        let mut conns = self.servers.clone();
        if self.config.num_concurrent_requests() < conns.len() {
            let idx = self
                .index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % self.servers.len();
            conns.rotate_left(idx);
        };

        let configuration = EyeballConfiguration {
            concurrent_start_delay: Some(self.config.attempt_delay),
            maximum_concurrency: Some(self.config.num_concurrent_requests()),
            initial_concurrency: Some(1),
            ..Default::default()
        };

        tracing::trace!(maximum_concurrency=?configuration.maximum_concurrency, "Eyeball Set");

        let mut eyeballs = EyeballSet::new(configuration);

        for conn in conns {
            eyeballs.push(conn.service.oneshot(request.clone().into()));
        }

        match eyeballs.await {
            Ok(outcome) => Ok(outcome.into()),
            Err(HappyEyeballsError::Error(client_error)) => Err(client_error),
            Err(HappyEyeballsError::NoProgress) => Err(DNSClientError::Closed),
            Err(HappyEyeballsError::Timeout(_)) => Err(DNSClientError::Closed),
            Err(_) => panic!("Unexpected error"),
        }
    }
}
