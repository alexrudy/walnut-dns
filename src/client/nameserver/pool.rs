use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use future_eyeballs::{EyeballConfiguration, EyeballSet, HappyEyeballsError};
use futures::future::BoxFuture;
use hickory_proto::op::Message;
use serde::Deserialize;
use tower::ServiceExt;
use tracing::Instrument as _;

use crate::client::DnsClientError;

use super::Nameserver;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Deserialize)]
pub enum PoolStrategy {
    ConnectionStats,
    RoundRobin,
    UserProvidedOrder,
}

#[derive(Debug, Clone)]
pub struct Pool {
    inner: Arc<InnerPool>,
}

impl Pool {
    pub fn new(servers: Vec<Nameserver>, config: PoolConfig) -> Self {
        let config = Arc::new(config);
        Self {
            inner: Arc::new(InnerPool {
                servers,
                config,
                index: AtomicUsize::new(0),
            }),
        }
    }
}

impl tower::Service<Message> for Pool {
    type Response = Message;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<Message, DnsClientError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.inner.servers.is_empty() {
            Poll::Ready(Err(DnsClientError::Unavailable("No nameservers".into())))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move { inner.send(req).await })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PoolConfig {
    pub num_concurrent_requests: usize,
    pub attempt_delay: Duration,
    pub strategy: PoolStrategy,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            num_concurrent_requests: 1,
            attempt_delay: Duration::from_millis(150),
            strategy: PoolStrategy::ConnectionStats,
        }
    }
}

impl PoolConfig {
    pub fn num_concurrent_requests(&self) -> usize {
        self.num_concurrent_requests.max(1)
    }
}

struct InnerPool {
    servers: Vec<Nameserver>,
    config: Arc<PoolConfig>,
    index: AtomicUsize,
}

impl fmt::Debug for InnerPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerPool")
            .field("servers", &self.servers)
            .finish()
    }
}

impl InnerPool {
    async fn send(&self, request: Message) -> Result<Message, DnsClientError> {
        let mut nameservers = self.servers.clone();

        match self.config.strategy {
            PoolStrategy::ConnectionStats => {
                nameservers.sort_unstable_by(|a, b| match (a.stats(), b.stats()) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (Some(a), Some(b)) => a.cmp(b),
                });
            }
            PoolStrategy::RoundRobin => {
                let first = self.index.fetch_add(1, Ordering::Relaxed) % nameservers.len();
                nameservers.rotate_left(first);
            }
            PoolStrategy::UserProvidedOrder => {}
        };

        let configuration = EyeballConfiguration {
            concurrent_start_delay: Some(self.config.attempt_delay),
            maximum_concurrency: Some(self.config.num_concurrent_requests()),
            initial_concurrency: Some(self.config.num_concurrent_requests()),
            ..Default::default()
        };

        tracing::trace!(maximum_concurrency=?configuration.maximum_concurrency, "Eyeball Set");

        let mut eyeballs = EyeballSet::new(configuration);

        for conn in nameservers {
            let span = tracing::info_span!("nameserver", conn.addr=%conn.address());
            eyeballs.push(conn.oneshot(request.clone().into()).instrument(span));
        }

        match eyeballs.await {
            Ok(outcome) => Ok(outcome.into()),
            Err(HappyEyeballsError::Error(client_error)) => Err(client_error),
            Err(HappyEyeballsError::NoProgress) => Err(DnsClientError::Closed),
            Err(HappyEyeballsError::Timeout(_)) => Err(DnsClientError::Closed),
            Err(_) => panic!("Unexpected error"),
        }
    }
}
