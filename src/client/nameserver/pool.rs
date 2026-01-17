use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use future_eyeballs::{EyeballConfiguration, EyeballSet, HappyEyeballsError};
use futures::future::BoxFuture;
use hickory_proto::op::Message;
use tower::ServiceExt;

use crate::client::{DnsClientError, codec::TaggedMessage};

use super::{NameServerConnection, ProtocolConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PriorityTier {
    Connected = 1,
    Connectionless,
    NotConnected,
    Failing,
}

#[derive(Debug)]
pub struct ConnectionSpeed {
    average: AtomicU64,
    smoothing: u64,
}

impl PartialEq for ConnectionSpeed {
    fn eq(&self, other: &Self) -> bool {
        self.average.load(Ordering::Relaxed) == other.average.load(Ordering::Relaxed)
    }
}

impl Eq for ConnectionSpeed {}

impl PartialOrd for ConnectionSpeed {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConnectionSpeed {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.average
            .load(Ordering::Relaxed)
            .cmp(&other.average.load(Ordering::Relaxed))
    }
}

// Generally, DNS should respond in less than 100ms, so this is a good conservative default.
const BASELINE_RESPONSE_MS: u64 = 100;

impl Default for ConnectionSpeed {
    fn default() -> Self {
        Self {
            average: AtomicU64::new(BASELINE_RESPONSE_MS),
            smoothing: 10,
        }
    }
}

impl ConnectionSpeed {
    /// Updates the average response time based on the given duration.
    pub fn update(&self, duration: Duration) {
        let current = self.average.load(Ordering::Acquire);
        let update = (duration.as_millis() - current as u128) / (self.smoothing as u128);

        let new = current + (update as u64);
        // Note: Missed updates are okay
        let _ = self
            .average
            .compare_exchange(current, new, Ordering::Release, Ordering::Relaxed);
    }

    /// Returns the current average response time in milliseconds.
    #[allow(dead_code)]
    pub fn get(&self) -> u64 {
        self.average.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct AtomicPriorityTier(AtomicUsize);

impl PartialEq for AtomicPriorityTier {
    fn eq(&self, other: &Self) -> bool {
        self.0.load(Ordering::Relaxed) == other.0.load(Ordering::Relaxed)
    }
}

impl Eq for AtomicPriorityTier {}

impl Ord for AtomicPriorityTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .load(Ordering::Relaxed)
            .cmp(&other.0.load(Ordering::Relaxed))
    }
}

impl PartialOrd for AtomicPriorityTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AtomicPriorityTier {
    pub fn new(tier: PriorityTier) -> Self {
        Self(AtomicUsize::new(tier as usize))
    }

    pub fn for_protocol(protocol: &ProtocolConfig) -> Self {
        match protocol {
            ProtocolConfig::Udp => Self::new(PriorityTier::Connectionless),
            _ => Self::new(PriorityTier::NotConnected),
        }
    }

    pub fn get(&self) -> PriorityTier {
        match self.0.load(Ordering::Relaxed) {
            1 => PriorityTier::Connected,
            2 => PriorityTier::Connectionless,
            3 => PriorityTier::NotConnected,
            4 => PriorityTier::Failing,
            _ => unreachable!(),
        }
    }

    pub fn reset(&self, protocol: &ProtocolConfig) {
        match protocol {
            ProtocolConfig::Udp => self.set(PriorityTier::Connectionless),
            _ => self.set(PriorityTier::NotConnected),
        }
    }

    pub fn connected(&self, protocol: &ProtocolConfig) {
        match protocol {
            ProtocolConfig::Udp => self.set(PriorityTier::Connectionless),
            _ => self.set(PriorityTier::Connected),
        }
    }

    pub fn set(&self, tier: PriorityTier) {
        self.0.store(tier as usize, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct NameserverPool {
    inner: Arc<InnerPool>,
}

impl NameserverPool {
    pub fn new(connections: Vec<NameServerConnection>, config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(InnerPool {
                servers: connections
                    .into_iter()
                    .map(|c| PooledConnection::new(c))
                    .collect(),
                config: Arc::new(config),
            }),
        }
    }
}

impl tower::Service<Message> for NameserverPool {
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

#[derive(Debug, Clone)]
pub struct PooledConnection {
    inner: NameServerConnection,
    priority: Arc<AtomicPriorityTier>,
    speed: Arc<ConnectionSpeed>,
    active: Arc<AtomicUsize>,
}

impl PooledConnection {
    pub fn new(inner: NameServerConnection) -> Self {
        let priority = AtomicPriorityTier::for_protocol(&inner.config.protocol).into();
        Self {
            inner,
            priority,
            speed: ConnectionSpeed::default().into(),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl PartialEq for PooledConnection {
    fn eq(&self, other: &Self) -> bool {
        self.priority.get() == other.priority.get()
            && self.active.load(Ordering::Relaxed) == other.active.load(Ordering::Relaxed)
            && self.speed == other.speed
    }
}

impl Eq for PooledConnection {}

impl PartialOrd for PooledConnection {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PooledConnection {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .get()
            .cmp(&other.priority.get())
            .then(
                self.active
                    .load(Ordering::Relaxed)
                    .cmp(&other.active.load(Ordering::Relaxed)),
            )
            .then(self.speed.cmp(&other.speed))
    }
}

impl tower::Service<TaggedMessage> for PooledConnection {
    type Response = TaggedMessage;
    type Error = DnsClientError;
    type Future = BoxFuture<'static, Result<TaggedMessage, DnsClientError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.service.poll_ready(cx)
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        let new = self.clone();
        let mut current = std::mem::replace(self, new);
        current.active.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let start = Instant::now();
            let response = current.inner.service.call(req).await;
            current.speed.update(start.elapsed());
            if response.is_err() {
                current.priority.set(PriorityTier::Failing);
            } else if current.priority.get() == PriorityTier::Failing {
                current.priority.reset(&current.inner.config.protocol);
            } else {
                current.priority.connected(&current.inner.config.protocol);
            }
            current.active.fetch_sub(1, Ordering::Relaxed);

            response
        })
    }
}

struct InnerPool {
    servers: Vec<PooledConnection>,
    config: Arc<PoolConfig>,
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
        let mut conns = self.servers.clone();
        conns.sort_unstable();

        let configuration = EyeballConfiguration {
            concurrent_start_delay: Some(self.config.attempt_delay),
            maximum_concurrency: Some(self.config.num_concurrent_requests()),
            initial_concurrency: Some(1),
            ..Default::default()
        };

        tracing::trace!(maximum_concurrency=?configuration.maximum_concurrency, "Eyeball Set");

        let mut eyeballs = EyeballSet::new(configuration);

        for conn in conns {
            eyeballs.push(conn.oneshot(request.clone().into()));
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
