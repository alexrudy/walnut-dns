mod connection;
mod monitor;
mod pool;

use std::{
    cmp::Ordering,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use hickory_proto::xfer::Protocol;
use serde::Deserialize;
use tracing::Instrument as _;

pub use self::connection::{
    ConnectionConfig, NameServerConnection, NameserverConfig, ProtocolConfig,
};
use self::monitor::{ConnectionStats, MonitoredConnection, PriorityTier};
pub use self::pool::{Pool, PoolConfig};

use super::{DnsClientError, codec::TaggedMessage};

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionPolicy {
    /// Should disable UDP protocol and require connection-based protocols?
    pub disable_udp: bool,

    /// Should we optimistically connect to encrypted protocols?
    pub optimistic_encryption: bool,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            disable_udp: false,
            optimistic_encryption: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Nameserver {
    connections: Vec<MonitoredConnection<NameServerConnection>>,
    address: IpAddr,
    policy: ConnectionPolicy,
}

impl Nameserver {
    pub fn new(configuration: NameserverConfig) -> Self {
        Self {
            connections: configuration
                .connections
                .into_iter()
                .map(|cfg| {
                    let protocol = cfg.protocol.protocol();
                    MonitoredConnection::new(
                        NameServerConnection::from_config(configuration.address, &cfg),
                        &protocol,
                    )
                })
                .collect(),
            address: configuration.address,
            policy: configuration.policy,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn stats(&self) -> Option<&ConnectionStats> {
        self.connections.iter().map(|conn| conn.monitor()).min()
    }

    fn select_connection(&mut self) -> Option<&mut MonitoredConnection<NameServerConnection>> {
        self.connections
            .iter_mut()
            .filter(|conn| !(self.policy.disable_udp && *conn.protocol() == Protocol::Udp))
            .min_by(|a, b| {
                match (a.monitor().priority(), b.monitor().priority()) {
                    (PriorityTier::Connected, _) => {
                        return Ordering::Less;
                    }
                    (_, PriorityTier::Connected) => {
                        return Ordering::Less;
                    }
                    _ => {}
                };

                if self.policy.optimistic_encryption {
                    if a.protocol().is_encrypted() {
                        return Ordering::Less;
                    } else if b.protocol().is_encrypted() {
                        return Ordering::Greater;
                    }
                }

                a.monitor().cmp(b.monitor())
            })
    }
}

impl tower::Service<TaggedMessage> for Nameserver {
    type Response = TaggedMessage;

    type Error = DnsClientError;

    type Future = NameserverFuture;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        let addr = self.address();
        let conn = self.select_connection();

        if let Some(conn) = conn {
            let span = tracing::info_span!("dns_request", dns.address=%addr, dns.protocol=%conn.protocol());

            let future = conn.call(req);
            return NameserverFuture(Box::pin(
                async move {
                    let result = future.await;
                    if result.is_err() {
                        tracing::error!("dns request error");
                    } else {
                        tracing::debug!("dns response recieved");
                    }
                    result
                }
                .instrument(span),
            ));
        } else {
            return NameserverFuture(Box::pin(async move {
                Err(DnsClientError::Unavailable(format!(
                    "No connections available for nameserver {addr}"
                )))
            }));
        }
    }
}

pub struct NameserverFuture(BoxFuture<'static, Result<TaggedMessage, DnsClientError>>);

impl Future for NameserverFuture {
    type Output = Result<TaggedMessage, DnsClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
