//! A single, re-usable connection. Similar to a pooled connection, but if the pool only ever had one spot.

use std::collections::VecDeque;
use std::fmt;
use std::ops::Deref;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::task::Poll;
use std::task::ready;

use chateau::client::conn::Connection;
use chateau::client::conn::Protocol;
use chateau::client::conn::Transport;

use tokio::sync::{oneshot, watch};
use tracing::Instrument as _;

use super::DnsClientError;
use super::codec::TaggedMessage;
use super::nameserver::ConnectionStatus;
use super::nameserver::NameserverConnection;

enum ConnectionState<C> {
    None,
    Idle(C),
    Busy,
}

impl<C> fmt::Debug for ConnectionState<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::None => write!(f, "None"),
            ConnectionState::Idle(_) => write!(f, "Idle"),
            ConnectionState::Busy => write!(f, "Busy"),
        }
    }
}

struct InnerConnector<C> {
    connection: ConnectionState<C>,
    waiters: VecDeque<oneshot::Sender<C>>,
}

impl<C> fmt::Debug for InnerConnector<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("connection", &self.connection)
            .field("waiters", &self.waiters.len())
            .finish()
    }
}

impl<C> InnerConnector<C> {
    fn new() -> Self {
        Self {
            connection: ConnectionState::None,
            waiters: VecDeque::new(),
        }
    }

    fn close(&mut self) {
        self.connection = ConnectionState::None;
        self.waiters.clear();
    }

    fn push(&mut self, mut connection: C) {
        loop {
            connection = if let Some(sender) = self.waiters.pop_front() {
                match sender.send(connection) {
                    Ok(()) => return,
                    Err(conn) => conn,
                }
            } else {
                self.connection = ConnectionState::Idle(connection);
                return;
            };
        }
    }
}

pub struct DnsConnector<A, T, P>
where
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage>,
{
    address: A,
    transport: T,
    protocol: P,

    #[allow(clippy::type_complexity)]
    connection: Arc<Mutex<InnerConnector<<P as Protocol<T::IO, TaggedMessage>>::Connection>>>,
}

impl<A, T, P> fmt::Debug for DnsConnector<A, T, P>
where
    A: fmt::Debug,
    T: Transport<A> + fmt::Debug,
    P: Protocol<T::IO, TaggedMessage> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsConnector")
            .field("address", &self.address)
            .field("transport", &self.transport)
            .field("protocol", &self.protocol)
            .field("connection", &self.connection)
            .finish()
    }
}

impl<A, T, P> Clone for DnsConnector<A, T, P>
where
    A: Clone,
    T: Transport<A> + Clone,
    P: Protocol<T::IO, TaggedMessage> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            transport: self.transport.clone(),
            protocol: self.protocol.clone(),
            connection: self.connection.clone(),
        }
    }
}

type DnsConnectionError<A, T, P> = ConnectionError<
    <T as Transport<A>>::Error,
    <P as Protocol<<T as Transport<A>>::IO, TaggedMessage>>::Error,
>;

impl<A, T, P> DnsConnector<A, T, P>
where
    A: Clone,
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage> + Clone,
{
    pub fn new(address: A, transport: T, protocol: P) -> Self {
        Self {
            address,
            transport,
            protocol,
            connection: Arc::new(Mutex::new(InnerConnector::new())),
        }
    }

    pub fn connect(&mut self) -> Connecting<A, T, P> {
        let state = {
            let mut inner = self.connection.lock().expect("poisoned");
            match std::mem::replace(&mut inner.connection, ConnectionState::Busy) {
                ConnectionState::None => {
                    let protocol = self.protocol.clone();
                    let protocol = std::mem::replace(&mut self.protocol, protocol);
                    ConnectingState::Transport {
                        future: self.transport.connect(self.address.clone()),
                        protocol,
                    }
                }
                ConnectionState::Idle(c) => ConnectingState::Connection {
                    connection: Some(c),
                },
                ConnectionState::Busy => {
                    let (tx, rx) = oneshot::channel();
                    inner.waiters.push_back(tx);
                    ConnectingState::Waiting { channel: rx }
                }
            }
        };

        Connecting {
            state,
            inner: Arc::downgrade(&self.connection),
        }
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), DnsConnectionError<A, T, P>>> {
        let inner = self.connection.lock().expect("poisoned");

        // Check if we already have a connection, no need to backpressure connector.
        if matches!(inner.connection, ConnectionState::None) {
            ready!(self.transport.poll_ready(cx)).map_err(ConnectionError::Transport)?;
            ready!(<P as Protocol<T::IO, TaggedMessage>>::poll_ready(
                &mut self.protocol,
                cx
            ))
            .map_err(ConnectionError::Protocol)?;
        }
        Poll::Ready(Ok(()))
    }
}

#[pin_project::pin_project(project=StateProjection)]
enum ConnectingState<A, T, P>
where
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage>,
{
    Waiting {
        #[pin]
        channel: oneshot::Receiver<P::Connection>,
    },
    Connection {
        connection: Option<P::Connection>,
    },
    Transport {
        #[pin]
        future: T::Future,
        protocol: P,
    },
    Protocol {
        #[pin]
        future: <P as Protocol<T::IO, TaggedMessage>>::Future,
    },
}

impl<A, T, P> fmt::Debug for ConnectingState<A, T, P>
where
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectingState::Waiting { .. } => f.write_str("State::Waiting"),
            ConnectingState::Connection { .. } => f.write_str("State::Connection"),
            ConnectingState::Transport { .. } => f.write_str("State::Transport"),
            ConnectingState::Protocol { .. } => f.write_str("State::Protocol"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError<TE, PE> {
    #[error("Connection dropped")]
    #[allow(dead_code)]
    ConnectionDropped,

    #[error("Transport: {0}")]
    Transport(#[source] TE),

    #[error("Protocol: {0}")]
    Protocol(#[source] PE),
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct Connecting<A, T, P>
where
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage>,
{
    #[pin]
    state: ConnectingState<A, T, P>,

    #[allow(clippy::type_complexity)]
    inner: Weak<Mutex<InnerConnector<<P as Protocol<T::IO, TaggedMessage>>::Connection>>>,
}

impl<A, T, P> Future for Connecting<A, T, P>
where
    T: Transport<A>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    P: Protocol<T::IO, TaggedMessage>,
    <P as Protocol<T::IO, TaggedMessage>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Output = Result<DnsConnection<P::Connection>, DnsClientError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                StateProjection::Waiting { channel } => match ready!(channel.poll(cx)) {
                    Ok(connection) => {
                        return Poll::Ready(Ok(DnsConnection::new(connection, this.inner.clone())));
                    }
                    Err(_) => {
                        return Poll::Ready(Err(DnsClientError::Closed));
                    }
                },
                StateProjection::Connection { connection } => {
                    return Poll::Ready(Ok(DnsConnection::new(
                        connection.take().expect("connection stolen"),
                        this.inner.clone(),
                    )));
                }
                StateProjection::Transport { future, protocol } => match ready!(future.poll(cx)) {
                    Ok(stream) => {
                        let future = protocol.connect(stream);
                        this.state.set(ConnectingState::Protocol { future })
                    }
                    Err(error) => {
                        if let Some(inner) = this.inner.upgrade() {
                            if let Ok(mut manager) = inner.try_lock() {
                                manager.close();
                            }
                        }
                        return Poll::Ready(Err(DnsClientError::Transport(error.into())));
                    }
                },
                StateProjection::Protocol { future } => match ready!(future.poll(cx)) {
                    Ok(connection) => {
                        return Poll::Ready(Ok(DnsConnection::new(connection, this.inner.clone())));
                    }
                    Err(error) => {
                        if let Some(inner) = this.inner.upgrade() {
                            if let Ok(mut manager) = inner.try_lock() {
                                manager.close();
                            }
                        }
                        return Poll::Ready(Err(DnsClientError::Protocol(error.into())));
                    }
                },
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsConnection<C> {
    connection: Option<C>,
    inner: Weak<Mutex<InnerConnector<C>>>,
}

impl<C> DnsConnection<C> {
    fn new(connection: C, inner: Weak<Mutex<InnerConnector<C>>>) -> Self {
        DnsConnection {
            connection: Some(connection),
            inner,
        }
    }
}

impl<C> Deref for DnsConnection<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        self.connection.as_ref().unwrap()
    }
}

impl<C> DerefMut for DnsConnection<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection.as_mut().unwrap()
    }
}

impl<C> Drop for DnsConnection<C> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            if let Ok(mut conn) = inner.try_lock() {
                if let Some(idle) = self.connection.take() {
                    conn.push(idle);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsConnectorService<A, T, P>
where
    A: Clone,
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage> + Clone,
{
    connector: DnsConnector<A, T, P>,
    tx: watch::Sender<ConnectionStatus>,
    rx: watch::Receiver<ConnectionStatus>,
    protocol: hickory_proto::xfer::Protocol,
}

impl<A, T, P> DnsConnectorService<A, T, P>
where
    A: Clone,
    T: Transport<A>,
    P: Protocol<T::IO, TaggedMessage> + Clone,
{
    pub fn new(connector: DnsConnector<A, T, P>, protocol: hickory_proto::xfer::Protocol) -> Self {
        let (tx, rx) = watch::channel(ConnectionStatus::NotConnected);
        Self {
            connector,
            tx,
            rx,
            protocol,
        }
    }
}

impl<A, T, P> tower::Service<TaggedMessage> for DnsConnectorService<A, T, P>
where
    A: fmt::Debug + Clone + 'static,
    T: Transport<A> + 'static,
    P: Protocol<T::IO, TaggedMessage> + Clone + Send + 'static,
    P::Connection: Connection<TaggedMessage, Response = TaggedMessage> + Send + 'static,
{
    type Response = TaggedMessage;

    type Error = DnsClientError;

    type Future = DnsConnectorServiceFuture;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connector
            .poll_ready(cx)
            .map_err(|error| DnsClientError::Protocol(error.into()))
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        let span = tracing::debug_span!("dns", address=?self.connector.address);
        let connecting = self.connector.connect();
        let status = self.tx.clone();

        DnsConnectorServiceFuture(Box::pin(
            async move {
                let mut conn = match connecting.await {
                    Ok(conn) => {
                        let _ = status.send(ConnectionStatus::Connected);
                        conn
                    }
                    Err(error) => {
                        let _ = status.send(ConnectionStatus::Failed);
                        return Err(error);
                    }
                };
                conn.send_request(req)
                    .await
                    .map_err(|error| DnsClientError::Protocol(error.into()))
            }
            .instrument(span),
        ))
    }
}

impl<A, T, P> NameserverConnection for DnsConnectorService<A, T, P>
where
    A: fmt::Debug + Clone + 'static,
    T: Transport<A> + 'static,
    P: Protocol<T::IO, TaggedMessage> + Clone + Send + 'static,
    P::Connection: Connection<TaggedMessage, Response = TaggedMessage> + Send + 'static,
{
    fn status(&self) -> super::nameserver::ConnectionStatus {
        *self.rx.borrow()
    }

    fn protocol(&self) -> hickory_proto::xfer::Protocol {
        self.protocol
    }
}

pub struct DnsConnectorServiceFuture(
    Pin<Box<dyn Future<Output = Result<TaggedMessage, DnsClientError>> + Send>>,
);

impl Future for DnsConnectorServiceFuture {
    type Output = Result<TaggedMessage, DnsClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
