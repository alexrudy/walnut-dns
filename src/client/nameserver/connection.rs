use std::{fmt, ops::Deref};

use futures::future::BoxFuture;
use hickory_proto::xfer::Protocol;

use crate::client::{DnsClientError, codec::TaggedMessage};

#[derive(Debug, Clone, Copy)]
pub enum ConnectionStatus {
    NotConnected,
    Connected,
    #[allow(dead_code)]
    Closed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct BoxFutureService<S>(S);

impl<S> BoxFutureService<S> {
    pub fn new(service: S) -> Self {
        Self(service)
    }
}

impl<S> Deref for BoxFutureService<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, Req> tower::Service<Req> for BoxFutureService<S>
where
    S: tower::Service<Req>,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = S::Response;

    type Error = DnsClientError;

    type Future = BoxFuture<'static, Result<S::Response, DnsClientError>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0
            .poll_ready(cx)
            .map_err(|error| DnsClientError::Service(error.into()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let fut = self.0.call(req);
        Box::pin(async move {
            fut.await
                .map_err(|error| DnsClientError::Service(error.into()))
        })
    }
}

pub trait NameserverConnection {
    fn status(&self) -> ConnectionStatus;
    fn protocol(&self) -> Protocol;
}

impl<S> NameserverConnection for BoxFutureService<S>
where
    S: NameserverConnection + tower::Service<TaggedMessage, Response = TaggedMessage>,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn status(&self) -> ConnectionStatus {
        self.0.status()
    }

    fn protocol(&self) -> Protocol {
        self.0.protocol()
    }
}

/// A [`Service`] that can be cloned, sent, and shared across threads.
pub struct SharedNameserverService(
    Box<
        dyn CloneService<
                Response = TaggedMessage,
                Error = DnsClientError,
                Future = BoxFuture<'static, Result<TaggedMessage, DnsClientError>>,
            > + Send
            + Sync
            + 'static,
    >,
);
impl SharedNameserverService {
    /// Create a new `SharedService` from a `Service`.
    pub fn new<S>(service: S) -> Self
    where
        S: NameserverConnection
            + tower::Service<TaggedMessage, Response = TaggedMessage>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(Box::new(BoxFutureService::new(service)))
    }

    /// Create a layer which wraps a `Service` in a `SharedService`.
    #[allow(dead_code)]
    pub fn layer<S>() -> impl tower::layer::Layer<S, Service = SharedNameserverService>
    where
        S: NameserverConnection
            + tower::Service<TaggedMessage, Response = TaggedMessage>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        tower::layer::layer_fn(Self::new)
    }
}

impl tower::Service<TaggedMessage> for SharedNameserverService {
    type Response = TaggedMessage;

    type Error = DnsClientError;

    type Future = BoxFuture<'static, Result<TaggedMessage, DnsClientError>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        self.0.call(req)
    }
}

impl NameserverConnection for SharedNameserverService {
    fn status(&self) -> ConnectionStatus {
        self.0.status()
    }

    fn protocol(&self) -> Protocol {
        self.0.protocol()
    }
}

impl Clone for SharedNameserverService {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

trait CloneService: tower::Service<TaggedMessage> + NameserverConnection {
    fn clone_box(
        &self,
    ) -> Box<
        dyn CloneService<Response = Self::Response, Error = Self::Error, Future = Self::Future>
            + Send
            + Sync
            + 'static,
    >;
}

impl<T> CloneService for T
where
    T: tower::Service<TaggedMessage> + NameserverConnection + Clone + Send + Sync + 'static,
{
    fn clone_box(
        &self,
    ) -> Box<
        dyn CloneService<Response = Self::Response, Error = Self::Error, Future = Self::Future>
            + Send
            + Sync
            + 'static,
    > {
        Box::new(self.clone())
    }
}

impl fmt::Debug for SharedNameserverService {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SharedNameserverService").finish()
    }
}
