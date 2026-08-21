use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use hickory_proto::op::ResponseCode;
use tracing::trace;

use crate::authority::{LookupError, Search};
use crate::cache::QueryLookup;
use crate::error::HickoryError;
use crate::messages::{DnsQuery, Message};
use crate::{Catalog, Lookup};

pub mod connection;
pub mod request;
pub mod response;
pub mod stream;
pub mod udp;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A layer for applying metadata like the request ID and OpCode
/// between the request and response.
#[derive(Debug, Clone)]
pub struct MessageMetadataLayer {
    _priv: (),
}

impl MessageMetadataLayer {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> tower::layer::Layer<S> for MessageMetadataLayer {
    type Service = MessageMetadata<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MessageMetadata { inner }
    }
}

/// Service for copying message metadata between requests and responses.
#[derive(Debug, Clone)]
pub struct MessageMetadata<S> {
    inner: S,
}

impl<S> tower::Service<Message> for MessageMetadata<S>
where
    S: tower::Service<Message, Response = Message, Error = HickoryError> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Message;

    type Error = HickoryError;

    type Future = BoxFuture<'static, Result<Message, HickoryError>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let service = self.inner.clone();
        let mut service = std::mem::replace(&mut self.inner, service);

        let id = req.id();
        let op_code = req.op_code();

        Box::pin(async move {
            let response = match service.call(req).await {
                Ok(mut message) => {
                    message.set_op_code(op_code);
                    message.set_id(id);
                    message
                }
                Err(HickoryError::LookupError(LookupError::ResponseCode(code))) => {
                    Message::error_msg(id, op_code, code)
                }
                Err(error) => {
                    return Err(error);
                }
            };

            Ok(response)
        })
    }
}

#[derive(Debug, Clone)]
pub struct ValidateLookupLayer {
    _priv: (),
}

impl ValidateLookupLayer {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> tower::Layer<S> for ValidateLookupLayer {
    type Service = ValidateLookup<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ValidateLookup { inner }
    }
}

/// A service that validates an incoming request as a DNS Query,
/// ensuring that it has one query exactly, and otherwise returning
/// a FormErr response.
#[derive(Debug, Clone)]
pub struct ValidateLookup<S> {
    inner: S,
}

impl<S> tower::Service<Message> for ValidateLookup<S>
where
    S: tower::Service<DnsQuery, Response = QueryLookup> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<HickoryError>,
{
    type Response = Message;

    type Error = HickoryError;

    type Future = BoxFuture<'static, Result<Message, HickoryError>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let service = self.inner.clone();
        let mut service = std::mem::replace(&mut self.inner, service);

        Box::pin(async move {
            let query: DnsQuery = match req.try_into() {
                Ok(query) => query,
                Err(error) => {
                    trace!("Invalid request format: {error}");
                    return Err(HickoryError::LookupError(LookupError::ResponseCode(
                        ResponseCode::FormErr,
                    )));
                }
            };
            let lookup = service.call(query).await.map_err(Into::into)?;
            Ok(dbg!(lookup).into())
        })
    }
}

#[derive(Debug, Clone)]
pub struct ValidateRequestLayer {
    _priv: (),
}

impl ValidateRequestLayer {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> tower::Layer<S> for ValidateRequestLayer {
    type Service = ValidateRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ValidateRequest { inner }
    }
}

/// A service that validates an incoming request as a DNS Query,
/// ensuring that it has one query exactly, and otherwise returning
/// a FormErr response.
#[derive(Debug, Clone)]
pub struct ValidateRequest<S> {
    inner: S,
}

impl<S> tower::Service<Message> for ValidateRequest<S>
where
    S: tower::Service<Message, Response = Message> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<HickoryError>,
{
    type Response = Message;

    type Error = HickoryError;

    type Future = BoxFuture<'static, Result<Message, HickoryError>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let svc = self.inner.clone();
        let mut svc = std::mem::replace(&mut self.inner, svc);
        match req.header().message_type() {
            hickory_proto::op::MessageType::Query => {
                Box::pin(async move { svc.call(req).await.map_err(Into::into) })
            }
            hickory_proto::op::MessageType::Response => {
                Box::pin(async move { Err(HickoryError::ResponseAsRequest) })
            }
        }
    }
}

/// Catalog service for handling messages
#[derive(Debug, Clone)]
pub struct CatalogService<A> {
    catalog: Catalog<A>,
}

impl<A> CatalogService<A> {
    pub fn new(catalog: Catalog<A>) -> Self {
        Self { catalog }
    }
}

impl<A> tower::Service<DnsQuery> for CatalogService<A>
where
    A: Search + Lookup + Send + 'static,
{
    type Response = QueryLookup;

    type Error = LookupError;

    type Future = BoxFuture<'static, Result<QueryLookup, LookupError>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: DnsQuery) -> Self::Future {
        let catalog = self.catalog.clone();
        Box::pin(async move { catalog.handle_lookup(req).await })
    }
}
