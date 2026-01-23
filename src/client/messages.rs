//! Adapters for DNS Client Messages

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::{DnsRequest, DnsResponse};
use pin_project::pin_project;

#[derive(Debug, Clone, Default)]
pub struct DnsRequestLayer<M> {
    message: PhantomData<fn(M) -> M>,
}

impl<M> DnsRequestLayer<M> {
    pub fn new() -> Self {
        Self {
            message: PhantomData,
        }
    }
}

impl<M, S> tower::Layer<S> for DnsRequestLayer<M> {
    type Service = DnsRequestMiddleware<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsRequestMiddleware::new(inner)
    }
}

#[derive(Debug, Clone)]
pub struct DnsRequestMiddleware<S, M> {
    inner: S,
    message: PhantomData<fn(M) -> M>,
}

impl<S, M> DnsRequestMiddleware<S, M> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            message: PhantomData,
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S, M> tower::Service<DnsRequest> for DnsRequestMiddleware<S, M>
where
    S: tower::Service<M, Response = M>,
    S::Error: From<ProtoError>,
    M: Into<Message> + From<Message> + Send + 'static,
{
    type Response = DnsResponse;

    type Error = S::Error;

    type Future = ResponseAdapter<S::Future, M, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let (msg, _options) = req.into_parts();
        let fut = self.inner.call(msg.into());
        ResponseAdapter {
            inner: fut,
            error: PhantomData,
        }
    }
}

#[pin_project]
pub struct ResponseAdapter<F, M, E> {
    #[pin]
    inner: F,
    error: PhantomData<fn() -> (M, E)>,
}

impl<F, M, E> Future for ResponseAdapter<F, M, E>
where
    F: Future<Output = Result<M, E>>,
    E: From<ProtoError>,
    M: Into<Message> + Send + 'static,
{
    type Output = Result<DnsResponse, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let message = match ready!(self.project().inner.poll(cx)) {
            Ok(message) => message.into(),
            Err(error) => return Poll::Ready(Err(error)),
        };

        Poll::Ready(DnsResponse::from_message(message).map_err(Into::into))
    }
}
