//! Adapters for DNS Client Messages

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::{DnsRequest, DnsResponse};
use pin_project::pin_project;

#[derive(Debug, Clone, Default)]
pub struct DNSRequestLayer;

#[derive(Debug, Clone)]
pub struct DNSRequestMiddleware<S> {
    inner: S,
}

impl<S> DNSRequestMiddleware<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> tower::Service<DnsRequest> for DNSRequestMiddleware<S>
where
    S: tower::Service<Message, Response = Message>,
    S::Error: From<ProtoError>,
{
    type Response = DnsResponse;

    type Error = S::Error;

    type Future = ResponseAdapter<S::Future, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let (msg, _options) = req.into_parts();
        let fut = self.inner.call(msg);
        ResponseAdapter {
            inner: fut,
            error: PhantomData,
        }
    }
}

#[pin_project]
pub struct ResponseAdapter<F, E> {
    #[pin]
    inner: F,
    error: PhantomData<fn() -> E>,
}

impl<F, E> Future for ResponseAdapter<F, E>
where
    F: Future<Output = Result<Message, E>>,
    E: From<ProtoError>,
{
    type Output = Result<DnsResponse, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let message = match ready!(self.project().inner.poll(cx)) {
            Ok(message) => message,
            Err(error) => return Poll::Ready(Err(error)),
        };

        Poll::Ready(DnsResponse::from_message(message).map_err(Into::into))
    }
}
