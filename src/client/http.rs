use std::{pin::Pin, task::Poll};

use bytes::BytesMut;
use hickory_proto::{
    op::Message,
    xfer::{DnsRequest, DnsResponse},
};
use http_body_util::BodyExt;
use tokio_util::codec::{Decoder as _, Encoder as _};

use crate::{codec::DNSCodec, services::http::DNSBody};

use super::DNSClientError;

const MIME_APPLICATION_DNS: &str = "application/dns-message";

#[derive(Debug, Clone)]
pub struct DNSOverHTTPLayer {
    version: http::Version,
    uri: http::Uri,
}

impl DNSOverHTTPLayer {
    pub fn new(version: http::Version, uri: http::Uri) -> Self {
        Self { version, uri }
    }
}

impl<S> tower::Layer<S> for DNSOverHTTPLayer {
    type Service = DNSOverHTTP<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DNSOverHTTP::new(inner, self.version, self.uri.clone())
    }
}

#[derive(Debug, Clone)]
pub struct DNSOverHTTP<S> {
    dns_service: S,
    version: http::Version,
    codec: DNSCodec<Message, Message>,
    method: http::Method,
    uri: http::Uri,
}

impl<S> DNSOverHTTP<S> {
    pub fn new(dns_service: S, version: http::Version, uri: http::Uri) -> Self {
        Self {
            dns_service,
            version,
            codec: DNSCodec::new(false, None),
            method: http::Method::POST,
            uri,
        }
    }
}

impl<S> tower::Service<DnsRequest> for DNSOverHTTP<S>
where
    S: tower::Service<http::Request<DNSBody>, Response = http::Response<hyper::body::Incoming>>
        + Clone,
{
    type Response = DnsResponse;

    type Error = DNSClientError;

    type Future = DNSOverHttpsFuture;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.dns_service.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let svc = self.dns_service.clone();
        let svc = std::mem::replace(&mut self.dns_service, svc);
        let codec = self.codec.clone();
        let method = self.method.clone();
        let builder = http::Request::builder()
            .header(http::header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(http::header::ACCEPT, MIME_APPLICATION_DNS)
            .uri(self.uri.clone())
            .version(self.version);

        DNSOverHttpsFuture(Box::pin(async move {
            let mut buf = BytesMut::with_capacity(512);

            let (message, _) = req.into_parts();
            codec.encode(message, &mut buf)?;

            let req = match method {
                http::Method::POST => builder.body(DNSBody::new(buf.freeze())),
                _ => panic!("Unsupported HTTP method: {method}"),
            }?;

            let res = svc.call(req).await?;

            let body = BytesMut::from(res.into_body().collect().await?.to_bytes());
            let msg = codec.decode(&mut body)?.unwrap();
            DnsResponse::from_message(msg).map_err(Into::into)
        }))
    }
}

pub struct DNSOverHttpsFuture(
    Pin<Box<dyn Future<Output = Result<DnsResponse, DNSClientError>> + Send>>,
);

impl Future for DNSOverHttpsFuture {
    type Output = Result<DnsResponse, DNSClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
