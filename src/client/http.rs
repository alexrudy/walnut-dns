use std::{pin::Pin, task::Poll};

use bytes::BytesMut;
use hickory_proto::op::Message;
use http_body_util::BodyExt;
use tokio_util::codec::{Decoder as _, Encoder as _};

use crate::{codec::DnsCodec, services::http::DnsBody};

use super::{DnsClientError, codec::TaggedMessage, nameserver::NameserverConnection};

const MIME_APPLICATION_DNS: &str = "application/dns-message";

#[derive(Debug, Clone)]
pub struct DnsOverHttpLayer {
    version: http::Version,
    uri: http::Uri,
}

impl DnsOverHttpLayer {
    pub fn new(version: http::Version, uri: http::Uri) -> Self {
        Self { version, uri }
    }
}

impl<S> tower::Layer<S> for DnsOverHttpLayer {
    type Service = DnsOverHttp<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsOverHttp::new(inner, self.version, self.uri.clone())
    }
}

#[derive(Debug, Clone)]
pub struct DnsOverHttp<S> {
    dns_service: S,
    version: http::Version,
    codec: DnsCodec<Message, Message>,
    method: http::Method,
    uri: http::Uri,
}

impl<S> DnsOverHttp<S> {
    pub fn new(dns_service: S, version: http::Version, uri: http::Uri) -> Self {
        Self {
            dns_service,
            version,
            codec: DnsCodec::new_for_protocol(hickory_proto::xfer::Protocol::Https),
            method: http::Method::POST,
            uri,
        }
    }
}

impl<S> NameserverConnection for DnsOverHttp<S>
where
    S: NameserverConnection,
{
    fn status(&self) -> super::nameserver::ConnectionStatus {
        self.dns_service.status()
    }

    fn protocol(&self) -> hickory_proto::xfer::Protocol {
        self.dns_service.protocol()
    }
}

impl<S> tower::Service<TaggedMessage> for DnsOverHttp<S>
where
    S: tower::Service<http::Request<DnsBody>, Response = http::Response<hyper::body::Incoming>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = TaggedMessage;

    type Error = DnsClientError;

    type Future = DnsOverHttpsFuture;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.dns_service
            .poll_ready(cx)
            .map_err(|error| DnsClientError::Service(error.into()))
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        let svc = self.dns_service.clone();
        let mut svc = std::mem::replace(&mut self.dns_service, svc);
        let mut codec = self.codec.clone();
        let method = self.method.clone();
        let builder = http::Request::builder()
            .header(http::header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(http::header::ACCEPT, MIME_APPLICATION_DNS)
            .uri(self.uri.clone())
            .version(self.version);

        DnsOverHttpsFuture(Box::pin(async move {
            let mut buf = BytesMut::with_capacity(512);

            let mut msg: Message = req.into();
            msg.set_id(0);

            codec.encode(msg, &mut buf)?;

            let req = match method {
                http::Method::POST => builder
                    .body(DnsBody::new(buf.freeze()))
                    .expect("Failed to build http request"),
                http::Method::GET => {
                    let mut request = builder
                        .body(DnsBody::empty())
                        .expect("Failed to build http request");

                    // When the HTTP method is GET,
                    // the single variable "dns" is defined as the content of the DNS
                    // request (as described in Section 6), encoded with base64url
                    // [RFC4648].
                    //
                    // When using the GET method, the data payload for this media type MUST
                    // be encoded with base64url [RFC4648] and then provided as a variable
                    // named "dns" to the URI Template expansion.  Padding characters for
                    // base64url MUST NOT be included.
                    let uri = request.uri_mut();
                    let path = uri.path();
                    let query = data_encoding::BASE64URL_NOPAD.encode(&buf);
                    let path_and_query = format!("{}?dns={}", path, query)
                        .parse()
                        .expect("valid http uri for GET");
                    tracing::debug!("Sending DNS request with {}", path_and_query);
                    let mut parts = uri.clone().into_parts();
                    parts.path_and_query = Some(path_and_query);

                    *uri = http::Uri::from_parts(parts).expect("valid http uri");
                    request
                }
                _ => panic!("Unsupported HTTP method: {method}"),
            };

            let res = svc
                .call(req)
                .await
                .map_err(|error| DnsClientError::Service(error.into()))?;

            let mut body = BytesMut::from(res.into_body().collect().await?.to_bytes());
            let msg = codec
                .decode(&mut body)?
                .expect("Entire frame is availalbe to codec");
            Ok(TaggedMessage::from(msg))
        }))
    }
}

pub struct DnsOverHttpsFuture(
    Pin<Box<dyn Future<Output = Result<TaggedMessage, DnsClientError>> + Send>>,
);

impl Future for DnsOverHttpsFuture {
    type Output = Result<TaggedMessage, DnsClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
