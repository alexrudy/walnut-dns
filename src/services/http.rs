use std::{
    convert::Infallible,
    fmt, io,
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddr},
    pin::{Pin, pin},
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use chateau::info::ConnectionInfo;
use hickory_proto::op::Message;
use hickory_server::{authority::MessageRequest, server::Request};
use http::HeaderMap;
use tokio_util::codec::{Decoder, Encoder as _};
use tracing::debug;

use crate::{
    codec::{DNSCodec, DNSCodecRecovery},
    error::HickoryError,
};

const MIME_APPLICATION_DNS: &str = "application/dns-message";

#[derive(Debug)]
pub struct DNSBody {
    data: Option<Bytes>,
}

impl DNSBody {
    pub fn new(data: Bytes) -> Self {
        Self { data: Some(data) }
    }
}

impl http_body::Body for DNSBody {
    type Data = Bytes;

    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.data.take().map(|d| Ok(http_body::Frame::data(d))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.data
            .as_ref()
            .map(|data| http_body::SizeHint::with_exact(u64::try_from(data.remaining()).unwrap()))
            .unwrap_or_else(|| http_body::SizeHint::with_exact(0))
    }
}

#[derive(Debug, Clone)]
pub struct DNSOverHTTPLayer {
    version: http::Version,
}

impl DNSOverHTTPLayer {
    pub fn new(version: http::Version) -> Self {
        Self { version }
    }
}

impl<S> tower::Layer<S> for DNSOverHTTPLayer {
    type Service = DNSOverHTTP<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DNSOverHTTP::new(inner, self.version)
    }
}

#[derive(Debug, Clone)]
pub struct DNSOverHTTP<S> {
    dns_service: S,
    version: http::Version,
    codec: DNSCodecRecovery<Message, MessageRequest>,
}

impl<S> DNSOverHTTP<S> {
    pub fn new(dns_service: S, version: http::Version) -> Self {
        Self {
            dns_service,
            version,
            codec: DNSCodec::new(false, None).with_recovery(),
        }
    }
}

impl<S, B> tower::Service<http::Request<B>> for DNSOverHTTP<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError> + Clone,
    B: http_body::Body,
    B::Data: fmt::Debug + AsRef<[u8]>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = http::Response<DNSBody>;

    type Error = HickoryError;

    type Future = DNSOverHTTPFuture<B, S>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.dns_service.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let service = self.dns_service.clone();
        let service = std::mem::replace(&mut self.dns_service, service);
        let addr = req
            .extensions()
            .get::<ConnectionInfo<SocketAddr>>()
            .map_or((Ipv4Addr::LOCALHOST, 0).into(), |info| *info.remote_addr());

        match req.method() {
            &http::Method::GET => match req.uri().query().and_then(|q| {
                q.split('&')
                    .filter_map(|item| item.split_once('='))
                    .find(|(key, _)| *key == "dns")
            }) {
                Some((_, value)) => {
                    let data: bytes::BytesMut =
                        match data_encoding::BASE64URL_NOPAD.decode(value.as_bytes()) {
                            Ok(data) => bytes::Bytes::from(data).into(),
                            Err(error) => {
                                return DNSOverHTTPFuture::error(
                                    HickoryError::Recv(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        error,
                                    )),
                                    self.version,
                                    addr,
                                    self.codec.clone(),
                                );
                            }
                        };

                    DNSOverHTTPFuture::decode(data, service, self.version, addr, self.codec.clone())
                }
                None => DNSOverHTTPFuture::error(
                    HickoryError::Recv(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "No dns query on GET request",
                    )),
                    self.version,
                    addr,
                    self.codec.clone(),
                ),
            },
            &http::Method::POST => {
                let body = req.into_body();
                DNSOverHTTPFuture::post(body, service, self.version, addr, self.codec.clone())
            }
            method => DNSOverHTTPFuture::error(
                HickoryError::Recv(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid method: {method}"),
                )),
                self.version,
                addr,
                self.codec.clone(),
            ),
        }
    }
}

#[pin_project::pin_project(project=StateProject)]
enum DoHFState<B, S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    Collect {
        #[pin]
        body: B,
        bytes: Option<BytesMut>,
        trailers: HeaderMap,
        service: Option<S>,
    },
    Execute {
        #[pin]
        future: S::Future,
    },
    Decode {
        bytes: BytesMut,
        service: S,
    },
    Error {
        error: Option<HickoryError>,
    },
}

#[pin_project::pin_project]
pub struct DNSOverHTTPFuture<B, S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    #[pin]
    state: DoHFState<B, S>,
    version: http::Version,
    address: SocketAddr,
    codec: DNSCodecRecovery<Message, MessageRequest>,
}

impl<B, S> DNSOverHTTPFuture<B, S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    fn error(
        error: HickoryError,
        version: http::Version,
        address: SocketAddr,
        codec: DNSCodecRecovery<Message, MessageRequest>,
    ) -> Self {
        Self {
            state: DoHFState::Error { error: Some(error) },
            version,
            address,
            codec,
        }
    }

    fn decode(
        bytes: BytesMut,
        service: S,
        version: http::Version,
        address: SocketAddr,
        codec: DNSCodecRecovery<Message, MessageRequest>,
    ) -> Self {
        Self {
            state: DoHFState::Decode { bytes, service },
            version,
            address,
            codec,
        }
    }

    fn post(
        body: B,
        service: S,
        version: http::Version,
        address: SocketAddr,
        codec: DNSCodecRecovery<Message, MessageRequest>,
    ) -> Self {
        Self {
            state: DoHFState::Collect {
                body,
                bytes: Some(BytesMut::with_capacity(512)),
                trailers: HeaderMap::new(),
                service: Some(service),
            },
            version,
            address,
            codec,
        }
    }

    fn respond(
        mut self: Pin<&mut Self>,
        message: Message,
    ) -> Result<http::Response<DNSBody>, HickoryError> {
        let mut buf = BytesMut::with_capacity(512);
        self.as_mut().project().codec.encode(message, &mut buf)?;

        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .version(self.version)
            .header(http::header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(http::header::CONTENT_LENGTH, buf.len())
            .body(DNSBody {
                data: Some(buf.freeze()),
            })
            .unwrap();
        Ok(response)
    }
}

impl<B, S> Future for DNSOverHTTPFuture<B, S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
    B: http_body::Body,
    B::Data: fmt::Debug + AsRef<[u8]>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Output = Result<http::Response<DNSBody>, HickoryError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut().project();

        loop {
            match this.state.as_mut().project() {
                StateProject::Collect {
                    body,
                    bytes,
                    trailers,
                    service,
                } => match ready!(body.poll_frame(cx)) {
                    Some(Ok(frame)) if frame.is_data() => {
                        bytes
                            .as_mut()
                            .unwrap()
                            .extend_from_slice(frame.into_data().unwrap().as_ref());
                    }
                    Some(Ok(frame)) => {
                        let tr = frame.into_trailers().unwrap();
                        trailers.extend(tr);
                    }
                    Some(Err(err)) => {
                        return Poll::Ready(Err(HickoryError::Recv(io::Error::new(
                            io::ErrorKind::InvalidData,
                            err,
                        ))));
                    }
                    None => {
                        let bytes = bytes.take().unwrap();
                        let service = service.take().unwrap();
                        this.state.set(DoHFState::Decode { bytes, service })
                    }
                },
                StateProject::Decode { bytes, service } => match this.codec.decode(bytes) {
                    Ok(Some(request)) => {
                        match request
                            .with_address(*this.address, hickory_proto::xfer::Protocol::Https)
                        {
                            crate::codec::DNSRequest::Message(request) => {
                                let future = service.call(request);
                                this.state.set(DoHFState::Execute { future })
                            }
                            crate::codec::DNSRequest::Failed((response, _)) => {
                                return Poll::Ready(self.respond(response));
                            }
                        }
                    }
                    Ok(None) => {
                        return Poll::Ready(Err(HickoryError::Recv(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Insufficient data for decoder",
                        ))));
                    }
                    Err(error) => match error {
                        crate::codec::CodecError::DropMessage(proto_error, _)
                        | crate::codec::CodecError::Protocol(proto_error) => {
                            return Poll::Ready(Err(HickoryError::Protocol(proto_error)));
                        }
                        crate::codec::CodecError::FailedMessage(header, response_code) => {
                            let response =
                                Message::error_msg(header.id(), header.op_code(), response_code);
                            return Poll::Ready(self.respond(response));
                        }
                        crate::codec::CodecError::IO(error) => {
                            return Poll::Ready(Err(HickoryError::Recv(error)));
                        }
                    },
                },
                StateProject::Execute { future } => match ready!(future.poll(cx)) {
                    Ok(message) => {
                        return Poll::Ready(self.respond(message));
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                },
                StateProject::Error { error } => {
                    return Poll::Ready(Err(error.take().expect("polled after error")));
                }
            };
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    version: http::Version,
    name_server: Option<String>,
    path: String,
}

impl VerifyRequest {
    pub fn new(version: http::Version, name_server: Option<String>, path: String) -> Self {
        Self {
            version,
            name_server,
            path,
        }
    }

    pub fn verify<B>(&self, request: &http::Request<B>) -> Result<(), io::Error> {
        let uri = request.uri();
        if uri.path() != self.path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "URI Path mismatch",
            ));
        }

        if let Some(name_server) = &self.name_server {
            if let Some(authority) = uri.authority() {
                if authority.host() != name_server {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Incorrect authority",
                    ));
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Request is missing authority",
                ));
            }
        }

        if request.version() != self.version {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wrong HTTP version",
            ));
        }

        match request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|v| v.to_str())
        {
            Some(Ok(ctype)) if ctype == MIME_APPLICATION_DNS => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported content type",
                ));
            }
        };

        match request
            .headers()
            .get(http::header::ACCEPT)
            .map(|v| v.to_str())
        {
            Some(Ok(ctype)) => {
                let mut found = false;
                for mime_and_quality in ctype.split(',') {
                    let mut parts = mime_and_quality.splitn(2, ';');
                    match parts.next() {
                        Some(mime) if mime.trim() == MIME_APPLICATION_DNS => {
                            found = true;
                            break;
                        }
                        Some(mime) if mime.trim() == "application/*" => {
                            found = true;
                            break;
                        }
                        _ => continue,
                    }
                }

                if !found {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no supported accept type",
                    ));
                }
            }
            Some(Err(e)) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "accept not specified",
                ));
            }
        };

        Ok(())
    }
}

pub struct VerifyDNSOverHTTP<S> {
    service: S,
    verify: Option<VerifyRequest>,
}

impl<B, S> tower::Service<http::Request<B>> for VerifyDNSOverHTTP<S>
where
    S: tower::Service<http::Request<B>>,
    S::Error: Into<HickoryError>,
{
    type Response = S::Response;

    type Error = HickoryError;

    type Future = VerifyDOHFuture<S::Future, S::Response, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        if let Some(verify) = &self.verify {
            if let Err(error) = verify.verify(&req) {
                debug!("DNS over HTTPS got an invalid request: {error}");
                return VerifyDOHFuture::error(error);
            }
        }

        VerifyDOHFuture::future(self.service.call(req))
    }
}

#[pin_project::pin_project(project=VDoHProjected)]
enum VDoHState<F> {
    Future(#[pin] F),
    Error(Option<HickoryError>),
}

#[pin_project::pin_project]
pub struct VerifyDOHFuture<F, R, E> {
    #[pin]
    state: VDoHState<F>,
    _response: PhantomData<fn() -> (R, E)>,
}

impl<F, R, E> VerifyDOHFuture<F, R, E> {
    fn error(error: io::Error) -> Self {
        Self {
            state: VDoHState::Error(Some(HickoryError::Recv(error))),
            _response: PhantomData,
        }
    }

    fn future(future: F) -> Self {
        Self {
            state: VDoHState::Future(future),
            _response: PhantomData,
        }
    }
}

impl<F, R, E> Future for VerifyDOHFuture<F, R, E>
where
    F: Future<Output = Result<R, E>>,
    E: Into<HickoryError>,
{
    type Output = Result<R, HickoryError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().state.project() {
            VDoHProjected::Future(future) => future.poll(cx).map_err(Into::into),
            VDoHProjected::Error(error) => {
                Poll::Ready(Err(error.take().expect("polled after error returned")))
            }
        }
    }
}
