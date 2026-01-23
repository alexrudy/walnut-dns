//! Support for outbound NOTIFY messages

use std::{
    collections::HashMap,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{Stream as _, stream::FuturesUnordered};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RecordType},
    xfer::{DnsRequest, DnsRequestOptions, DnsResponse},
};
use pin_project::pin_project;
use rand::Rng as _;
use serde::Deserialize;
use thiserror::Error;
use tower::{ServiceExt, util::Oneshot};
use tracing::{debug, instrument};

use crate::client::nameserver::Nameserver;
use crate::client::{DnsClientError, DnsRequestMiddleware, TaggedMessage};
use crate::rr::RecordSet;

#[derive(Debug, Error)]
#[error("notify request failed")]
pub struct NotifyError {
    errors: HashMap<IpAddr, DnsClientError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyConfig {
    pub max_payload_len: u16,
    pub notify_once: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            max_payload_len: 512,
            notify_once: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotifyManager {
    nameservers: Vec<DnsRequestMiddleware<Nameserver, TaggedMessage>>,
    config: NotifyConfig,
}

impl NotifyManager {
    pub fn new(nameservers: Vec<Nameserver>, config: NotifyConfig) -> Self {
        Self {
            nameservers: nameservers
                .into_iter()
                .map(DnsRequestMiddleware::new)
                .collect(),
            config,
        }
    }

    pub fn add_nameserver(&mut self, nameserver: Nameserver) {
        self.nameservers.push(DnsRequestMiddleware::new(nameserver));
    }

    /// Sends a notify message to each nameserver configured here.
    #[instrument(skip_all, fields(dns.label=%name, dns.type=%query_type, dns.id=tracing::field::Empty))]
    pub fn notify<R>(
        &mut self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
        rrset: Option<R>,
        options: DnsRequestOptions,
    ) -> NotifyFuture<
        Oneshot<IntoNotifyError<DnsRequestMiddleware<Nameserver, TaggedMessage>>, DnsRequest>,
    >
    where
        R: Into<RecordSet>,
    {
        let rrset = rrset.map(Into::into);

        debug!(records=%rrset.as_ref().map(|rr| rr.len()).unwrap_or(0), "notifying: {} {:?}", name, query_type);

        // build the message
        let mut rng = rand::rng();
        let mut message = Message::new();
        message
            .set_id(rng.random())
            // 3.3. NOTIFY is similar to QUERY in that it has a request message with
            // the header QR flag "clear" and a response message with QR "set".  The
            // response message contains no useful information, but its reception by
            // the Primary is an indication that the Secondary has received the NOTIFY
            // and that the Primary Zone Server can remove the Secondary from any retry queue for
            // this NOTIFY event.
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Notify);

        tracing::Span::current().record("dns.id", tracing::field::display(message.id()));

        // Extended dns
        if options.use_edns {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(self.config.max_payload_len)
                .set_version(0)
                .set_dnssec_ok(options.edns_set_dnssec_ok);
        }

        // add the query
        let mut query: Query = Query::new();
        query
            .set_name(name)
            .set_query_class(query_class)
            .set_query_type(RecordType::SOA);
        message.add_query(query);

        // add the notify message, see https://tools.ietf.org/html/rfc1996, section 3.7
        if let Some(rrset) = rrset {
            message.add_answers(rrset.into_hickory_iter());
        }

        let request = DnsRequest::new(message, options);
        NotifyFuture {
            futures: self
                .nameservers
                .iter()
                .cloned()
                .map(|ns| {
                    let addr = ns.inner().address();
                    IntoNotifyError::new(ns, addr).oneshot(request.clone())
                })
                .collect(),
            errors: Some(HashMap::new()),
        }
    }
}

#[pin_project]
pub struct NotifyFuture<F> {
    #[pin]
    futures: FuturesUnordered<F>,
    errors: Option<HashMap<IpAddr, DnsClientError>>,
}

impl<F, R> Future for NotifyFuture<F>
where
    F: Future<Output = Result<R, (IpAddr, DnsClientError)>>,
{
    type Output = Result<(), NotifyError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        while let Some(result) = ready!(this.futures.as_mut().poll_next(cx)) {
            match result {
                Ok(_) => {}
                Err((addr, error)) => {
                    tracing::error!("notify request encountered an error: {error}");
                    if let Some(errors) = this.errors.as_mut() {
                        errors.insert(addr, error);
                    }
                }
            }
        }

        let errors = this.errors.take().expect("polled after errors returned");
        if errors.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(NotifyError { errors }))
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntoNotifyError<S> {
    inner: S,
    addr: IpAddr,
}

impl<S> IntoNotifyError<S> {
    pub fn new(inner: S, addr: IpAddr) -> Self {
        Self { inner, addr }
    }
}

impl<S, Req> tower::Service<Req> for IntoNotifyError<S>
where
    S: tower::Service<Req, Response = DnsResponse, Error = DnsClientError>,
{
    type Response = ();
    type Error = (IpAddr, DnsClientError);
    type Future = WithAddrFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| (self.addr, error))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let future = self.inner.call(req);
        WithAddrFuture::new(future, self.addr)
    }
}

#[pin_project]
pub struct WithAddrFuture<F> {
    #[pin]
    future: F,
    addr: IpAddr,
}

impl<F> WithAddrFuture<F> {
    pub fn new(future: F, addr: IpAddr) -> Self {
        Self { future, addr }
    }
}

impl<F> Future for WithAddrFuture<F>
where
    F: Future<Output = Result<DnsResponse, DnsClientError>>,
{
    type Output = Result<(), (IpAddr, DnsClientError)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            Poll::Ready(Ok(response)) => {
                if matches!(response.response_code(), ResponseCode::NoError) {
                    tracing::debug!(answered=%response.contains_answer(), code=%response.response_code(), "Recieved response to NOTIFY");
                    Poll::Ready(Ok(()))
                } else {
                    tracing::error!(code=%response.response_code(), "Recieved error response to NOTIFY");
                    Poll::Ready(Err((
                        *this.addr,
                        DnsClientError::Response(
                            response.header().clone(),
                            response.response_code(),
                        ),
                    )))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err((*this.addr, error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
