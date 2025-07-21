use std::{
    collections::BTreeMap,
    fmt, io,
    net::SocketAddr,
    pin::{Pin, pin},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker, ready},
};

use futures::{Sink as _, Stream};
use hickory_proto::{
    ProtoError,
    op::{Edns, Header, Message, Query, ResponseCode},
    xfer::{DnsRequest, DnsRequestOptions, DnsResponse},
};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing::{debug, trace, warn};

use crate::codec::{CodecError, DNSCodec};

#[derive(Debug, Clone)]
pub struct ClientConfiguration {
    max_payload_len: u16,
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        ClientConfiguration {
            max_payload_len: 2048,
        }
    }
}

/// A DNS Client
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<InnerClient>,
    config: Arc<ClientConfiguration>,
}

impl Client {
    pub async fn new_udp_client(address: SocketAddr, bind: SocketAddr) -> io::Result<Client> {
        let socket = UdpSocket::bind(bind).await?;
        Ok(Client {
            inner: Arc::new(InnerClient::new(address, socket)),
            config: Arc::new(ClientConfiguration::default()),
        })
    }

    pub fn lookup(&self, mut query: Query, options: DnsRequestOptions) -> ResponseHandle {
        let mut message = Message::new();
        message.set_id(12345u16);
        let mut original_query = None;

        if options.case_randomization {
            original_query = Some(query.clone());
            query.name.randomize_label_case();
        }

        message
            .add_query(query)
            .set_recursion_desired(options.recursion_desired);

        // Extended dns
        if options.use_edns {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(self.config.max_payload_len)
                .set_version(0)
                .set_dnssec_ok(options.edns_set_dnssec_ok);
        }

        let request = DnsRequest::new(message, options).with_original_query(original_query);
        self.inner.send(request)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DNSClientError {
    #[error("Protocol: {0}")]
    Protocol(#[from] ProtoError),

    #[error("Invalid response for message {}: {}", .0.id(), .1)]
    Response(Header, ResponseCode),

    #[error("Connection closed")]
    Closed,
}

#[derive(Debug)]
struct InflightRequest {
    waker: Option<Waker>,
    query_pair: Option<(Query, Query)>,
}

#[derive(Debug)]
enum RequestEntry {
    Inflight(InflightRequest),
    Response(Option<Message>),
}

#[derive(Debug)]
struct InnerClient {
    in_flight: Mutex<BTreeMap<u16, RequestEntry>>,
    driver: Mutex<Pin<Box<ConnectionDriver>>>,
    address: SocketAddr,
}

impl InnerClient {
    fn new(address: SocketAddr, bind: UdpSocket) -> Self {
        Self {
            in_flight: Mutex::new(BTreeMap::new()),
            driver: Mutex::new(Box::pin(ConnectionDriver {
                framed: UdpFramed::new(
                    Arc::new(bind),
                    DNSCodec::new_for_protocol(hickory_proto::xfer::Protocol::Udp),
                ),
            })),
            address,
        }
    }

    fn send(self: &Arc<Self>, request: DnsRequest) -> ResponseHandle {
        let driver = self.driver.lock().expect("driver poisoned");
        let sender = UdpFramed::new(
            driver.framed.get_ref().clone(),
            driver.framed.codec().clone(),
        );
        drop(driver);

        ResponseHandle {
            sender: Sender {
                framed: sender,
                address: self.address,
            },
            client: Arc::clone(self),
            state: ResponseState::Request(Some(request)),
        }
    }

    fn pending(&self, id: u16, query_pair: Option<(Query, Query)>, waker: Waker) {
        let mut in_flight = self.in_flight.lock().expect("in-flight poisoned");
        in_flight.insert(
            id,
            RequestEntry::Inflight(InflightRequest {
                waker: Some(waker),
                query_pair,
            }),
        );
    }

    fn check(&self, id: u16, waker: &Waker) -> Option<Result<DnsResponse, DNSClientError>> {
        let mut in_flight = self.in_flight.lock().expect("in-flight poisoned");
        let entry = in_flight.get_mut(&id)?;
        match entry {
            RequestEntry::Inflight(inflight) => {
                inflight.waker.replace(waker.clone());
                None
            }
            RequestEntry::Response(message) => {
                let msg = message
                    .take()
                    .expect("message error: someone stole our message!");
                Some(DnsResponse::from_message(msg).map_err(Into::into))
            }
        }
    }

    fn insert(&self, mut message: Message) {
        let mut in_flight = self.in_flight.lock().expect("in-flight poisoned");
        trace!("Inserting id={}", message.id());
        let Some(entry) = in_flight.get_mut(&message.id()) else {
            warn!("Dropping unexpected response: {}", message.id());
            return;
        };

        match entry {
            RequestEntry::Inflight(ifr) => {
                if let Some((original, modified)) = ifr.query_pair.as_ref() {
                    if Some(modified) != message.query() {
                        warn!("Dropping case-mismatched response: {}", message.id());
                        return;
                    }
                    message.take_queries();
                    message.add_query(original.clone());
                }
                ifr.waker.take().expect("stolen waker").wake();
                debug!("Got response for query: {}", message.id());
                *entry = RequestEntry::Response(Some(message));
            }
            RequestEntry::Response(_) => {
                warn!("Dropping duplicate response: {}", message.id());
            }
        }
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
struct ConnectionDriver {
    #[pin]
    framed: UdpFramed<DNSCodec<Message>, Arc<UdpSocket>>,
}

impl ConnectionDriver {
    fn poll_recv(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Message, SocketAddr), DNSClientError>> {
        match ready!(self.as_mut().project().framed.poll_next(cx)) {
            Some(Ok((message, sender))) => match message {
                crate::codec::MessageDecoded::Message(message) => {
                    Poll::Ready(Ok((message, sender)))
                }
                crate::codec::MessageDecoded::Failed(header, response_code) => {
                    Poll::Ready(Err(DNSClientError::Response(header, response_code)))
                }
            },
            Some(Err(CodecError::DropMessage(error))) => {
                Poll::Ready(Err(DNSClientError::Protocol(error)))
            }
            Some(Err(CodecError::IO(io))) => Poll::Ready(Err(DNSClientError::Protocol(io.into()))),
            None => Poll::Ready(Err(DNSClientError::Closed)),
        }
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
struct Sender {
    #[pin]
    framed: UdpFramed<DNSCodec<Message>, Arc<UdpSocket>>,
    address: SocketAddr,
}

impl Sender {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), DNSClientError>> {
        self.project().framed.poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), DNSClientError> {
        let this = self.as_mut().project();
        this.framed
            .start_send((item, *this.address))
            .map_err(Into::into)
    }
}

enum ResponseState {
    Request(Option<DnsRequest>),
    Pending(u16),
}

impl fmt::Debug for ResponseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseState::Request(_) => f.write_str("Request"),
            ResponseState::Pending(_) => f.write_str("Pending"),
        }
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct ResponseHandle {
    #[pin]
    sender: Sender,
    client: Arc<InnerClient>,
    state: ResponseState,
}

impl Future for ResponseHandle {
    type Output = Result<DnsResponse, DNSClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut().project();
        loop {
            match &mut this.state {
                ResponseState::Request(dns_request) => {
                    ready!(this.sender.as_mut().poll_ready(cx))?;
                    let request = dns_request.take().expect("state error: missing message");

                    let queries = request
                        .original_query()
                        .cloned()
                        .and_then(|q| request.query().cloned().map(|m| (q, m)));
                    let id = request.id();
                    let (message, _) = request.into_parts();
                    this.sender.as_mut().start_send(message)?;
                    this.client.pending(id, queries, cx.waker().clone());
                    *this.state = ResponseState::Pending(id);
                }
                ResponseState::Pending(id) => {
                    trace!("Checking if {id} is ready");
                    if let Some(response) = this.client.check(*id, cx.waker()) {
                        return Poll::Ready(response);
                    }

                    let (response, sender) = {
                        let mut driver = this.client.driver.lock().expect("driver poisoned");

                        match driver.as_mut().poll_recv(cx) {
                            Poll::Ready(Ok((response, sender))) => (response, sender),
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => break,
                        }
                    };

                    trace!("Received DNS response from {sender}");

                    if this.sender.address != sender {
                        warn!("Received response from unknown sender, dropping");
                    }

                    this.client.insert(response);
                }
            }
        }

        // At this point, we are returning pending from recv, but we should try to flush if there is work to do.
        match ready!(this.sender.as_mut().project().framed.poll_flush(cx)) {
            Ok(()) => {
                // Already pending recv above,
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error.into())),
        }
    }
}
