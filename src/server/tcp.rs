//! TCP Protocol for DNS

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use chateau::server::{Connection, Protocol};
use chateau::stream::tcp::TcpStream;
use futures::{Sink, Stream};
use hickory_proto::op::Message;
use hickory_server::server::Request;
use tokio::task::JoinSet;
use tokio_util::codec::Framed;
use tracing::{Instrument, debug, error, trace, trace_span};

use crate::{codec::DNSCodec, error::HickoryError};

#[derive(Debug, Default)]
pub struct DnsOverTcp {
    _priv: (),
}

impl DnsOverTcp {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> Protocol<S, TcpStream, Request> for DnsOverTcp
where
    S: tower::Service<Request, Response = Message, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = Message;
    type Error = HickoryError;

    type Connection = DnsOverTcpConnection<S>;

    fn serve_connection(&self, stream: TcpStream, service: S) -> Self::Connection {
        DnsOverTcpConnection::new(stream, service)
    }
}

#[pin_project::pin_project]
pub struct DnsOverTcpConnection<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    service: S,
    #[pin]
    codec: Framed<TcpStream, DNSCodec>,
    tasks: JoinSet<Result<Message, HickoryError>>,
    outbound: Option<Message>,
    cancelled: bool,
}

impl<S> DnsOverTcpConnection<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    pub fn new(stream: TcpStream, service: S) -> Self {
        let codec = Framed::new(stream, DNSCodec::new(hickory_proto::xfer::Protocol::Tcp));
        let tasks = JoinSet::new();
        Self {
            service,
            codec,
            tasks,
            outbound: None,
            cancelled: false,
        }
    }
}

impl<S> fmt::Debug for DnsOverTcpConnection<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsOverTcpConnection")
            .field("codec", &self.codec)
            .finish()
    }
}

enum ReadAction {
    Spawned,
    Terminated,
}

impl<S> DnsOverTcpConnection<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
    S::Future: Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadAction, HickoryError>> {
        let mut this = self.as_mut().project();
        ready!(this.service.poll_ready(cx))?;
        loop {
            match ready!(this.codec.as_mut().poll_next(cx)) {
                Some(Ok(message)) => {
                    trace!("Recieved message");
                    let src = this
                        .codec
                        .get_ref()
                        .peer_addr()
                        .map_err(HickoryError::Recv)?;
                    let id = message.id();
                    let future = this.service.call(Request::new(
                        message,
                        src,
                        hickory_proto::xfer::Protocol::Tcp,
                    ));
                    this.tasks.spawn(
                        async move {
                            trace!("Processing message {id}");
                            let response = future.await?;
                            trace!("Task returning response {id}");
                            Ok(response)
                        }
                        .instrument(trace_span!(parent: None, "message", %id)),
                    );
                    trace!(%id, "Spawned task");
                    return Ok(ReadAction::Spawned).into();
                }
                Some(Err(error)) => {
                    trace!("Dropping message, codec error: {error}");
                }
                None => {
                    trace!("Codec Empty");
                    return Ok(ReadAction::Terminated).into();
                }
            }
        }
    }

    fn poll_tasks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Message>, HickoryError>> {
        loop {
            match ready!(self.tasks.poll_join_next(cx)) {
                Some(Ok(Ok(message))) => {
                    tracing::trace!("Service provided response {id}", id = message.id());
                    return Ok(Some(message)).into();
                }
                Some(Ok(Err(error))) => return Err(error).into(),
                Some(Err(error)) if error.is_panic() => {
                    error!("DNS Service panic handling request: {error}");
                }
                Some(Err(_)) => {
                    trace!("DNS Service task cancelled");
                }
                None => return Ok(None).into(),
            }
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), HickoryError>> {
        loop {
            if self.outbound.is_none() {
                let message = match ready!(self.as_mut().poll_tasks(cx))? {
                    Some(message) => message,
                    None => {
                        trace!("No active tasks");
                        return Ok(()).into();
                    }
                };
                self.as_mut().outbound = Some(message);
            }
            trace!("Writing message");
            let mut this = self.as_mut().project();
            ready!(this.codec.as_mut().poll_ready(cx))?;
            let message = this.outbound.take().expect("Pending outbound message");
            this.codec
                .start_send(message)
                .map_err(HickoryError::Protocol)?;
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), HickoryError>> {
        ready!(self.as_mut().poll_write(cx))?;
        trace!("Shutting down writer");
        self.as_mut()
            .project()
            .codec
            .poll_close(cx)
            .map_err(HickoryError::Protocol)
    }
}

impl<S> Future for DnsOverTcpConnection<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
    S::Future: Send + 'static,
{
    type Output = Result<(), HickoryError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Write as much as we can before pending.
        if let Poll::Ready(Err(error)) = self.as_mut().poll_write(cx) {
            debug!("Write error: {error}");
            return Err(error).into();
        };

        // Read and start new tasks only if we are still running.
        if !self.cancelled {
            match self.as_mut().poll_read(cx) {
                Poll::Ready(Ok(ReadAction::Terminated)) => {
                    self.cancelled = true;
                    self.as_mut().poll_shutdown(cx)
                }
                Poll::Ready(Ok(ReadAction::Spawned)) => self.as_mut().poll_write(cx),
                Poll::Ready(Err(error)) => {
                    debug!("Read error: {error}");
                    Err(error).into()
                }
                Poll::Pending if self.tasks.is_empty() => {
                    // No more tasks to poll, but there might be data sitting
                    // in the outbound buffer.
                    ready!(self.as_mut().project().codec.poll_flush(cx))?;
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }
        } else if self.tasks.is_empty() {
            // Cancelled, flush and close writer.
            self.as_mut().poll_shutdown(cx)
        } else {
            // Tasks are still running.
            Poll::Pending
        }
    }
}

impl<S> Connection for DnsOverTcpConnection<S>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    fn graceful_shutdown(mut self: Pin<&mut Self>) {
        self.cancelled = true;
    }
}
