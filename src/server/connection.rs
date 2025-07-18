//! TCP Protocol for DNS

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::{fmt, io};

use chateau::info::HasConnectionInfo;
use chateau::server::Connection;
use futures::{Sink, Stream};
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::Protocol;
use hickory_server::server::Request;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use tokio_util::codec::Framed;
use tracing::{Instrument, debug, error, trace, trace_span};

use crate::codec::DNSCodec;
use crate::error::HickoryError;

#[pin_project::pin_project]
pub struct DNSFramedStream<IO> {
    addr: SocketAddr,

    #[pin]
    codec: Framed<IO, DNSCodec>,
}

impl<IO> DNSFramedStream<IO>
where
    IO: AsyncRead + AsyncWrite + HasConnectionInfo,
    IO::Addr: Into<SocketAddr> + Clone,
{
    pub(crate) fn new(stream: IO, protocol: Protocol) -> Self {
        let remote = stream.info().remote_addr().clone().into();
        Self {
            addr: remote,
            codec: Framed::new(stream, DNSCodec::new(protocol)),
        }
    }
}

impl<IO> Sink<(Message, SocketAddr)> for DNSFramedStream<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    type Error = ProtoError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().codec.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: (Message, SocketAddr)) -> Result<(), Self::Error> {
        let (message, addr) = item;
        if addr != self.addr {
            return Err(ProtoError::from(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Incorrect address for stream ({}): {addr}", self.addr),
            )));
        }

        self.project().codec.start_send(message)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().codec.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().codec.poll_close(cx)
    }
}

impl<IO> Stream for DNSFramedStream<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    type Item = Result<Request, ProtoError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        this.codec.as_mut().poll_next(cx).map(|r| {
            r.map(|r| r.map(|msg| Request::new(msg, *this.addr, this.codec.codec().protocol())))
        })
    }
}

#[pin_project::pin_project]
pub struct DNSConnection<S, F> {
    service: S,
    #[pin]
    codec: F,
    tasks: JoinSet<Result<(Message, SocketAddr), HickoryError>>,
    outbound: Option<(Message, SocketAddr)>,
    cancelled: bool,
}

impl<S, F> DNSConnection<S, F> {
    pub fn new(service: S, codec: F) -> Self {
        Self {
            service,
            codec,
            tasks: JoinSet::new(),
            outbound: None,
            cancelled: false,
        }
    }
}

impl<S, IO> DNSConnection<S, DNSFramedStream<IO>>
where
    IO: AsyncRead + AsyncWrite + HasConnectionInfo,
    IO::Addr: Into<SocketAddr> + Clone,
{
    pub fn streamed(service: S, stream: IO, protocol: Protocol) -> Self {
        Self::new(service, DNSFramedStream::new(stream, protocol))
    }
}

impl<S, F> fmt::Debug for DNSConnection<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DNSConnection").finish()
    }
}

enum ReadAction {
    Spawned,
    Terminated,
}

impl<S, F> DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
    S::Future: Send + 'static,
    F: Stream<Item = Result<Request, ProtoError>>,
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

                    let id = message.id();
                    let addr = message.src();
                    let future = this.service.call(message);
                    this.tasks.spawn(
                        async move {
                            trace!("Processing message {id}");
                            let response = future.await?;
                            trace!("Task returning response {id}");
                            Ok((response, addr))
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
}

impl<S, F> DNSConnection<S, F> {
    fn poll_tasks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(Message, SocketAddr)>, HickoryError>> {
        loop {
            match ready!(self.as_mut().project().tasks.poll_join_next(cx)) {
                Some(Ok(Ok((message, addr)))) => {
                    tracing::trace!("Service provided response {id}", id = message.id());
                    return Ok(Some((message, addr))).into();
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
}

impl<S, F> DNSConnection<S, F>
where
    F: Sink<(Message, SocketAddr), Error = ProtoError>,
{
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
                *self.as_mut().project().outbound = Some(message);
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

impl<S, F> Future for DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
    S::Future: Send + 'static,
    F: Stream<Item = Result<Request, ProtoError>> + Sink<(Message, SocketAddr), Error = ProtoError>,
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
                    let this = self.as_mut().project();
                    *this.cancelled = true;
                    self.poll_shutdown(cx)
                }

                // Since we just spawned a task, poll_write probably won't succeed,
                // but it will register a wakeup when the taks completes.
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

impl<S, F> Connection for DNSConnection<S, F> {
    fn graceful_shutdown(self: Pin<&mut Self>) {
        *self.project().cancelled = true;
    }
}
