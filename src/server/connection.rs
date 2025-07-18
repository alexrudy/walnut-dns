//! TCP Protocol for DNS

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::{fmt, io};

use chateau::info::HasConnectionInfo;
use chateau::server::Connection;
use futures::stream::FuturesUnordered;
use futures::{Sink, Stream, TryStream};
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::Protocol;
use hickory_server::server::Request;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::instrument::Instrumented;
use tracing::{Instrument, debug, debug_span, trace, trace_span, warn};

use crate::codec::{CodecError, DNSCodec, DNSRequest};
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
    type Item = Result<DNSRequest, CodecError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        this.codec.as_mut().poll_next(cx).map(|r| {
            r.map(|r| r.map(|msg| msg.with_address(*this.addr, this.codec.codec().protocol())))
        })
    }
}

enum ServiceState<S> {
    Pending(Option<S>),
    Ready(Option<S>),
}

#[pin_project::pin_project(project=AddressStateProject)]
enum AddressFutureState<F> {
    Future(#[pin] F),
    Done(Option<Message>),
}

#[pin_project::pin_project]
struct AddressedFuture<F> {
    #[pin]
    state: AddressFutureState<F>,
    addr: SocketAddr,
}

impl<F> AddressedFuture<F> {
    fn future(future: F, addr: SocketAddr) -> Self {
        Self {
            state: AddressFutureState::Future(future),
            addr,
        }
    }

    fn done(message: Message, addr: SocketAddr) -> Self {
        Self {
            state: AddressFutureState::Done(Some(message)),
            addr,
        }
    }
}

impl<F> Future for AddressedFuture<F>
where
    F: Future<Output = Result<Message, HickoryError>>,
{
    type Output = Result<(Message, SocketAddr), HickoryError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.state.project() {
            AddressStateProject::Future(future) => ready!(future.poll(cx)),
            AddressStateProject::Done(message) => Ok(message.take().expect("polled after done")),
        }
        .map(|message| (message, *this.addr))
        .into()
    }
}

#[pin_project::pin_project]
pub struct DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    service: ServiceState<S>,
    #[pin]
    codec: F,

    #[pin]
    tasks: FuturesUnordered<Instrumented<AddressedFuture<S::Future>>>,
    outbound: Option<(Message, SocketAddr)>,
    cancelled: bool,
}

impl<S, F> DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    pub fn new(service: S, codec: F) -> Self {
        Self {
            service: ServiceState::Pending(Some(service)),
            codec,
            tasks: FuturesUnordered::new(),
            outbound: None,
            cancelled: false,
        }
    }
}

impl<S, IO> DNSConnection<S, DNSFramedStream<IO>>
where
    IO: AsyncRead + AsyncWrite + HasConnectionInfo,
    IO::Addr: Into<SocketAddr> + Clone,
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    pub fn streamed(service: S, stream: IO, protocol: Protocol) -> Self {
        Self::new(service, DNSFramedStream::new(stream, protocol))
    }
}

impl<S, F> fmt::Debug for DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
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
    F: Stream<Item = Result<DNSRequest, CodecError>>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadAction, HickoryError>> {
        let mut this = self.as_mut().project();
        match this.service {
            ServiceState::Pending(svc) => {
                ready!(svc.as_mut().expect("service available").poll_ready(cx))?;
                *this.service = ServiceState::Ready(svc.take());
            }
            ServiceState::Ready(_) => {}
        }

        loop {
            match ready!(this.codec.as_mut().try_poll_next(cx)) {
                Some(Ok(DNSRequest::Message(message))) => {
                    trace!("Recieved message");

                    let id = message.id();
                    let addr = message.src();

                    sanitize_address(&addr).map_err(HickoryError::Recv)?;

                    let mut svc = match this.service {
                        ServiceState::Pending(_) => None,
                        ServiceState::Ready(svc) => svc.take(),
                    }
                    .expect("service polled to ready");

                    let future = svc.call(message);
                    this.tasks.push(
                        AddressedFuture::future(future, addr)
                            .instrument(debug_span!(parent: None, "message", %id)),
                    );
                    trace!(%id, "Spawned task");
                    *this.service = ServiceState::Pending(Some(svc));
                    return Ok(ReadAction::Spawned).into();
                }
                Some(Ok(DNSRequest::Failed((reply, addr)))) => {
                    let id = reply.id();
                    this.tasks.push(
                        AddressedFuture::done(reply, addr)
                            .instrument(trace_span!(parent: None, "message", %id)),
                    );
                    trace!(%id, "Spawned error response");
                    return Ok(ReadAction::Spawned).into();
                }

                Some(Err(CodecError::DropMessage(error))) => {
                    trace!("Dropping message, codec error: {error}");
                }
                Some(Err(CodecError::IO(error))) => {
                    trace!("Codec IO Error");
                    return Err(HickoryError::Recv(error)).into();
                }
                None => {
                    trace!("Codec Empty");
                    return Ok(ReadAction::Terminated).into();
                }
            }
        }
    }
}

impl<S, F> DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    fn poll_tasks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(Message, SocketAddr)>, HickoryError>> {
        loop {
            match ready!(self.as_mut().project().tasks.try_poll_next(cx)) {
                Some(Ok((message, addr))) => {
                    trace!(id=%message.id(), "Service provided response");
                    return Ok(Some((message, addr))).into();
                }
                Some(Err(error)) => {
                    warn!("Task encountered an unhandled error: {error}");
                    return Ok(None).into();
                }
                None => return Ok(None).into(),
            }
        }
    }
}

impl<S, F> DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
    F: Sink<(Message, SocketAddr), Error = ProtoError>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), HickoryError>> {
        loop {
            ready!(self.as_mut().project().codec.poll_ready(cx))?;

            let message = match ready!(self.as_mut().poll_tasks(cx))? {
                Some(message) => message,
                None => {
                    return Ok(()).into();
                }
            };

            trace!(id=%message.0.id(), "Writing message");
            self.as_mut()
                .project()
                .codec
                .start_send(message)
                .map_err(HickoryError::Protocol)?;
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), HickoryError>> {
        ready!(self.as_mut().poll_write(cx))?;
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
    F: Stream<Item = Result<DNSRequest, CodecError>>
        + Sink<(Message, SocketAddr), Error = ProtoError>,
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
            loop {
                match self.as_mut().poll_read(cx) {
                    Poll::Ready(Ok(ReadAction::Terminated)) => {
                        trace!("Read terminated: cancel");
                        let this = self.as_mut().project();
                        *this.cancelled = true;
                        return self.poll_shutdown(cx);
                    }

                    // Since we just spawned a task, poll_write probably won't succeed,
                    // but it will register a wakeup when the taks completes.
                    Poll::Ready(Ok(ReadAction::Spawned)) => {
                        if let Err(error) = ready!(self.as_mut().poll_write(cx)) {
                            debug!("Write error: {error}");
                            return Err(error).into();
                        }
                    }
                    Poll::Ready(Err(error)) => {
                        debug!("Read error: {error}");
                        return Err(error).into();
                    }
                    Poll::Pending if self.tasks.is_empty() => {
                        // No more tasks to poll, but there might be data sitting
                        // in the outbound buffer.
                        ready!(self.as_mut().project().codec.poll_flush(cx)).inspect_err(
                            |error| {
                                debug!("Flush error: {error}");
                            },
                        )?;
                        return Poll::Pending;
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
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

impl<S, F> Connection for DNSConnection<S, F>
where
    S: tower::Service<Request, Response = Message, Error = HickoryError>,
{
    fn graceful_shutdown(self: Pin<&mut Self>) {
        *self.project().cancelled = true;
    }
}

fn sanitize_address(address: &SocketAddr) -> Result<(), io::Error> {
    if address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port cannot be zero",
        ));
    }

    if let IpAddr::V4(addr) = address.ip() {
        if addr.is_broadcast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "broadcast addresses are not supported",
            ));
        }
    }

    if address.ip().is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unspecified addresses are not supported",
        ));
    }

    Ok(())
}
