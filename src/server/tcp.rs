//! TCP Protocol for DNS

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use chateau::{
    server::{Connection, Protocol},
    stream::tcp::TcpStream,
};
use hickory_proto::xfer::SerialMessage;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tracing::{error, trace};

use crate::error::HickoryError;

use super::request::SerializedRequest;

/// Current state while writing to the remote of the TCP connection
enum WriteTcpState {
    /// Currently writing the length of bytes to of the buffer.
    LenBytes {
        /// Current position in the length buffer being written
        pos: usize,
        /// Length of the buffer
        length: [u8; 2],
        /// Buffer to write after the length
        bytes: Bytes,
    },
    /// Currently writing the buffer to the remote
    Bytes { bytes: Bytes },
    /// Currently flushing the bytes to the remote
    Flushing,
}

/// Current state of a TCP stream as it's being read.
enum ReadTcpState {
    /// Currently reading the length of the TCP packet
    LenBytes {
        /// Current position in the buffer
        pos: usize,
        /// Buffer of the length to read
        bytes: [u8; 2],
    },
    /// Currently reading the bytes of the DNS packet
    Bytes {
        /// Current position while reading the buffer
        pos: usize,
        /// buffer being read into
        bytes: BytesMut,
    },
}

#[derive(Debug)]
pub struct DnsOverTcp {}

impl<S> Protocol<S, TcpStream, SerializedRequest> for DnsOverTcp
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError> + 'static,
    S::Future: Send + 'static,
{
    type Response = SerialMessage;
    type Error = HickoryError;

    type Connection = DnsOverTcpConnection<S>;

    fn serve_connection(&self, stream: TcpStream, service: S) -> Self::Connection {
        DnsOverTcpConnection::new(stream, service)
    }
}

#[pin_project::pin_project]
pub struct DnsOverTcpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    service: S,
    read_state: ReadTcpState,
    write_state: Option<WriteTcpState>,
    outgoing: mpsc::UnboundedReceiver<SerialMessage>,
    incoming: Option<mpsc::UnboundedSender<SerialMessage>>,
    cancelled: bool,
    #[pin]
    stream: TcpStream,
}

impl<S> DnsOverTcpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    fn new(stream: TcpStream, service: S) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            service,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0; 2],
            },
            write_state: None,
            outgoing: rx,
            incoming: None,
            cancelled: false,
            stream,
        }
    }
}

impl<S> fmt::Debug for DnsOverTcpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsOverTcpConnection")
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S> DnsOverTcpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<SerializedRequest>, io::Error>> {
        let mut this = self.as_mut().project();
        loop {
            match &mut this.read_state {
                ReadTcpState::LenBytes { pos, bytes } => {
                    let mut buf = tokio::io::ReadBuf::new(&mut bytes[*pos..]);
                    match ready!(this.stream.as_mut().poll_read(cx, &mut buf)) {
                        Ok(()) => {
                            if buf.filled().len() == 0 {
                                // EOF implied
                                if *pos == 0 {
                                    trace!("EOF at message boundary");
                                    return Poll::Ready(Ok(None));
                                } else {
                                    trace!("EOF while reading message length");
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "EOF while reading message length",
                                    )));
                                }
                            }
                            *pos += buf.filled().len();
                            if *pos == bytes.len() {
                                // Length read, start reading the rest
                                let data_len = u16::from_be_bytes(*bytes);
                                trace!(n=%data_len, "data length read");
                                let buf = BytesMut::with_capacity(data_len as _);
                                *this.read_state = ReadTcpState::Bytes { pos: 0, bytes: buf };
                            }
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                ReadTcpState::Bytes { pos, bytes } => {
                    let mut buf = tokio::io::ReadBuf::new(bytes);
                    match ready!(this.stream.as_mut().poll_read(cx, &mut buf)) {
                        Ok(()) => {
                            if buf.filled().len() == 0 {
                                // EOF implied

                                trace!("EOF while reading message");
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "EOF while reading message",
                                )));
                            }
                            *pos += buf.filled().len();
                            if *pos == bytes.len() {
                                // Message read
                                if let ReadTcpState::Bytes { bytes, .. } = std::mem::replace(
                                    this.read_state,
                                    ReadTcpState::LenBytes {
                                        pos: 0,
                                        bytes: [0; 2],
                                    },
                                ) {
                                    let addr = this.stream.peer_addr()?;
                                    let msg = SerializedRequest::new(
                                        SerialMessage::new(bytes.into(), addr),
                                        hickory_proto::xfer::Protocol::Tcp,
                                    );
                                    return Poll::Ready(Ok(Some(msg)));
                                } else {
                                    panic!("TCP read state error: expected message found length");
                                }
                            }
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
            }
        }
    }

    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.write_state.is_none() {
            // Nothing to do, exit early.
            return Poll::Ready(Ok(()));
        }

        let mut this = self.as_mut().project();
        loop {
            match this.write_state {
                Some(WriteTcpState::Bytes { bytes }) => {
                    match ready!(this.stream.as_mut().poll_write(cx, &bytes)) {
                        Ok(n_written) => {
                            bytes.advance(n_written);
                            if bytes.is_empty() {
                                *this.write_state = Some(WriteTcpState::Flushing);
                            }
                        }
                        Err(error) => return Err(error).into(),
                    }
                }
                Some(WriteTcpState::Flushing) => {
                    match ready!(this.stream.as_mut().poll_flush(cx)) {
                        Ok(()) => {
                            *this.write_state = None;
                        }
                        Err(error) => {
                            trace!("Error during flush: {error}");
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                Some(WriteTcpState::LenBytes { pos, length, bytes }) => {
                    match ready!(this.stream.as_mut().poll_write(cx, length)) {
                        Ok(n) => {
                            *pos += n;
                            if *pos == 2 {
                                *this.write_state = Some(WriteTcpState::Bytes {
                                    bytes: bytes.clone(),
                                });
                            }
                        }
                        Err(_) => todo!(),
                    }
                }
                None => todo!(),
            }
        }
    }

    fn poll_recv(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.write_state.is_some() {
            // Don't poll for new inbound messages until the outbound messsages are done.
            return Poll::Ready(Ok(()));
        }
        let this = self.as_mut().project();
        match ready!(this.outgoing.poll_recv(cx)) {
            Some(msg) => {
                let (data, _) = msg.into_parts();
                let len_bytes: u16 = data.len().try_into().map_err(|_| {
                    trace!(n=%data.len(), "message won't fit length in u16");
                    io::Error::new(io::ErrorKind::InvalidData, "Message is too large")
                })?;
                let length = u16::to_be_bytes(len_bytes);
                trace!(n=%len_bytes, "setting up write");
                *this.write_state = Some(WriteTcpState::LenBytes {
                    pos: 0,
                    length,
                    bytes: data.into(),
                });
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Outgoing message pipe has closed",
            ))),
        }
    }
}

impl<S> Future for DnsOverTcpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
    S::Future: Send + 'static,
{
    type Output = Result<(), HickoryError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        ready!(self.service.poll_ready(cx))?;

        loop {
            match self.as_mut().poll_recv(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(HickoryError::Send(err))),
                Poll::Pending => {}
            };

            match self.as_mut().poll_write(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(HickoryError::Send(err))),
                Poll::Pending => break,
            };
        }
        if self.cancelled {
            return Poll::Pending;
        }

        loop {
            match self.as_mut().poll_read(cx) {
                Poll::Ready(Ok(Some(request))) => {
                    if let Some(sender) = self.incoming.clone() {
                        let future = self.service.call(request);
                        tokio::spawn(async move {
                            match future.await {
                                Ok(response) => {
                                    if let Err(_) = sender.send(response) {
                                        error!("Error sending response");
                                    }
                                }
                                Err(error) => {
                                    error!("Error handling request: {error}");
                                }
                            }
                        });
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }

                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(HickoryError::Recv(err))),
                Poll::Pending => break,
            }
        }
        Poll::Pending
    }
}

impl<S> Connection for DnsOverTcpConnection<S>
where
    S: tower::Service<SerializedRequest, Response = SerialMessage, Error = HickoryError>,
{
    fn graceful_shutdown(mut self: Pin<&mut Self>) {
        self.cancelled = true;
        self.incoming.take();
    }
}
