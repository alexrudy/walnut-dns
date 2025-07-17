use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable as _, BinDecoder};
use hickory_proto::xfer::SerialMessage;
use hickory_server::{authority::MessageRequest, server::Request};
use tracing::trace;

use crate::server::request::SerializedRequest;

use crate::error::HickoryError;

#[derive(Debug, Clone, Default)]
pub struct DNSEncoderDecoderLayer {
    _priv: (),
}

impl DNSEncoderDecoderLayer {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> tower::Layer<S> for DNSEncoderDecoderLayer {
    type Service = DNSEncoderDecoder<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DNSEncoderDecoder::new(inner)
    }
}

/// A service that decodes and encodes DNS queries and responses.
#[derive(Debug, Clone, Default)]
pub struct DNSEncoderDecoder<S> {
    inner: S,
}

impl<S> DNSEncoderDecoder<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> tower::Service<SerializedRequest> for DNSEncoderDecoder<S>
where
    S: tower::Service<Request, Response = Message>,
    S::Error: Into<HickoryError>,
{
    type Response = SerialMessage;

    type Error = HickoryError;

    type Future = self::future::SerializerFuture<S::Future, S::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: SerializedRequest) -> Self::Future {
        //TODO: We could implement things like preserving the encoded query here...
        let addr = req.addr();
        let protocl = req.protocol();
        let mut decoder = BinDecoder::new(req.bytes());

        let message = match MessageRequest::read(&mut decoder) {
            Ok(mr) => mr,
            Err(error) => {
                trace!("Error decoding incoming message: {error}");
                return self::future::SerializerFuture::error(error);
            }
        };
        let request = Request::new(message, addr, req.protocol());
        let inner = self.inner.call(request);
        self::future::SerializerFuture::new(inner, addr, protocl)
    }
}

mod future {
    use std::future::Future;
    use std::marker::PhantomData;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll, ready};

    use hickory_proto::op::Message;
    use hickory_proto::xfer::{Protocol, SerialMessage};

    use crate::server::response::encode_response;

    use super::HickoryError;

    #[pin_project::pin_project(project = SerializerFutureStateProj)]
    enum SerializerFutureState<F> {
        Future {
            #[pin]
            future: F,
            dst: SocketAddr,
            protocol: Protocol,
        },
        Error(Option<HickoryError>),
    }

    /// Future returned by the DNSEncoderDecoderService
    #[pin_project::pin_project]
    pub struct SerializerFuture<F, E> {
        #[pin]
        state: SerializerFutureState<F>,

        _error: PhantomData<fn() -> E>,
    }

    impl<F, E> SerializerFuture<F, E> {
        pub(super) fn new(future: F, dst: SocketAddr, protocol: Protocol) -> Self {
            Self {
                state: SerializerFutureState::Future {
                    future,
                    dst,
                    protocol,
                },
                _error: PhantomData,
            }
        }

        pub(super) fn error<G: Into<HickoryError>>(error: G) -> Self {
            Self {
                state: SerializerFutureState::Error(Some(error.into())),
                _error: PhantomData,
            }
        }
    }

    impl<F, E> Future for SerializerFuture<F, E>
    where
        F: Future<Output = Result<Message, E>>,
        E: Into<HickoryError>,
    {
        type Output = Result<SerialMessage, HickoryError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.as_mut().project();
            match this.state.project() {
                SerializerFutureStateProj::Error(error) => {
                    Poll::Ready(Err(error.take().expect("future polled after ready")))
                }
                SerializerFutureStateProj::Future {
                    future,
                    dst,
                    protocol,
                } => match ready!(future.poll(cx)) {
                    Ok(response) => {
                        Poll::Ready(encode_response(response, *protocol, *dst).map_err(Into::into))
                    }
                    Err(error) => Poll::Ready(Err(error.into())),
                },
            }
        }
    }
}

#[cfg(test)]
mod test {}
