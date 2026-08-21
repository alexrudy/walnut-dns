use hickory_proto::op::{Edns, Header, ResponseCode};

use crate::messages::Message;

/// Middleware which handles Edns validation and response.
#[derive(Debug, Clone)]
pub struct EdnsMiddleware<S> {
    service: S,
}

impl<S> EdnsMiddleware<S> {
    pub fn new(service: S) -> Self {
        Self { service }
    }

    fn handle_edns(&self, request: &Message) -> Result<Option<Edns>, Message> {
        if let Some(req_edns) = request.extensions().as_ref() {
            let mut response = Message::new();
            response.add_queries(request.queries().iter().cloned());
            let mut response_header = Header::response_from_request(request.header());

            let mut resp_edns: Edns = Edns::new();

            // check our version against the request
            // TODO: what version are we?
            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                tracing::warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response_header.set_response_code(ResponseCode::BADVERS);
                resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                response.set_edns(resp_edns);
                response.set_header(response_header);

                return Err(response);
            }
            Ok(Some(resp_edns))
        } else {
            Ok(None)
        }
    }
}

impl<S> tower::Service<Message> for EdnsMiddleware<S>
where
    S: tower::Service<Message, Response = Message>,
{
    type Response = Message;

    type Error = S::Error;

    type Future = self::future::EdnsMiddlewareFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let edns = match self.handle_edns(&req) {
            Err(message) => return self::future::EdnsMiddlewareFuture::ready(message),
            Ok(edns) => edns,
        };

        let future = self.service.call(req);
        self::future::EdnsMiddlewareFuture::future(future, edns)
    }
}

#[derive(Debug, Clone)]
pub struct EdnsLayer {
    _priv: (),
}

impl<S> tower::Layer<S> for EdnsLayer {
    type Service = EdnsMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        EdnsMiddleware::new(service)
    }
}

mod future {

    use std::pin::Pin;
    use std::task::{Poll, ready};

    use hickory_proto::op::Edns;
    use pin_project::pin_project;

    use crate::messages::Message;

    #[pin_project(project = StateProj)]
    enum State<F> {
        Future {
            #[pin]
            future: F,
            edns: Option<Edns>,
        },
        Ready(Option<Message>),
    }

    #[pin_project]
    pub struct EdnsMiddlewareFuture<F> {
        #[pin]
        state: State<F>,
    }

    impl<F> EdnsMiddlewareFuture<F> {
        pub(super) fn ready(response: Message) -> Self {
            Self {
                state: State::Ready(Some(response)),
            }
        }

        pub(super) fn future(future: F, edns: Option<Edns>) -> Self {
            Self {
                state: State::Future { future, edns },
            }
        }
    }

    impl<F, E> Future for EdnsMiddlewareFuture<F>
    where
        F: Future<Output = Result<Message, E>>,
    {
        type Output = Result<Message, E>;

        fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
            let state = self.project().state;
            match state.project() {
                StateProj::Future { future, edns } => {
                    let mut response = ready!(future.poll(cx))?;
                    if let Some(edns) = edns.take() {
                        response.set_edns(edns);
                    };
                    Poll::Ready(Ok(response))
                }
                StateProj::Ready(message) => {
                    Poll::Ready(Ok(message.take().expect("future polled after completion")))
                }
            }
        }
    }
}
