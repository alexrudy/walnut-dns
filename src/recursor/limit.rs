use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Clone)]
pub struct RecursionLimit<S> {
    /// Inner service which is called repeatedly.
    inner: S,

    max_depth: usize,
    depth: usize,
}

impl<S> RecursionLimit<S> {
    pub fn reset(&mut self) {
        self.depth = 0;
    }
}

impl<S, R> tower::Service<R> for RecursionLimit<S>
where
    S: tower::Service<R>,
{
    type Response = S::Response;

    type Error = RecursionError<S::Error>;

    type Future = self::future::RecursionLimitFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| RecursionError::Service(error))
    }

    fn call(&mut self, req: R) -> Self::Future {
        if self.depth >= self.max_depth {
            return self::future::RecursionLimitFuture::limit(self.max_depth);
        }
        let future = self.inner.call(req);
        self.depth += 1;
        self::future::RecursionLimitFuture::future(future)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecursionError<E> {
    #[error(transparent)]
    Service(E),

    #[error("Recursion depth {0} exceeded")]
    DepthExceeded(usize),
}

impl<E> RecursionError<E> {
    pub fn into_inner(self) -> Option<E> {
        match self {
            RecursionError::Service(e) => Some(e),
            RecursionError::DepthExceeded(_) => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LimitError<E> {
    #[error(transparent)]
    Service(E),

    #[error("Count {0} exceeded")]
    CountExceeded(usize),
}

impl<E> LimitError<E> {
    pub fn into_inner(self) -> Option<E> {
        match self {
            LimitError::Service(e) => Some(e),
            LimitError::CountExceeded(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryCountLimit<S> {
    inner: S,
    count: Arc<AtomicUsize>,
    limit: usize,
}

impl<S> QueryCountLimit<S> {
    pub fn new(inner: S, limit: usize) -> Self {
        Self {
            inner,
            count: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }
}

impl<S, R> tower::Service<R> for QueryCountLimit<S>
where
    S: tower::Service<R>,
{
    type Response = S::Response;

    type Error = LimitError<S::Error>;

    type Future = self::future::LimitFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| LimitError::Service(error))
    }

    fn call(&mut self, req: R) -> Self::Future {
        let depth = self.count.fetch_add(1, Ordering::Relaxed);
        if depth >= self.limit {
            return self::future::LimitFuture::limit(self.limit);
        }
        let future = self.inner.call(req);
        self::future::LimitFuture::future(future)
    }
}

mod future {
    use std::{pin::Pin, task::Poll};

    use super::{LimitError, RecursionError};

    #[derive(Debug)]
    #[pin_project::pin_project(project=LimitStateProject)]
    enum LimitState<F> {
        Future(#[pin] F),
        LimitExceeded(usize),
    }

    #[derive(Debug)]
    #[pin_project::pin_project]
    pub struct RecursionLimitFuture<F> {
        #[pin]
        state: LimitState<F>,
    }

    impl<F> RecursionLimitFuture<F> {
        pub(super) fn future(future: F) -> Self {
            RecursionLimitFuture {
                state: LimitState::Future(future),
            }
        }

        pub(super) fn limit(depth: usize) -> Self {
            RecursionLimitFuture {
                state: LimitState::LimitExceeded(depth),
            }
        }
    }

    impl<F, R, E> Future for RecursionLimitFuture<F>
    where
        F: Future<Output = Result<R, E>>,
    {
        type Output = Result<R, RecursionError<E>>;

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            match self.project().state.project() {
                LimitStateProject::Future(pin) => {
                    pin.poll(cx).map_err(|error| RecursionError::Service(error))
                }
                LimitStateProject::LimitExceeded(limit) => {
                    Poll::Ready(Err(RecursionError::DepthExceeded(*limit)))
                }
            }
        }
    }

    #[derive(Debug)]
    #[pin_project::pin_project]
    pub struct LimitFuture<F> {
        #[pin]
        state: LimitState<F>,
    }

    impl<F> LimitFuture<F> {
        pub(super) fn future(future: F) -> Self {
            LimitFuture {
                state: LimitState::Future(future),
            }
        }

        pub(super) fn limit(depth: usize) -> Self {
            LimitFuture {
                state: LimitState::LimitExceeded(depth),
            }
        }
    }

    impl<F, R, E> Future for LimitFuture<F>
    where
        F: Future<Output = Result<R, E>>,
    {
        type Output = Result<R, LimitError<E>>;

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            match self.project().state.project() {
                LimitStateProject::Future(pin) => {
                    pin.poll(cx).map_err(|error| LimitError::Service(error))
                }
                LimitStateProject::LimitExceeded(limit) => {
                    Poll::Ready(Err(LimitError::CountExceeded(*limit)))
                }
            }
        }
    }
}
