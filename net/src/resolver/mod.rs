pub mod hosts;
pub mod reserved;

pub use crate::lookup::QueryLookup;
use crate::{
    Catalog, Lookup,
    authority::{LookupError, Search},
    messages::DnsQuery,
};
pub use hosts::{HostsLayer, HostsResolver, HostsService};
pub use reserved::{ReservedNamesLayer, ReservedNamesResolver, ReservedNamesService, UsageArea};

pub type ResolverError = Box<dyn std::error::Error + Send + Sync>;

/// A service wrapper for a catalog that provides resolver behavior.
///
/// Resolvers map from Query to QueryLookup
#[derive(Debug, Clone)]
pub struct Resolver<A> {
    catalog: Catalog<A>,
}

impl<A> tower::Service<DnsQuery> for Resolver<A>
where
    A: Search + Lookup + Send + 'static,
{
    type Response = QueryLookup;

    type Error = LookupError;

    type Future = self::future::ResolverFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn call(&mut self, req: DnsQuery) -> Self::Future {
        let catalog = self.catalog.clone();

        self::future::ResolverFuture::new(async move { catalog.handle_lookup(req).await })
    }
}

mod future {
    use core::fmt;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use crate::authority::LookupError;

    use super::QueryLookup;

    pub struct ResolverFuture {
        inner: Pin<Box<dyn Future<Output = Result<QueryLookup, LookupError>> + Send + 'static>>,
    }

    impl fmt::Debug for ResolverFuture {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ResovlerFuture").finish()
        }
    }

    impl ResolverFuture {
        pub(super) fn new<F>(future: F) -> Self
        where
            F: Future<Output = Result<QueryLookup, LookupError>> + Send + 'static,
        {
            Self {
                inner: Box::pin(future),
            }
        }
    }

    impl Future for ResolverFuture {
        type Output = Result<QueryLookup, LookupError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.inner.as_mut().poll(cx)
        }
    }
}
