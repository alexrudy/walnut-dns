use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::Query;
use hickory_proto::rr::{RData, RecordType};
use tower::ServiceExt as _;
use tracing::{trace, warn};

use crate::authority::LookupError;
use crate::lookup::QueryLookup;

use crate::messages::DnsQuery;
use crate::recursor::limit::LimitError;

use super::limit::QueryCountLimit;

#[derive(Debug, Clone)]
pub struct CNameResolverLayer {
    cname_limit: usize,
}

impl CNameResolverLayer {
    pub fn new(cname_limit: usize) -> Self {
        Self { cname_limit }
    }
}

impl<S> tower::Layer<S> for CNameResolverLayer {
    type Service = CNameResolver<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CNameResolver::new(inner, self.cname_limit)
    }
}

/// Middleware which resovles CNAME records
#[derive(Debug, Clone)]
pub struct CNameResolver<S> {
    inner: S,
    cname_limit: usize,
}

impl<S> CNameResolver<S> {
    pub fn new(inner: S, cname_limit: usize) -> Self {
        Self { inner, cname_limit }
    }
}

impl<S> tower::Service<DnsQuery> for CNameResolver<S>
where
    S: tower::Service<DnsQuery, Response = QueryLookup, Error = LookupError>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    type Response = QueryLookup;

    type Error = LookupError;

    type Future = future::CNameResolverFuture<S, S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsQuery) -> Self::Future {
        let service = self.inner.clone();
        let mut service = std::mem::replace(&mut self.inner, service);

        let future = service.call(req.clone());
        future::CNameResolverFuture::new(future, service, req, self.cname_limit)
    }
}

/// CNAME Resolution algorithm.
async fn resolve_cname<S>(
    request: &DnsQuery,
    service: &QueryCountLimit<S>,
    mut response: QueryLookup,
) -> Result<QueryLookup, LookupError>
where
    S: tower::Service<DnsQuery, Response = QueryLookup, Error = LookupError> + Clone,
{
    let query_type = request.query_type();

    // Don't resolve CNAME for CNAME or ANY queries.
    if matches!(query_type, RecordType::CNAME | RecordType::ANY) {
        return Ok(response);
    }

    // Return early if there aren't any CNAME in the response.
    let has_cname = response
        .records()
        .iter()
        .any(|rec| matches!(rec.rdata(), RData::CNAME(_)));
    if !has_cname {
        return Ok(response);
    }

    // Start resolving CNAME chain, with a limit on the number of entries we will resolve.
    let mut cname_chain = Vec::new();

    for record in response.records.iter() {
        let RData::CNAME(name) = record.rdata() else {
            continue;
        };

        if response
            .records()
            .answers
            .iter()
            .any(|answer| answer.name() == &name.0)
        {
            trace!("CNAME {} already in answers", name);
            continue;
        }
        trace!("Processing {}", record.name());
        let cname_query = Query::query(name.0.clone(), query_type);
        let cname_dns_query = DnsQuery::new(cname_query, request.extensions().cloned());

        // Query depth is implicitly checked by QueryCountLimit
        let cname_response = match service.clone().oneshot(cname_dns_query).await {
            Ok(cname_response) => cname_response,
            Err(LimitError::Service(error)) => {
                return Err(error);
            }
            Err(LimitError::CountExceeded(limit)) => {
                warn!("CNAME limit exceeded: {} queries", limit);
                return Ok(response);
            }
        };
        cname_chain.extend(cname_response.records().answers.iter().filter_map(|rr| {
            if rr.record_type() == query_type || rr.record_type() == RecordType::CNAME {
                trace!(type=%rr.record_type(), "Adding {} to chain", rr.name());
                return Some(rr.clone());
            }

            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = rr.rdata() {
                let type_covered = rrsig.type_covered();
                trace!(type=%type_covered, "Adding signature {} to chain", rr.name());
                if type_covered == query_type || type_covered == RecordType::CNAME {
                    return Some(rr.to_owned());
                }
            }

            None
        }));
    }

    if !cname_chain.is_empty() {
        response.records_mut().answers.extend(cname_chain);
    }

    Ok(response)
}

mod future {
    use std::{
        pin::Pin,
        task::{Poll, ready},
    };

    use hickory_proto::{
        op::Query,
        rr::{RData, RecordType},
    };
    use pin_project::pin_project;

    use crate::{
        authority::LookupError, lookup::QueryLookup, messages::DnsQuery,
        recursor::limit::QueryCountLimit,
    };

    use super::resolve_cname;

    #[pin_project(project=StateProject)]
    enum State<F> {
        Poll(#[pin] F),
        CName(Pin<Box<dyn Future<Output = Result<QueryLookup, LookupError>> + Send + 'static>>),
        Done,
    }

    #[pin_project]
    pub struct CNameResolverFuture<S, F> {
        #[pin]
        future: State<F>,
        service: QueryCountLimit<S>,
        request: DnsQuery,
    }

    impl<S, F> CNameResolverFuture<S, F> {
        pub(super) fn new(future: F, service: S, request: DnsQuery, limit: usize) -> Self {
            Self {
                future: State::Poll(future),
                service: QueryCountLimit::new(service, limit),
                request,
            }
        }
    }
    impl<S, F> CNameResolverFuture<S, F> where
        S: tower::Service<Query, Response = QueryLookup, Error = LookupError> + Clone
    {
    }

    impl<S, F> Future for CNameResolverFuture<S, F>
    where
        S: tower::Service<DnsQuery, Response = QueryLookup, Error = LookupError>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
        F: Future<Output = Result<QueryLookup, LookupError>>,
    {
        type Output = Result<QueryLookup, LookupError>;

        fn poll(
            self: Pin<&mut CNameResolverFuture<S, F>>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<Self::Output> {
            let mut this = self.project();
            loop {
                let response = match this.future.as_mut().project() {
                    StateProject::Poll(pin) => ready!(pin.poll(cx))?,
                    StateProject::CName(future) => {
                        return Pin::new(future).poll(cx);
                    }
                    StateProject::Done => panic!("Polled future after completion"),
                };

                this.future.set(State::Done);
                let query_type = this.request.query_type();

                // Don't resolve CNAME for CNAME or ANY queries.
                if matches!(query_type, RecordType::CNAME | RecordType::ANY) {
                    return Poll::Ready(Ok(response));
                }

                // Return early if there aren't any CNAME in the response.
                let has_cname = response
                    .records()
                    .iter()
                    .any(|rec| matches!(rec.rdata(), RData::CNAME(_)));
                if !has_cname {
                    return Poll::Ready(Ok(response));
                }

                let query = this.request.clone();
                let service = this.service.clone();
                this.future.set(State::CName(Box::pin(async move {
                    resolve_cname(&query, &service, response).await
                })));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType, rdata},
    };

    use crate::{
        Catalog, ZoneInfo as _,
        authority::Records,
        catalog::{CatalogStore, InMemoryStore},
        messages::DnsQuery,
        recursor::cname::CNameResolverLayer,
        server::CatalogService,
    };
    use walnut_proto::rr::{Record, SerialNumber, TimeToLive, Zone, ZoneType};

    fn create_test_zone(name: &str) -> Zone {
        let name = Name::from_utf8(name).unwrap();
        let soa = rdata::SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        let soa_record = Record::from_rdata(name.clone(), TimeToLive::from(3600), soa);
        Zone::empty(name, soa_record, ZoneType::Primary, false)
    }

    fn create_test_a_record() -> Record {
        let name = Name::from_utf8("www.test.example.com.").unwrap();
        let ttl = TimeToLive::from(300);
        let rdata = rdata::A::new(192, 168, 1, 1);
        Record::from_rdata(name, ttl, rdata).into_record_rdata()
    }

    #[tokio::test]
    async fn simple_zone() {
        let store = InMemoryStore::new();
        let mut zone = create_test_zone("example.com.");
        let record = create_test_a_record();
        zone.upsert(record.clone(), SerialNumber::from(1)).unwrap();
        store.upsert(zone.origin().clone(), &[&zone]).await.unwrap();

        let found = store
            .find(&Name::from_utf8("example.com.").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin(), &Name::from_utf8("example.com.").unwrap());
        assert!(!found[0].is_empty());
    }

    #[tokio::test]
    async fn test_lookup_empty_zone() {
        use tower::ServiceExt as _;

        let store = InMemoryStore::new();
        let zone = create_test_zone("example.com.");
        store.upsert(zone.origin().clone(), &[&zone]).await.unwrap();

        let svc = tower::ServiceBuilder::new()
            .layer(CNameResolverLayer::new(3))
            .service(CatalogService::new(Catalog::new(store)));

        let query = DnsQuery::new(
            Query::query(Name::from_utf8("example.com.").unwrap(), RecordType::A),
            None,
        );

        let found = svc.oneshot(query).await.unwrap();
        assert_eq!(found.records().len(), 1);
    }
}
