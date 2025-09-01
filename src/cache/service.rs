use std::task::{Context, Poll};

use chrono::Utc;
use futures::future::BoxFuture;
use hickory_proto::{
    op::ResponseCode,
    xfer::{DnsRequest, DnsResponse},
};

use crate::{client::DNSClientError, rr::TimeToLive};

use super::DNSCache;

#[derive(Debug, Clone)]
pub struct DnsCacheService<S> {
    service: S,
    cache: DNSCache,
}

impl<S> DnsCacheService<S> {
    pub fn new(service: S, cache: DNSCache) -> Self {
        Self { service, cache }
    }
}

impl<S> tower::Service<DnsRequest> for DnsCacheService<S>
where
    S: tower::Service<DnsRequest, Response = DnsResponse, Error = DNSClientError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = DnsResponse;
    type Error = DNSClientError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let cache = self.cache.clone();
        let service = self.service.clone();
        let mut service = std::mem::replace(&mut self.service, service);
        Box::pin(async move {
            match cache
                .get(
                    req.query().expect("no query in DnsRequest").clone(),
                    Utc::now(),
                )
                .await
            {
                Ok(Some(answer)) => {
                    tracing::trace!("Cache hit, reconstructing answer message");
                    let mut msg = answer
                        .into_response()
                        .expect("protocol error from cached response");
                    msg.set_id(req.id());
                    Ok(msg)
                }
                Err(error) => Err(DNSClientError::Cache(error.into())),
                Ok(None) => {
                    tracing::trace!("Cache miss");

                    let response = service.call(req).await?;
                    let now = Utc::now();

                    if response.answer_count() > 0 {
                        let ttl = response
                            .soa()
                            .map(|r| TimeToLive::from_secs(r.ttl()))
                            .unwrap_or(TimeToLive::from_days(1));
                        if matches!(response.response_code(), ResponseCode::NoError) {
                            let lookup = response.clone().try_into()?;
                            cache
                                .insert_query(&lookup, now, ttl)
                                .await
                                .map_err(|error| DNSClientError::Cache(error.into()))?;
                        } else if matches!(response.response_code(), ResponseCode::NXDomain) {
                            let nxdomain = response.clone().try_into()?;
                            cache
                                .insert_nxdomain(&nxdomain, now, ttl)
                                .await
                                .map_err(|error| DNSClientError::Cache(error.into()))?;
                        }
                    }
                    Ok(response)
                }
            }
        })
    }
}
