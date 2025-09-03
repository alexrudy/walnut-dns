use chrono::{DateTime, Utc};
use hickory_proto::{
    ProtoError, ProtoErrorKind,
    op::{Query, ResponseCode},
    rr::{Name, RData, RecordType},
    xfer::DnsResponse,
};

use crate::{
    cache::CacheTimestamp,
    rr::{QueryID, Record, TimeToLive},
};

/// Result of a query lookup
///
/// This can represent negative caches, nxdomain responses, and regular responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryLookup {
    id: QueryID,
    query: Query,
    records: Box<[Record]>,
    negative_ttl: Option<TimeToLive>,
    response_code: ResponseCode,
    valid_until: CacheTimestamp,
}

impl QueryLookup {
    pub fn new(
        id: QueryID,
        query: Query,
        records: Box<[Record]>,
        valid_until: CacheTimestamp,
    ) -> Self {
        Self {
            id,
            query,
            records,
            negative_ttl: None,
            response_code: ResponseCode::NoError,
            valid_until,
        }
    }

    pub fn no_records(query: Query, response_code: ResponseCode) -> Self {
        Self {
            id: QueryID::new(),
            query,
            records: Box::new([]),
            negative_ttl: None,
            response_code,
            valid_until: CacheTimestamp::now(),
        }
    }

    pub fn from_records(query: Query, records: Vec<Record>) -> Self {
        Self {
            id: QueryID::new(),
            query,
            records: records.into(),
            negative_ttl: None,
            response_code: ResponseCode::NoError,
            valid_until: CacheTimestamp::now() + TimeToLive::DEFAULT,
        }
    }

    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let records = vec![Record::from_rdata(
            query.name().clone(),
            TimeToLive::DEFAULT,
            rdata,
        )]
        .into();
        Self {
            id: QueryID::new(),
            query,
            records,
            negative_ttl: None,
            response_code: ResponseCode::NoError,
            valid_until: CacheTimestamp::now() + TimeToLive::DEFAULT,
        }
    }

    pub fn id(&self) -> QueryID {
        self.id
    }

    pub fn ttl(&self, now: DateTime<Utc>) -> TimeToLive {
        self.valid_until.since(now).into()
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn records(&self) -> &[Record<RData>] {
        &self.records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn is_nx_domain(&self) -> bool {
        self.response_code == ResponseCode::NXDomain
    }

    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    pub fn soa(&self) -> Option<&Record> {
        self.records
            .iter()
            .find(|rr| rr.record_type() == RecordType::SOA)
    }

    pub fn ns(&self) -> impl Iterator<Item = &Record> {
        self.records
            .iter()
            .filter(|rr| rr.record_type() == RecordType::NS)
    }

    pub fn glue(&self, name: &Name) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(move |rr| rr.name() == name)
    }

    pub fn negative_ttl(&self) -> Option<TimeToLive> {
        self.negative_ttl
    }

    pub fn valid_until(&self) -> CacheTimestamp {
        self.valid_until
    }
}

impl TryFrom<DnsResponse> for QueryLookup {
    type Error = ProtoError;

    fn try_from(response: DnsResponse) -> Result<Self, Self::Error> {
        let (message, _) = response.into_parts();
        let ttl = message
            .answers()
            .iter()
            .map(|rr| rr.ttl().into())
            .min()
            .unwrap_or(TimeToLive::MIN);
        let parts = message.into_parts();

        let deadline = ttl.deadline();

        Ok(QueryLookup {
            id: QueryID::new(),
            query: parts
                .queries
                .into_iter()
                .next()
                .ok_or_else(|| ProtoErrorKind::BadQueryCount(0))?,
            records: parts
                .answers
                .into_iter()
                .chain(parts.additionals)
                .chain(parts.name_servers)
                .map(Record::from)
                .collect(),
            negative_ttl: None,
            response_code: parts.header.response_code(),
            valid_until: deadline.into(),
        })
    }
}
