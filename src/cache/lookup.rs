use std::{
    collections::HashMap,
    ops::{Add, Deref as _},
    time::Duration,
};

use chrono::{DateTime, TimeDelta, TimeZone as _, Utc};
use hickory_proto::{
    ProtoError, ProtoErrorKind,
    op::{Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
    xfer::DnsResponse,
};
use rusqlite::{
    ToSql,
    types::{FromSql, ToSqlOutput, Value},
};
use thiserror::Error;

use crate::{
    database::FromRow,
    rr::{QueryID, Record, SqlName, TimeToLive},
};

/// Result of a DNS query when querying for any record type supported by the Hickory DNS Proto library.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    id: QueryID,
    query: Query,
    records: Vec<Record>,
    valid_until: CacheTimestamp,
}

impl Lookup {
    pub fn new(
        id: QueryID,
        query: Query,
        records: Vec<Record>,
        valid_until: CacheTimestamp,
    ) -> Self {
        Lookup {
            id,
            query,
            records,
            valid_until,
        }
    }

    pub fn id(&self) -> QueryID {
        self.id
    }

    pub fn ttl(&self, now: DateTime<Utc>) -> TimeToLive {
        self.valid_until.since(now.into()).into()
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn records(&self) -> &[Record<RData>] {
        &self.records
    }

    pub fn valid_until(&self) -> CacheTimestamp {
        self.valid_until
    }
}

impl TryFrom<DnsResponse> for Lookup {
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

        Ok(Lookup {
            id: QueryID::new(),
            query: parts
                .queries
                .into_iter()
                .next()
                .ok_or_else(|| ProtoErrorKind::BadQueryCount(0))?,
            records: parts
                .answers
                .into_iter()
                .chain(parts.additionals.into_iter())
                .chain(parts.name_servers.into_iter())
                .map(|rr| Record::from(rr))
                .collect(),
            valid_until: deadline.into(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ForwardNSData {
    ns: Record,
    glue: Vec<Record>,
}

struct NxDomainRecordValues {
    soa: Option<Record>,
    ns: Option<Vec<ForwardNSData>>,
    authorities: Option<Vec<Record>>,
}

impl NxDomainRecordValues {
    fn from_records(records: impl Iterator<Item = Record>) -> Self {
        let mut mapped: HashMap<RecordType, Vec<_>> =
            records.into_iter().fold(HashMap::new(), |mut map, record| {
                map.entry(record.record_type()).or_default().push(record);
                map
            });

        let soa = mapped
            .remove(&RecordType::SOA)
            .and_then(|records| records.into_iter().next());

        let mut referral_nameservers = Vec::new();
        mapped
            .remove(&RecordType::NS)
            .into_iter()
            .flatten()
            .for_each(|ns| {
                if let Some(ns_name) = ns.data().as_ns() {
                    let mut glue = Vec::new();
                    glue.extend(
                        mapped
                            .get(&RecordType::A)
                            .into_iter()
                            .flatten()
                            .filter(|record| record.name() == ns_name.deref())
                            .cloned(),
                    );
                    glue.extend(
                        mapped
                            .get(&RecordType::AAAA)
                            .into_iter()
                            .flatten()
                            .filter(|record| record.name() == ns_name.deref())
                            .cloned(),
                    );

                    referral_nameservers.push(ForwardNSData { ns, glue })
                }
            });

        let ns = if referral_nameservers.is_empty() {
            None
        } else {
            Some(referral_nameservers)
        };

        let authorities = {
            let authorities: Vec<Record> = mapped.into_values().flatten().collect();
            if authorities.is_empty() {
                None
            } else {
                Some(authorities)
            }
        };

        NxDomainRecordValues {
            soa,
            ns,
            authorities,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NxDomain {
    id: QueryID,
    query: Query,
    soa: Option<Record>,
    ns: Option<Vec<ForwardNSData>>,
    negative_ttl: Option<TimeToLive>,
    response_code: ResponseCode,
    authorities: Option<Vec<Record>>,
    valid_until: CacheTimestamp,
}

impl NxDomain {
    pub fn new(
        id: QueryID,
        query: Query,
        records: Vec<Record>,
        response_code: ResponseCode,
        valid_until: CacheTimestamp,
    ) -> Self {
        let records = NxDomainRecordValues::from_records(records.into_iter());
        let negative_ttl = records
            .soa
            .as_ref()
            .map(|rr| rr.ttl().min(rr.data().as_soa().unwrap().minimum().into()));

        Self {
            id,
            query,
            soa: records.soa,
            ns: records.ns,
            negative_ttl,
            response_code,
            authorities: records.authorities,
            valid_until,
        }
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn soa(&self) -> Option<&Record> {
        self.soa.as_ref()
    }

    pub fn ns(&self) -> Option<&Vec<ForwardNSData>> {
        self.ns.as_ref()
    }

    pub fn negative_ttl(&self) -> Option<TimeToLive> {
        self.negative_ttl
    }

    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    pub fn authorities(&self) -> Option<&Vec<Record<RData>>> {
        self.authorities.as_ref()
    }

    pub fn valid_until(&self) -> CacheTimestamp {
        self.valid_until
    }

    pub fn id(&self) -> QueryID {
        self.id
    }

    pub fn records(&self) -> NxDomainRecords<'_> {
        NxDomainRecords::new(self)
    }
}

impl TryFrom<DnsResponse> for NxDomain {
    type Error = ProtoError;

    fn try_from(response: DnsResponse) -> Result<Self, Self::Error> {
        let response_code = response.response_code();
        let negative_ttl = response.negative_ttl().map(|ttl| ttl.into());
        let (message, _) = response.into_parts();
        let parts = message.into_parts();
        let record_fields = NxDomainRecordValues::from_records(
            parts
                .answers
                .into_iter()
                .chain(parts.additionals.into_iter())
                .chain(parts.name_servers.into_iter())
                .map(|rr| Record::from(rr)),
        );

        Ok(NxDomain {
            id: QueryID::new(),
            query: parts
                .queries
                .into_iter()
                .next()
                .ok_or_else(|| ProtoErrorKind::BadQueryCount(0))?,
            soa: record_fields.soa,
            ns: record_fields.ns,
            negative_ttl,
            response_code,
            authorities: record_fields.authorities,
            valid_until: negative_ttl
                .map(|ttl| ttl.deadline().into())
                .unwrap_or(CacheTimestamp::now()),
        })
    }
}

enum GlueState<'n> {
    NS,
    Glue(std::slice::Iter<'n, Record>),
    End,
}

enum State<'n> {
    SOA,
    Authorities(Option<std::slice::Iter<'n, Record>>),
    Glue(
        Option<std::slice::Iter<'n, ForwardNSData>>,
        Option<&'n ForwardNSData>,
        GlueState<'n>,
    ),
    End,
}

pub struct NxDomainRecords<'n> {
    nxdomain: &'n NxDomain,
    state: State<'n>,
}

impl<'n> NxDomainRecords<'n> {
    fn new(nxdomain: &'n NxDomain) -> Self {
        Self {
            nxdomain,
            state: State::SOA,
        }
    }
}

impl<'n> Iterator for NxDomainRecords<'n> {
    type Item = &'n Record;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
                State::SOA => {
                    self.state =
                        State::Authorities(self.nxdomain.authorities.as_ref().map(|rr| rr.iter()));
                    if let Some(soa) = &self.nxdomain.soa {
                        return Some(soa);
                    }
                }
                State::Authorities(auth) => {
                    if let Some(record) = auth.as_mut().and_then(|i| i.next()) {
                        return Some(record);
                    } else {
                        self.state = State::Glue(
                            self.nxdomain.ns.as_ref().map(|rr| rr.iter()),
                            None,
                            GlueState::NS,
                        );
                    }
                }
                State::Glue(iter, current, state) => {
                    if let Some(forwards) = current.or_else(|| iter.as_mut().and_then(|i| i.next()))
                    {
                        match state {
                            GlueState::NS => {
                                *state = GlueState::Glue(forwards.glue.iter());
                                return Some(&forwards.ns);
                            }
                            GlueState::Glue(iter) => {
                                if let Some(record) = iter.next() {
                                    return Some(record);
                                } else {
                                    *state = GlueState::End
                                }
                            }
                            GlueState::End => {
                                *current = iter.as_mut().and_then(|i| i.next());
                            }
                        }
                    } else {
                        self.state = State::End;
                    }
                }
                State::End => {
                    return None;
                }
            }
        }
    }
}

/// Temporary struct to hold the query row.
pub struct EntryMeta {
    id: QueryID,
    query: Query,
    response_code: ResponseCode,
    expires: CacheTimestamp,
}

impl EntryMeta {
    /// Database ID
    pub fn id(&self) -> QueryID {
        self.id
    }

    /// Expiration timestamp
    pub fn expires(&self) -> CacheTimestamp {
        self.expires
    }

    /// Construct a lookup result from an entry meta and associated records
    pub fn from_stored_records(self: EntryMeta, records: Vec<Record>) -> Result<Lookup, NxDomain> {
        if matches!(self.response_code, ResponseCode::NoError) {
            Ok(Lookup::new(self.id, self.query, records, self.expires))
        } else {
            Err(NxDomain::new(
                self.id,
                self.query,
                records,
                self.response_code,
                self.expires,
            ))
        }
    }
}

impl FromRow for EntryMeta {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized,
    {
        let query = {
            let name: Name = row.get::<_, SqlName>("name")?.into();
            let mut query = Query::new();
            query.set_name(name);
            query.set_query_type(row.get::<_, u16>("record_type")?.into());
            query.set_query_class(row.get::<_, u16>("dns_class")?.into());
            query
        };

        Ok(EntryMeta {
            id: row.get("id")?,
            query,
            response_code: row.get::<_, u16>("response_code")?.into(),
            expires: row.get("expires")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CachedQuery {
    lookup: Result<Lookup, NxDomain>,
}

impl From<Result<Lookup, NxDomain>> for CachedQuery {
    fn from(lookup: Result<Lookup, NxDomain>) -> Self {
        Self { lookup }
    }
}

impl CachedQuery {
    pub fn new(lookup: Result<Lookup, NxDomain>) -> Self {
        Self { lookup }
    }

    pub fn id(&self) -> QueryID {
        match &self.lookup {
            Ok(lookup) => lookup.id(),
            Err(nxdomain) => nxdomain.id(),
        }
    }

    pub fn lookup(&self) -> &Result<Lookup, NxDomain> {
        &self.lookup
    }

    pub fn name(&self) -> &Name {
        self.query().name()
    }

    pub fn query_type(&self) -> RecordType {
        self.query().query_type()
    }

    pub fn query_class(&self) -> DNSClass {
        self.query().query_class()
    }

    pub fn query(&self) -> &Query {
        match &self.lookup {
            Ok(lookup) => lookup.query(),
            Err(nxdomain) => nxdomain.query(),
        }
    }
}

impl TryFrom<DnsResponse> for CachedQuery {
    type Error = ProtoError;

    fn try_from(response: DnsResponse) -> Result<Self, Self::Error> {
        match response.response_code() {
            ResponseCode::NoError => Ok(CachedQuery {
                lookup: Ok(response.try_into()?),
            }),
            ResponseCode::NXDomain => Ok(CachedQuery {
                lookup: Err(response.try_into()?),
            }),
            _ => Err(ProtoError::from_response(response, false).unwrap_err()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTimestamp(DateTime<Utc>);

impl CacheTimestamp {
    pub fn since(&self, other: DateTime<Utc>) -> Duration {
        self.0
            .signed_duration_since(other)
            .to_std()
            .expect("Time Delta out of range")
    }

    pub fn now() -> Self {
        CacheTimestamp(Utc::now())
    }
}

impl Add<TimeToLive> for CacheTimestamp {
    type Output = CacheTimestamp;

    fn add(self, rhs: TimeToLive) -> Self::Output {
        CacheTimestamp(
            self.0
                .checked_add_signed(TimeDelta::seconds(rhs.into()))
                .unwrap(),
        )
    }
}

impl From<DateTime<Utc>> for CacheTimestamp {
    fn from(value: DateTime<Utc>) -> Self {
        CacheTimestamp(value)
    }
}

#[derive(Debug, Error)]
#[error("Not a valid timestamp")]
pub struct NotATimestamp;

impl FromSql for CacheTimestamp {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        i64::column_result(value).and_then(|timestamp| {
            Utc.timestamp_millis_opt(timestamp)
                .earliest()
                .map(CacheTimestamp)
                .ok_or_else(|| rusqlite::types::FromSqlError::Other(NotATimestamp.into()))
        })
    }
}

impl ToSql for CacheTimestamp {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(
            self.0.timestamp_millis(),
        )))
    }
}
