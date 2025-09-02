//! DNS lookup and response types for the cache system.
//!
//! This module defines the core data structures used to represent cached DNS query
//! results, including successful lookups, NXDOMAIN responses, and timestamp handling.
//! It provides conversions between the hickory-proto types and the cache's internal
//! representation.

use std::{
    collections::HashMap,
    ops::{Add, Deref as _},
    time::Duration,
};

use chrono::{DateTime, TimeDelta, TimeZone as _, Utc};
use hickory_proto::{
    ProtoError, ProtoErrorKind,
    op::{Message, Query, ResponseCode},
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
    rr::{AsHickory as _, QueryID, Record, SqlName, TimeToLive},
};

/// Result of a successful DNS query.
///
/// Contains the query information, DNS records returned, and cache expiration timestamp.
/// This type represents positive DNS responses that can be cached.
///
/// # Examples
///
/// ```rust,ignore
/// let lookup = Lookup::new(
///     QueryID::new(),
///     query,
///     records,
///     valid_until_timestamp
/// );
///
/// // Get remaining TTL
/// let ttl = lookup.ttl(Utc::now());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    id: QueryID,
    query: Query,
    records: Vec<Record>,
    valid_until: CacheTimestamp,
}

impl Lookup {
    /// Creates a new lookup result.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this query
    /// * `query` - The original DNS query
    /// * `records` - DNS records returned in the response
    /// * `valid_until` - When this cache entry expires
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

    /// Returns the unique identifier for this lookup.
    pub fn id(&self) -> QueryID {
        self.id
    }

    /// Calculates the remaining TTL from the given timestamp.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp to calculate TTL from
    ///
    /// # Returns
    ///
    /// The remaining time-to-live for this cache entry.
    pub fn ttl(&self, now: DateTime<Utc>) -> TimeToLive {
        self.valid_until.since(now).into()
    }

    /// Returns a reference to the original query.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns the DNS records in this lookup result.
    pub fn records(&self) -> &[Record<RData>] {
        &self.records
    }

    /// Returns the cache expiration timestamp.
    pub fn valid_until(&self) -> CacheTimestamp {
        self.valid_until
    }
}

impl From<Lookup> for Message {
    fn from(lookup: Lookup) -> Self {
        let mut msg = Message::new();
        msg.add_query(lookup.query)
            .add_answers(lookup.records.into_iter().map(|r| r.as_hickory()));
        msg
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
                .chain(parts.additionals)
                .chain(parts.name_servers)
                .map(Record::from)
                .collect(),
            valid_until: deadline.into(),
        })
    }
}

/// Nameserver data with associated glue records.
///
/// Used in NXDOMAIN responses to provide referral information.
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

/// Represents a negative DNS response (NXDOMAIN, NODATA, etc.).
///
/// Contains the query information, authority records, and negative caching TTL.
/// This type represents DNS responses indicating that a requested record does not exist.
///
/// # Examples
///
/// ```rust,ignore
/// let nxdomain = NxDomain::new(
///     QueryID::new(),
///     query,
///     authority_records,
///     ResponseCode::NXDomain,
///     valid_until_timestamp
/// );
///
/// // Get negative TTL from SOA record
/// if let Some(ttl) = nxdomain.negative_ttl() {
///     // Use negative TTL
/// }
/// ```
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
    /// Creates a new NXDOMAIN response.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this query
    /// * `query` - The original DNS query
    /// * `records` - Authority records from the response
    /// * `response_code` - DNS response code (typically NXDOMAIN)
    /// * `valid_until` - When this cache entry expires
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

    /// Returns a reference to the original query.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns the SOA record if present.
    ///
    /// The SOA record provides authoritative information about the domain
    /// and is used to determine negative caching TTL.
    pub fn soa(&self) -> Option<&Record> {
        self.soa.as_ref()
    }

    /// Returns nameserver data with glue records if present.
    pub fn ns(&self) -> Option<&Vec<ForwardNSData>> {
        self.ns.as_ref()
    }

    /// Returns the negative caching TTL derived from the SOA record.
    ///
    /// This TTL determines how long the NXDOMAIN response should be cached.
    pub fn negative_ttl(&self) -> Option<TimeToLive> {
        self.negative_ttl
    }

    /// Returns the DNS response code.
    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    /// Returns additional authority records if present.
    pub fn authorities(&self) -> Option<&Vec<Record<RData>>> {
        self.authorities.as_ref()
    }

    /// Returns the cache expiration timestamp.
    pub fn valid_until(&self) -> CacheTimestamp {
        self.valid_until
    }

    /// Returns the unique identifier for this query.
    pub fn id(&self) -> QueryID {
        self.id
    }

    /// Returns an iterator over all records in this NXDOMAIN response.
    ///
    /// Iterates through SOA, authority, and nameserver records in order.
    pub fn records(&self) -> NxDomainRecords<'_> {
        NxDomainRecords::new(self)
    }
}

impl From<NxDomain> for Message {
    fn from(nxdomain: NxDomain) -> Self {
        let mut msg = Message::new();
        msg.add_query(nxdomain.query);

        if let Some(soa) = nxdomain.soa {
            msg.add_answer(soa.as_hickory());
        }
        if let Some(auth) = nxdomain.authorities {
            msg.add_additionals(auth.into_iter().map(|r| r.as_hickory()));
        }

        if let Some(ns) = nxdomain.ns {
            for nsd in ns {
                msg.add_name_server(nsd.ns.as_hickory());
                msg.add_additionals(nsd.glue.into_iter().map(|r| r.as_hickory()));
            }
        }

        msg.set_response_code(nxdomain.response_code);

        msg
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
                .chain(parts.additionals)
                .chain(parts.name_servers)
                .map(Record::from),
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
    #[allow(clippy::upper_case_acronyms)]
    NS,
    Glue(std::slice::Iter<'n, Record>),
    End,
}

enum State<'n> {
    #[allow(clippy::upper_case_acronyms)]
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

/// Metadata for a cached DNS query entry.
///
/// Contains the basic information about a cached query without the full record data.
/// Used as an intermediate type when retrieving entries from the database.
pub struct EntryMeta {
    id: QueryID,
    query: Query,
    response_code: ResponseCode,
    expires: CacheTimestamp,
}

impl EntryMeta {
    /// Returns the unique identifier for this query.
    pub fn id(&self) -> QueryID {
        self.id
    }

    /// Returns the cache expiration timestamp.
    pub fn expires(&self) -> CacheTimestamp {
        self.expires
    }

    /// Constructs a complete lookup result from metadata and associated records.
    ///
    /// Based on the response code, creates either a successful `Lookup` or an `NxDomain`.
    ///
    /// # Arguments
    ///
    /// * `records` - DNS records associated with this cache entry
    ///
    /// # Returns
    ///
    /// * `Ok(Lookup)` - For successful responses (NoError)
    /// * `Err(NxDomain)` - For negative responses (NXDOMAIN, etc.)
    #[allow(clippy::result_large_err)]
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

/// A cached DNS query result that can be either successful or negative.
///
/// This type unifies successful lookups and NXDOMAIN responses into a single
/// cacheable type. It provides a convenient interface for working with cached
/// DNS query results regardless of their success or failure.
///
/// # Examples
///
/// ```rust,ignore
/// // Successful lookup
/// let cached = CachedQuery::new(Ok(lookup));
///
/// // NXDOMAIN response
/// let cached = CachedQuery::new(Err(nxdomain));
///
/// // Check query type regardless of success/failure
/// let record_type = cached.query_type();
/// ```
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
    /// Creates a new cached query from a lookup result.
    ///
    /// # Arguments
    ///
    /// * `lookup` - Either a successful lookup or an NXDOMAIN response
    pub fn new(lookup: Result<Lookup, NxDomain>) -> Self {
        Self { lookup }
    }

    /// Returns the unique identifier for this query.
    pub fn id(&self) -> QueryID {
        match &self.lookup {
            Ok(lookup) => lookup.id(),
            Err(nxdomain) => nxdomain.id(),
        }
    }

    /// Returns a reference to the underlying lookup result.
    pub fn lookup(&self) -> &Result<Lookup, NxDomain> {
        &self.lookup
    }

    /// Returns the domain name being queried.
    pub fn name(&self) -> &Name {
        self.query().name()
    }

    /// Returns the DNS record type being queried.
    pub fn query_type(&self) -> RecordType {
        self.query().query_type()
    }

    /// Returns the DNS class of the query.
    pub fn query_class(&self) -> DNSClass {
        self.query().query_class()
    }

    /// Returns a reference to the original query.
    pub fn query(&self) -> &Query {
        match &self.lookup {
            Ok(lookup) => lookup.query(),
            Err(nxdomain) => nxdomain.query(),
        }
    }

    /// Converts this cached query into a DNS response.
    ///
    /// # Returns
    ///
    /// A `DnsResponse` suitable for sending to DNS clients.
    ///
    /// # Errors
    ///
    /// Returns a `ProtoError` if the response cannot be constructed.
    pub fn into_response(self) -> Result<DnsResponse, ProtoError> {
        match self.lookup {
            Ok(lookup) => DnsResponse::from_message(lookup.into()),
            Err(nxdomain) => DnsResponse::from_message(nxdomain.into()),
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

/// A timestamp used for cache expiration tracking.
///
/// Wraps a UTC datetime and provides methods for calculating time differences
/// and working with TTL values. Used throughout the cache system to track
/// when entries expire.
///
/// # Examples
///
/// ```rust,ignore
/// let now = CacheTimestamp::now();
/// let future = now + TimeToLive::from_secs(3600);
/// let duration = future.since(now);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTimestamp(DateTime<Utc>);

impl CacheTimestamp {
    /// Calculates the duration between this timestamp and another.
    ///
    /// # Arguments
    ///
    /// * `other` - The timestamp to calculate duration from
    ///
    /// # Returns
    ///
    /// The duration between the timestamps.
    ///
    /// # Panics
    ///
    /// Panics if the time delta is out of range for conversion to `Duration`.
    pub fn since(&self, other: DateTime<Utc>) -> Duration {
        self.0
            .signed_duration_since(other)
            .to_std()
            .expect("Time Delta out of range")
    }

    /// Creates a timestamp representing the current time.
    pub fn now() -> Self {
        CacheTimestamp(Utc::now())
    }

    /// Checks if this timestamp represents an expired cache entry.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp to check against
    ///
    /// # Returns
    ///
    /// `true` if this timestamp is in the past relative to `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.0 <= now
    }

    /// Returns the underlying UTC timestamp.
    pub fn as_utc(&self) -> DateTime<Utc> {
        self.0
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

/// Error indicating an invalid timestamp value in database conversion.
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, Record, rdata::A};
    use std::{str::FromStr, time::Duration};

    #[test]
    fn test_cache_timestamp_now() {
        let ts1 = CacheTimestamp::now();
        std::thread::sleep(Duration::from_millis(1));
        let ts2 = CacheTimestamp::now();
        assert!(ts2.0 > ts1.0);
    }

    #[test]
    fn test_cache_timestamp_since() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(300);
        let ts = CacheTimestamp::from(future);
        let duration = ts.since(now);
        assert_eq!(duration, Duration::from_secs(300));
    }

    #[test]
    fn test_cache_timestamp_add_ttl() {
        let now = CacheTimestamp::now();
        let ttl = TimeToLive::from_secs(3600);
        let future = now + ttl;
        assert!(future.0 > now.0);
    }

    #[test]
    fn test_lookup_construction() {
        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        let record = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A::new(192, 168, 1, 1)),
        );
        let valid_until = CacheTimestamp::now();
        let id = QueryID::new();

        let lookup = Lookup::new(id, query.clone(), vec![record.into()], valid_until);

        assert_eq!(lookup.id(), id);
        assert_eq!(lookup.query(), &query);
        assert_eq!(lookup.valid_until(), valid_until);
        assert_eq!(lookup.records().len(), 1);
    }

    #[test]
    fn test_lookup_ttl_calculation() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(300);
        let lookup = Lookup::new(
            QueryID::new(),
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::A),
            vec![],
            CacheTimestamp::from(future),
        );

        let ttl = lookup.ttl(now);
        assert_eq!(ttl, TimeToLive::from_secs(300));
    }

    #[test]
    fn test_cached_query_construction() {
        let lookup = Lookup::new(
            QueryID::new(),
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::A),
            vec![],
            CacheTimestamp::now(),
        );
        let cached = CachedQuery::new(Ok(lookup.clone()));

        assert_eq!(cached.id(), lookup.id());
        assert_eq!(cached.query(), lookup.query());
        assert_eq!(cached.name(), lookup.query().name());
        assert_eq!(cached.query_type(), RecordType::A);
    }

    #[test]
    fn test_nxdomain_construction() {
        let query = Query::query(Name::from_str("nonexistent.com.").unwrap(), RecordType::A);
        let soa_record = Record::from_rdata(
            Name::from_str("nonexistent.com.").unwrap(),
            3600,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_str("ns1.nonexistent.com.").unwrap(),
                Name::from_str("admin.nonexistent.com.").unwrap(),
                1,
                3600,
                1800,
                604800,
                86400,
            )),
        );

        let nxdomain = NxDomain::new(
            QueryID::new(),
            query,
            vec![soa_record.into()],
            ResponseCode::NXDomain,
            CacheTimestamp::now(),
        );

        assert_eq!(nxdomain.response_code(), ResponseCode::NXDomain);
        assert!(nxdomain.soa().is_some());
        assert_eq!(nxdomain.negative_ttl(), Some(TimeToLive::from_secs(3600)));
    }

    #[test]
    fn test_cache_timestamp_is_expired() {
        let now = Utc::now();
        let past = CacheTimestamp::from(now - chrono::Duration::seconds(300));
        let future = CacheTimestamp::from(now + chrono::Duration::seconds(300));

        assert!(past.is_expired(now));
        assert!(!future.is_expired(now));
        assert!(CacheTimestamp::from(now).is_expired(now));
    }

    #[test]
    fn test_cache_timestamp_as_utc() {
        let now = Utc::now();
        let timestamp = CacheTimestamp::from(now);
        assert_eq!(timestamp.as_utc(), now);
    }
}
