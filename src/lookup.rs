//! Unified DNS lookup and response types.
//!
//! This module defines a unified data structure for representing all types of DNS query
//! results, including successful lookups, NXDOMAIN responses, and other negative responses.
//! It provides conversions between the hickory-proto types and the internal representation.

use std::{
    ops::Add,
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

/// A unified DNS lookup result that can represent any type of DNS response.
///
/// This type consolidates successful lookups, NXDOMAIN responses, and other negative
/// responses into a single structure. It contains the query information, DNS records,
/// response code, and cache expiration timestamp.
///
/// # Examples
///
/// ```rust,ignore
/// // Successful lookup
/// let lookup = Lookup::new(
///     QueryID::new(),
///     query,
///     records,
///     ResponseCode::NoError,
///     valid_until_timestamp
/// );
/// 
/// // Check if it's a successful response
/// if lookup.is_success() {
///     for record in lookup.answer_records() {
///         // Process answer records
///     }
/// } else if lookup.is_nxdomain() {
///     // Handle NXDOMAIN response
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    id: QueryID,
    query: Query,
    records: Vec<Record>,
    response_code: ResponseCode,
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
    /// * `response_code` - DNS response code indicating success or failure type
    /// * `valid_until` - When this cache entry expires
    pub fn new(
        id: QueryID,
        query: Query,
        records: Vec<Record>,
        response_code: ResponseCode,
        valid_until: CacheTimestamp,
    ) -> Self {
        Self {
            id,
            query,
            records,
            response_code,
            valid_until,
        }
    }

    /// Creates a lookup with no records and the specified response code.
    ///
    /// Useful for creating negative responses like NXDOMAIN.
    pub fn no_records(query: Query, response_code: ResponseCode) -> Self {
        Self {
            id: QueryID::new(),
            query,
            records: Vec::new(),
            response_code,
            valid_until: CacheTimestamp::now(),
        }
    }

    /// Creates a successful lookup from a list of records.
    pub fn from_records(query: Query, records: Vec<Record>) -> Self {
        Self {
            id: QueryID::new(),
            query,
            records,
            response_code: ResponseCode::NoError,
            valid_until: CacheTimestamp::now() + TimeToLive::DEFAULT,
        }
    }

    /// Creates a successful lookup from a single RData.
    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let records = vec![Record::from_rdata(
            query.name().clone(),
            TimeToLive::DEFAULT,
            rdata,
        )];
        Self {
            id: QueryID::new(),
            query,
            records,
            response_code: ResponseCode::NoError,
            valid_until: CacheTimestamp::now() + TimeToLive::DEFAULT,
        }
    }

    /// Returns the unique identifier for this lookup.
    pub fn id(&self) -> QueryID {
        self.id
    }

    /// Returns a reference to the original query.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns the domain name being queried.
    pub fn name(&self) -> &Name {
        self.query.name()
    }

    /// Returns the DNS record type being queried.
    pub fn query_type(&self) -> RecordType {
        self.query.query_type()
    }

    /// Returns the DNS class of the query.
    pub fn query_class(&self) -> DNSClass {
        self.query.query_class()
    }

    /// Returns the DNS response code.
    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    /// Returns all DNS records in this lookup result.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Returns the cache expiration timestamp.
    pub fn valid_until(&self) -> CacheTimestamp {
        self.valid_until
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
        self.valid_until.since(now.into()).into()
    }

    /// Checks if this represents a successful DNS response.
    ///
    /// # Returns
    ///
    /// `true` if the response code indicates success (NoError).
    pub fn is_success(&self) -> bool {
        matches!(self.response_code, ResponseCode::NoError)
    }

    /// Checks if this represents an NXDOMAIN response.
    ///
    /// # Returns
    ///
    /// `true` if the response code indicates the domain does not exist.
    pub fn is_nxdomain(&self) -> bool {
        matches!(self.response_code, ResponseCode::NXDomain)
    }

    /// Checks if this represents a negative response (no records found).
    ///
    /// # Returns
    ///
    /// `true` if this is any type of negative response (NXDOMAIN, NODATA, etc.).
    pub fn is_negative(&self) -> bool {
        !self.is_success()
    }

    /// Checks if the lookup has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns answer records for successful lookups.
    ///
    /// Filters records to only include those that match the query type
    /// and are appropriate for the answer section.
    ///
    /// # Returns
    ///
    /// An iterator over answer records, or empty if this is a negative response.
    pub fn answer_records(&self) -> Box<dyn Iterator<Item = &Record> + '_> {
        if self.is_success() {
            Box::new(self.records
                .iter()
                .filter(|r| r.record_type() == self.query_type()))
        } else {
            Box::new([].iter())
        }
    }

    /// Returns the SOA record if present.
    ///
    /// The SOA record provides authoritative information about the domain
    /// and is used to determine negative caching TTL.
    ///
    /// # Returns
    ///
    /// The SOA record if present, or `None` if not found.
    pub fn soa(&self) -> Option<&Record> {
        self.records
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
    }

    /// Returns authority records (nameservers, SOA, etc.).
    ///
    /// # Returns
    ///
    /// An iterator over authority records.
    pub fn authority_records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(|r| {
            matches!(
                r.record_type(),
                RecordType::SOA | RecordType::NS | RecordType::DS
            )
        })
    }

    /// Returns NS records.
    ///
    /// # Returns
    ///
    /// An iterator over NS records.
    pub fn ns(&self) -> impl Iterator<Item = &Record> {
        self.records
            .iter()
            .filter(|rr| rr.record_type() == RecordType::NS)
    }

    /// Returns glue records for the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to find glue records for
    ///
    /// # Returns
    ///
    /// An iterator over glue records matching the name.
    pub fn glue(&self, name: &Name) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(move |rr| rr.name() == name)
    }

    /// Returns the negative caching TTL for negative responses.
    ///
    /// Derives the TTL from the SOA record's minimum field, which is used
    /// for negative caching according to RFC 2308.
    ///
    /// # Returns
    ///
    /// The negative TTL if this is a negative response with an SOA record.
    pub fn negative_ttl(&self) -> Option<TimeToLive> {
        if self.is_negative() {
            self.soa().and_then(|soa| {
                soa.data()
                    .as_soa()
                    .map(|soa_data| soa.ttl().min(soa_data.minimum().into()))
            })
        } else {
            None
        }
    }
}

impl From<Lookup> for Message {
    fn from(lookup: Lookup) -> Self {
        let mut msg = Message::new();
        msg.add_query(lookup.query.clone());
        msg.set_response_code(lookup.response_code);
        msg.set_message_type(hickory_proto::op::MessageType::Response);

        if lookup.is_success() {
            // Add answer records for successful responses
            let answers: Vec<_> = lookup.answer_records().map(|r| r.as_hickory()).collect();
            msg.add_answers(answers.iter().cloned());
        }

        // Add authority records for all response types
        let authorities: Vec<_> = lookup.authority_records().map(|r| r.as_hickory()).collect();
        msg.add_name_servers(authorities.iter().cloned());

        // Manually update header counts to match the actual records
        let mut header = msg.header().clone();
        header.set_answer_count(msg.answers().len() as u16);
        header.set_name_server_count(msg.name_servers().len() as u16);
        msg.set_header(header);

        msg
    }
}

impl TryFrom<DnsResponse> for Lookup {
    type Error = ProtoError;

    fn try_from(response: DnsResponse) -> Result<Self, Self::Error> {
        let response_code = response.response_code();
        let negative_ttl = response.negative_ttl().map(|ttl| ttl.into());
        let (message, _) = response.into_parts();
        let parts = message.into_parts();

        let ttl = if matches!(response_code, ResponseCode::NoError) {
            // For successful responses, use minimum TTL from answer records
            parts
                .answers
                .iter()
                .map(|rr| rr.ttl().into())
                .min()
                .unwrap_or(TimeToLive::MIN)
        } else {
            // For negative responses, use negative TTL from response
            negative_ttl.unwrap_or(TimeToLive::MIN)
        };

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
                .chain(parts.name_servers.into_iter())
                .chain(parts.additionals.into_iter())
                .map(Record::from)
                .collect(),
            response_code,
            valid_until: deadline.into(),
        })
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
    /// # Arguments
    ///
    /// * `records` - DNS records associated with this cache entry
    ///
    /// # Returns
    ///
    /// A unified `Lookup` that can represent any response type.
    pub fn into_lookup(self, records: Vec<Record>) -> Lookup {
        Lookup::new(self.id, self.query, records, self.response_code, self.expires)
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

    #[test]
    fn test_successful_lookup_construction() {
        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        let record = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A::new(192, 168, 1, 1))
        );
        let valid_until = CacheTimestamp::now();
        let id = QueryID::new();

        let lookup = Lookup::new(id, query.clone(), vec![record.into()], ResponseCode::NoError, valid_until);

        assert_eq!(lookup.id(), id);
        assert_eq!(lookup.query(), &query);
        assert_eq!(lookup.response_code(), ResponseCode::NoError);
        assert_eq!(lookup.valid_until(), valid_until);
        assert_eq!(lookup.records().len(), 1);
        assert!(lookup.is_success());
        assert!(!lookup.is_nxdomain());
        assert!(!lookup.is_negative());
        assert_eq!(lookup.answer_records().count(), 1);
    }

    #[test]
    fn test_nxdomain_lookup_construction() {
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
            ))
        );

        let lookup = Lookup::new(
            QueryID::new(),
            query,
            vec![soa_record.into()],
            ResponseCode::NXDomain,
            CacheTimestamp::now()
        );

        assert_eq!(lookup.response_code(), ResponseCode::NXDomain);
        assert!(lookup.is_nxdomain());
        assert!(lookup.is_negative());
        assert!(!lookup.is_success());
        assert!(lookup.soa().is_some());
        assert_eq!(lookup.negative_ttl(), Some(TimeToLive::from_secs(3600)));
        assert_eq!(lookup.answer_records().count(), 0);
    }

    #[test]
    fn test_lookup_ttl_calculation() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(300);
        let lookup = Lookup::new(
            QueryID::new(),
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::A),
            vec![],
            ResponseCode::NoError,
            CacheTimestamp::from(future)
        );

        let ttl = lookup.ttl(now);
        assert_eq!(ttl, TimeToLive::from_secs(300));
    }

    #[test]
    fn test_entry_meta_into_lookup() {
        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        let expires = CacheTimestamp::now();
        let id = QueryID::new();

        let meta = EntryMeta {
            id,
            query: query.clone(),
            response_code: ResponseCode::NoError,
            expires,
        };

        let lookup = meta.into_lookup(vec![]);
        assert_eq!(lookup.id(), id);
        assert_eq!(lookup.query(), &query);
        assert_eq!(lookup.response_code(), ResponseCode::NoError);
        assert_eq!(lookup.valid_until(), expires);
    }

    #[test]
    fn test_lookup_from_records() {
        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        let record = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A::new(192, 168, 1, 1))
        );

        let lookup = Lookup::from_records(query.clone(), vec![record.into()]);

        assert_eq!(lookup.query(), &query);
        assert_eq!(lookup.response_code(), ResponseCode::NoError);
        assert!(lookup.is_success());
        assert_eq!(lookup.records().len(), 1);
    }

    #[test]
    fn test_lookup_from_rdata() {
        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        let rdata = RData::A(A::new(192, 168, 1, 1));

        let lookup = Lookup::from_rdata(query.clone(), rdata);

        assert_eq!(lookup.query(), &query);
        assert_eq!(lookup.response_code(), ResponseCode::NoError);
        assert!(lookup.is_success());
        assert_eq!(lookup.records().len(), 1);
    }

    #[test]
    fn test_lookup_no_records() {
        let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);

        let lookup = Lookup::no_records(query.clone(), ResponseCode::NXDomain);

        assert_eq!(lookup.query(), &query);
        assert_eq!(lookup.response_code(), ResponseCode::NXDomain);
        assert!(lookup.is_nxdomain());
        assert!(lookup.is_empty());
        assert_eq!(lookup.records().len(), 0);
    }
}