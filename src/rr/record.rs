use std::{cmp::Ordering, fmt};

use chrono::{DateTime, Utc};
use hickory_proto::{
    dnssec::Proof,
    rr::{DNSClass, RData, RecordData, RecordType, RrKey},
    serialize::binary::{BinDecoder, Restrict},
};

use crate::database::FromRow;

use super::{AsHickory, RecordID, name::Name, ttl::TimeToLive};

/// DNS Resource Record with extra fields
///
/// The extra fields are `id` to provide a database ID for internal use, and `expires`,
/// an expiration timestamp to automatically delete a record from a primary zone at some
/// future point.
#[derive(Debug, Clone, Eq)]
pub struct Record<R: RecordData = RData> {
    id: RecordID,
    name_labels: Name,
    dns_class: DNSClass,
    ttl: TimeToLive,
    rdata: R,
    mdns_cache_flush: bool,
    proof: Proof,
    expires: Option<DateTime<Utc>>,
}

/// [RFC 1033](https://tools.ietf.org/html/rfc1033)
///
/// ```text
///   RESOURCE RECORDS
///
///   Records in the zone data files are called resource records (RRs).
///   They are specified in RFC-883 and RFC-973.  An RR has a standard
///   format as shown:
///
///           <name>   [<ttl>]   [<class>]   <type>   <data>
///
///   The record is divided into fields which are separated by white space.
///
///      <name>
///
///         The name field defines what domain name applies to the given
///         RR.  In some cases the name field can be left blank and it will
///         default to the name field of the previous RR.
///
///      <ttl>
///
///         TTL stands for Time To Live.  It specifies how long a domain
///         resolver should cache the RR before it throws it out and asks a
///         domain server again.  See the section on TTL's.  If you leave
///         the TTL field blank it will default to the minimum time
///         specified in the SOA record (described later).
///
///      <class>
///
///         The class field specifies the protocol group.  If left blank it
///         will default to the last class specified.
///
///      <type>
///
///         The type field specifies what type of data is in the RR.  See
///         the section on types.
///
///      <data>
///
///         The data field is defined differently for each type and class
///         of data.  Popular RR data formats are described later.
/// ```
impl<R: RecordData> fmt::Display for Record<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{name} {ttl} {class} {ty} {rdata} ; {id}{sp}{expires}",
            name = self.name_labels,
            ttl = self.ttl,
            class = self.dns_class,
            ty = self.record_type(),
            rdata = self.rdata,
            id = self.id,
            sp = self.expires.map(|_| " ").unwrap_or(""),
            expires = self.expires.map(|dt| dt.to_rfc3339()).unwrap_or("".into()),
        )?;

        Ok(())
    }
}

impl<R: RecordData> Record<R> {
    pub fn from_rdata(name: Name, ttl: TimeToLive, rdata: R) -> Self {
        Record {
            id: RecordID::new(),
            name_labels: name,
            dns_class: DNSClass::IN,
            ttl,
            rdata,
            mdns_cache_flush: false,
            proof: Proof::default(),
            expires: None,
        }
    }
}

impl Record {
    pub fn update0(name: Name, ttl: TimeToLive, rr_type: RecordType) -> Record {
        Record {
            id: RecordID::new(),
            name_labels: name,
            dns_class: DNSClass::IN,
            ttl,
            rdata: RData::Update0(rr_type),
            mdns_cache_flush: false,
            proof: Proof::default(),
            expires: None,
        }
    }
}

impl<R: RecordData> Record<R> {
    /// Converts the record into a record with generic record data
    pub fn into_record_rdata(self) -> Record<RData> {
        Record {
            id: self.id,
            name_labels: self.name_labels,
            dns_class: self.dns_class,
            ttl: self.ttl,
            rdata: self.rdata.into_rdata(),
            mdns_cache_flush: self.mdns_cache_flush,
            proof: self.proof,
            expires: self.expires,
        }
    }

    /// Sets the TTL, in seconds, to the specified value
    pub fn set_ttl(&mut self, ttl: TimeToLive) {
        self.ttl = ttl;
    }

    /// Set an expiry time for the record
    pub fn set_expires(&mut self, expires: DateTime<Utc>) {
        self.expires = Some(expires);
    }

    /// Clear the expiry time for the record
    pub fn clear_expires(&mut self) {
        self.expires = None;
    }

    /// Check if this record has expired
    pub fn expired(&self) -> bool {
        self.expires.is_some_and(|expires| expires < Utc::now())
    }

    pub(crate) fn set_data(&mut self, rdata: R) {
        self.rdata = rdata;
    }
}

impl<R: RecordData> Record<R> {
    /// Database Identifier for this record
    pub fn id(&self) -> RecordID {
        self.id
    }

    /// Record Lookup Key for this Record Set
    pub(crate) fn rrkey(&self) -> RrKey {
        RrKey::new(self.name().into(), self.record_type())
    }

    /// Label of the record resource
    pub fn name(&self) -> &Name {
        &self.name_labels
    }

    /// DNS Class of the record resource
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Time to Live of the record resource
    pub fn ttl(&self) -> TimeToLive {
        self.ttl
    }

    /// Record Data of the record resource
    pub fn rdata(&self) -> &R {
        &self.rdata
    }

    pub(crate) fn rdata_mut(&mut self) -> &mut R {
        &mut self.rdata
    }

    /// Record Type of the record resource
    pub fn record_type(&self) -> RecordType {
        self.rdata.record_type()
    }

    pub fn mdns_cache_flush(&self) -> bool {
        self.mdns_cache_flush
    }

    pub fn set_mdns_cache_flush(&mut self, mdns_cache_flush: bool) {
        self.mdns_cache_flush = mdns_cache_flush;
    }

    /// Time of expiration of the record resource
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        self.expires
    }
}

impl<R: RecordData> PartialEq for Record<R> {
    fn eq(&self, other: &Self) -> bool {
        self.name_labels == other.name_labels
            && self.dns_class == other.dns_class
            && self.rdata == other.rdata
    }
}

impl Ord for Record<RData> {
    /// Canonical ordering as defined by
    ///  [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
    ///
    /// ```text
    /// 6.2.  Canonical RR Form
    ///
    ///    For the purposes of DNS security, the canonical form of an RR is the
    ///    wire format of the RR where:
    ///
    ///    1.  every domain name in the RR is fully expanded (no DNS name
    ///        compression) and fully qualified;
    ///
    ///    2.  all uppercase US-ASCII letters in the owner name of the RR are
    ///        replaced by the corresponding lowercase US-ASCII letters;
    ///
    ///    3.  if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
    ///        HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
    ///        SRV, DNAME, A6, RRSIG, or NSEC, all uppercase US-ASCII letters in
    ///        the DNS names contained within the RDATA are replaced by the
    ///        corresponding lowercase US-ASCII letters;
    ///
    ///    4.  if the owner name of the RR is a wildcard name, the owner name is
    ///        in its original unexpanded form, including the "*" label (no
    ///        wildcard substitution); and
    ///
    ///    5.  the RR's TTL is set to its original value as it appears in the
    ///        originating authoritative zone or the Original TTL field of the
    ///        covering RRSIG RR.
    /// ```
    fn cmp(&self, other: &Self) -> Ordering {
        self.name_labels
            .cmp(&other.name_labels)
            .then(self.record_type().cmp(&other.record_type()))
            .then(self.dns_class.cmp(&other.dns_class))
            .then(self.ttl().cmp(&other.ttl()))
            .then(self.rdata().cmp(other.rdata()))
    }
}

impl PartialOrd for Record<RData> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromRow for RData {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized,
    {
        let buf: Vec<u8> = row.get("rdata")?;
        let record_type = row.get::<_, u16>("record_type")?.into();
        let mut decoder = BinDecoder::new(&buf);

        RData::read(&mut decoder, record_type, Restrict::new(buf.len() as u16)).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Blob, error.into())
        })
    }
}

impl FromRow for Record<RData> {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized,
    {
        Ok(Record {
            id: row.get("id")?,
            name_labels: row.get("name_labels")?,
            dns_class: row.get::<_, u16>("dns_class")?.into(),
            ttl: row.get("ttl")?,
            rdata: RData::from_row(row)?,
            mdns_cache_flush: row.get("mdns_cache_flush")?,
            proof: Proof::default(),
            expires: row.get("expires")?,
        })
    }
}

impl<R: RecordData> AsHickory for Record<R> {
    type Hickory = hickory_proto::rr::Record<R>;

    fn as_hickory(&self) -> Self::Hickory {
        hickory_proto::rr::Record::from_rdata(
            self.name().clone().into(),
            self.ttl().into(),
            self.rdata().clone(),
        )
    }
}
