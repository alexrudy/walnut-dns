use std::{cmp::Ordering, fmt};

use chrono::{DateTime, Utc};
use hickory_proto::{
    dnssec::Proof,
    rr::{DNSClass, RData, RecordData, RecordType, RrKey},
    serialize::binary::{BinDecoder, Restrict},
};

use crate::database::FromRow;

use super::{AsHickory, RecordID, SqlName, ttl::TimeToLive};
use hickory_proto::rr::Name;

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
    /// Create a new DNS record from resource data
    ///
    /// Creates a new DNS record with the specified name, TTL, and resource data.
    /// The record is assigned a new unique ID and defaults to the IN class.
    ///
    /// # Arguments
    ///
    /// * `name` - The DNS name for this record
    /// * `ttl` - Time To Live for this record
    /// * `rdata` - The resource data for this record
    ///
    /// # Returns
    ///
    /// A new DNS record instance
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
    /// Create a DNS UPDATE record for deletion (type 0)
    ///
    /// Creates a special DNS record used in DNS UPDATE operations to indicate
    /// that all records of the specified type should be deleted.
    ///
    /// # Arguments
    ///
    /// * `name` - The DNS name for the update record
    /// * `ttl` - Time To Live for the update record
    /// * `rr_type` - The record type to delete
    ///
    /// # Returns
    ///
    /// A new DNS UPDATE record for deletion
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
    /// Convert this record to use generic RData
    ///
    /// Converts a typed record into a record with generic RData, which can hold
    /// any type of DNS resource record data.
    ///
    /// # Returns
    ///
    /// A new record with the same data but using generic RData
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

    /// Set the Time To Live for this record
    ///
    /// Updates the TTL value for this record, which determines how long
    /// DNS resolvers should cache this record.
    ///
    /// # Arguments
    ///
    /// * `ttl` - The new TTL value
    ///
    /// # Returns
    ///
    /// A mutable reference to this record for method chaining
    pub fn set_ttl(&mut self, ttl: TimeToLive) -> &mut Self {
        self.ttl = ttl;
        self
    }

    /// Set the DNS class for this record
    ///
    /// Updates the DNS class (typically IN for Internet) for this record.
    ///
    /// # Arguments
    ///
    /// * `dns_class` - The new DNS class
    ///
    /// # Returns
    ///
    /// A mutable reference to this record for method chaining
    pub fn set_dns_class(&mut self, dns_class: DNSClass) -> &mut Self {
        self.dns_class = dns_class;
        self
    }

    /// Set an expiration time for this record
    ///
    /// Sets when this record should be automatically deleted from the zone.
    /// This is used for temporary records that should not persist indefinitely.
    ///
    /// # Arguments
    ///
    /// * `expires` - The UTC timestamp when this record should expire
    ///
    /// # Returns
    ///
    /// A mutable reference to this record for method chaining
    pub fn set_expires(&mut self, expires: DateTime<Utc>) -> &mut Self {
        self.expires = Some(expires);
        self
    }

    /// Clear the expiration time for this record
    ///
    /// Removes any expiration time, making this record permanent until
    /// explicitly deleted.
    ///
    /// # Returns
    ///
    /// A mutable reference to this record for method chaining
    pub fn clear_expires(&mut self) -> &mut Self {
        self.expires = None;
        self
    }

    /// Check if this record has expired
    ///
    /// Returns true if the record has an expiration time set and that time
    /// has passed.
    ///
    /// # Returns
    ///
    /// `true` if the record has expired, `false` otherwise
    pub fn expired(&self) -> bool {
        self.expires.is_some_and(|expires| expires < Utc::now())
    }

    /// Set the data for this record
    ///
    /// Updates the data associated with this record.
    ///
    /// # Parameters
    ///
    /// - `rdata`: The new data to associate with this record
    ///
    /// # Returns
    ///
    /// A mutable reference to this record for method chaining
    pub fn set_data(&mut self, rdata: R) -> &mut Self {
        self.rdata = rdata;
        self
    }
}

impl<R: RecordData> Record<R> {
    /// Get the unique database identifier for this record
    ///
    /// Returns the unique ID assigned to this record when it was created.
    /// This ID is used internally for database operations.
    ///
    /// # Returns
    ///
    /// The unique record identifier
    pub fn id(&self) -> RecordID {
        self.id
    }

    /// Record Lookup Key for this Record Set
    pub fn rrkey(&self) -> RrKey {
        RrKey::new(self.name().into(), self.record_type())
    }

    /// Get the DNS name for this record
    ///
    /// Returns the fully qualified domain name that this record applies to.
    ///
    /// # Returns
    ///
    /// A reference to the DNS name
    pub fn name(&self) -> &Name {
        &self.name_labels
    }

    /// Get the DNS class for this record
    ///
    /// Returns the DNS class (typically IN for Internet) for this record.
    ///
    /// # Returns
    ///
    /// The DNS class
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Get the Time To Live for this record
    ///
    /// Returns the TTL value which determines how long DNS resolvers
    /// should cache this record.
    ///
    /// # Returns
    ///
    /// The TTL value
    pub fn ttl(&self) -> TimeToLive {
        self.ttl
    }

    /// Get the resource data for this record
    ///
    /// Returns a reference to the resource data, which contains the
    /// actual DNS record content (IP address, CNAME target, etc.).
    ///
    /// # Returns
    ///
    /// A reference to the resource data
    pub fn rdata(&self) -> &R {
        &self.rdata
    }

    /// Get the resource data for this record (alias for rdata)
    ///
    /// Returns a reference to the resource data, which contains the
    /// actual DNS record content (IP address, CNAME target, etc.).
    /// This is an alias for the `rdata()` method.
    ///
    /// # Returns
    ///
    /// A reference to the resource data
    pub fn data(&self) -> &R {
        &self.rdata
    }

    pub(crate) fn rdata_mut(&mut self) -> &mut R {
        &mut self.rdata
    }

    /// Get the record type for this record
    ///
    /// Returns the DNS record type (A, AAAA, CNAME, MX, etc.) that
    /// determines the format and meaning of the resource data.
    ///
    /// # Returns
    ///
    /// The DNS record type
    pub fn record_type(&self) -> RecordType {
        self.rdata.record_type()
    }

    /// Get the mDNS cache flush flag
    ///
    /// Returns whether this record should trigger cache flushing in mDNS.
    ///
    /// # Returns
    ///
    /// `true` if cache flushing should be triggered
    pub fn mdns_cache_flush(&self) -> bool {
        self.mdns_cache_flush
    }

    /// Set the mDNS cache flush flag
    ///
    /// Sets whether this record should trigger cache flushing in mDNS.
    ///
    /// # Arguments
    ///
    /// * `mdns_cache_flush` - Whether to enable cache flushing
    pub fn set_mdns_cache_flush(&mut self, mdns_cache_flush: bool) {
        self.mdns_cache_flush = mdns_cache_flush;
    }

    /// Get the expiration time for this record
    ///
    /// Returns the UTC timestamp when this record should be automatically
    /// deleted, or None if the record doesn't expire.
    ///
    /// # Returns
    ///
    /// The expiration timestamp, or None if no expiration is set
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
            name_labels: row.get::<_, SqlName>("name_labels")?.into(),
            dns_class: row.get::<_, u16>("dns_class")?.into(),
            ttl: row.get("ttl")?,
            rdata: RData::from_row(row)?,
            mdns_cache_flush: row.get("mdns_cache_flush")?,
            proof: Proof::default(),
            expires: row.get("expires")?,
        })
    }
}

impl From<hickory_proto::rr::Record<RData>> for Record<RData> {
    fn from(hrecord: hickory_proto::rr::Record<RData>) -> Self {
        let parts = hrecord.into_parts();
        Record {
            id: RecordID::new(),
            name_labels: parts.name_labels,
            dns_class: parts.dns_class,
            ttl: parts.ttl.into(),
            rdata: parts.rdata,
            mdns_cache_flush: parts.mdns_cache_flush,
            proof: parts.proof,
            expires: None,
        }
    }
}

impl<R: RecordData> AsHickory for Record<R> {
    type Hickory = hickory_proto::rr::Record<R>;

    fn as_hickory(&self) -> Self::Hickory {
        hickory_proto::rr::Record::from_rdata(
            self.name().clone(),
            self.ttl().into(),
            self.rdata().clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use hickory_proto::rr::{RecordType, rdata::A};

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com").unwrap()
    }

    fn create_test_a_record() -> Record<A> {
        let name = create_test_name();
        let ttl = TimeToLive::from(300);
        let rdata = A::new(192, 168, 1, 1);
        Record::from_rdata(name, ttl, rdata)
    }

    #[test]
    fn test_record_creation() {
        let record = create_test_a_record();

        assert!(record.name().to_utf8().starts_with("test.example.com"));
        assert_eq!(u32::from(record.ttl()), 300u32);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(record.record_type(), RecordType::A);
        assert!(!record.mdns_cache_flush());
        assert_eq!(record.expires(), None);
    }

    #[test]
    fn test_record_update0() {
        let name = create_test_name();
        let ttl = TimeToLive::from(600);
        let record = Record::update0(name.clone(), ttl, RecordType::A);

        assert_eq!(record.name(), &name);
        assert_eq!(record.ttl(), ttl);
        assert_eq!(record.record_type(), RecordType::A);

        if let RData::Update0(rt) = record.rdata() {
            assert_eq!(*rt, RecordType::A);
        } else {
            panic!("Expected Update0 rdata");
        }
    }

    #[test]
    fn test_record_id_uniqueness() {
        let record1 = create_test_a_record();
        let record2 = create_test_a_record();

        assert_ne!(record1.id(), record2.id());
    }

    #[test]
    fn test_record_ttl_modification() {
        let mut record = create_test_a_record();
        let new_ttl = TimeToLive::from(600);

        record.set_ttl(new_ttl);
        assert_eq!(record.ttl(), new_ttl);
    }

    #[test]
    fn test_record_expiration() {
        let mut record = create_test_a_record();
        let future_time = Utc::now() + Duration::hours(1);

        // Initially not expired and no expiration set
        assert!(!record.expired());
        assert_eq!(record.expires(), None);

        // Set expiration in the future
        record.set_expires(future_time);
        assert_eq!(record.expires(), Some(future_time));
        assert!(!record.expired());

        // Set expiration in the past
        let past_time = Utc::now() - Duration::hours(1);
        record.set_expires(past_time);
        assert!(record.expired());

        // Clear expiration
        record.clear_expires();
        assert_eq!(record.expires(), None);
        assert!(!record.expired());
    }

    #[test]
    fn test_record_mdns_cache_flush() {
        let mut record = create_test_a_record();

        assert!(!record.mdns_cache_flush());
        record.set_mdns_cache_flush(true);
        assert!(record.mdns_cache_flush());
        record.set_mdns_cache_flush(false);
        assert!(!record.mdns_cache_flush());
    }

    #[test]
    fn test_record_equality() {
        let name = create_test_name();
        let ttl = TimeToLive::from(300);
        let rdata = A::new(192, 168, 1, 1);

        let record1 = Record::from_rdata(name.clone(), ttl, rdata);
        let record2 = Record::from_rdata(name, TimeToLive::ZERO, rdata);

        // Records should be equal based on name, class, and rdata (not ID or TTL)
        assert_eq!(record1, record2);
    }

    #[test]
    fn test_record_into_record_rdata() {
        let record = create_test_a_record();
        let id = record.id();
        let name = record.name().clone();
        let ttl = record.ttl();

        let generic_record = record.into_record_rdata();

        assert_eq!(generic_record.id(), id);
        assert_eq!(generic_record.name(), &name);
        assert_eq!(generic_record.ttl(), ttl);
        assert_eq!(generic_record.record_type(), RecordType::A);
    }

    #[test]
    fn test_record_rrkey() {
        let record = create_test_a_record();
        let rrkey = record.rrkey();

        assert_eq!(
            rrkey.name(),
            &hickory_proto::rr::LowerName::from(record.name())
        );
        assert_eq!(rrkey.record_type, RecordType::A);
    }

    #[test]
    fn test_record_display() {
        let record = create_test_a_record();
        let display_str = format!("{record}");

        assert!(display_str.contains("test.example.com"));
        assert!(display_str.contains("300"));
        assert!(display_str.contains("IN"));
        assert!(display_str.contains("A"));
        assert!(display_str.contains("192.168.1.1"));
    }

    #[test]
    fn test_record_ordering() {
        let name1 = Name::from_utf8("a.example.com").unwrap();
        let name2 = Name::from_utf8("b.example.com").unwrap();
        let ttl = TimeToLive::from(300);
        let rdata = A::new(192, 168, 1, 1);

        let record1 = Record::from_rdata(name1, ttl, rdata);
        let record2 = Record::from_rdata(name2, ttl, rdata);

        // Convert to RData records for ordering comparison
        let rdata_record1 = record1.into_record_rdata();
        let rdata_record2 = record2.into_record_rdata();

        assert!(rdata_record1 < rdata_record2);
    }

    #[test]
    fn test_record_as_hickory() {
        let record = create_test_a_record();
        let hickory_record = record.as_hickory();

        assert_eq!(hickory_record.name(), record.name());
        assert_eq!(hickory_record.ttl(), u32::from(record.ttl()));
        assert_eq!(hickory_record.record_type(), record.record_type());
        assert_eq!(hickory_record.dns_class(), record.dns_class());
    }

    #[test]
    fn test_record_clone() {
        let record1 = create_test_a_record();
        let record2 = record1.clone();

        assert_eq!(record1.id(), record2.id());
        assert_eq!(record1.name(), record2.name());
        assert_eq!(record1.ttl(), record2.ttl());
        assert_eq!(record1.rdata(), record2.rdata());
    }
}
