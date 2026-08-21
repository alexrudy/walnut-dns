use std::{cmp::Ordering, fmt};

use chrono::{DateTime, Utc};
use hickory_proto::{
    ProtoError, ProtoErrorKind,
    dnssec::Proof,
    op::{Edns, EdnsFlags},
    rr::{DNSClass, RData, RecordData, RecordType, RrKey, rdata::OPT},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, Restrict},
};

use crate::serialize::sqlite::FromRow;

use super::{AsHickory, RecordID, SqlName, ttl::TimeToLive};
use hickory_proto::rr::Name;

/// From [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
/// ```text
/// The cache-flush bit is the most significant bit of the second
/// 16-bit word of a resource record in a Resource Record Section of a
/// Multicast DNS message (the field conventionally referred to as the
/// rrclass field), and the actual resource record class is the least
/// significant fifteen bits of this field.
/// ```
const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;

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
    glue: bool,
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
            "{name} {ttl} {class} {ty} {rdata} {glue}; {id}{sp}{expires}",
            name = self.name_labels,
            ttl = self.ttl,
            class = self.dns_class,
            ty = self.record_type(),
            rdata = self.rdata,
            id = self.id,
            sp = self.expires.map(|_| " ").unwrap_or(""),
            expires = self.expires.map(|dt| dt.to_rfc3339()).unwrap_or("".into()),
            glue = if self.glue { "(g) " } else { "" },
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
            glue: false,
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
            glue: false,
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
            glue: self.glue,
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

    /// Set a bit identifying this record as glue.
    ///
    /// Glue records are sent along with a response but not as part of the response,
    /// instead as a way for DNS servers to find other nameservers who might be able
    /// to answer the query.
    ///
    /// This flag is used when reconstructing responses for caching, or for sending glue
    /// records with a known zone.
    ///
    /// # Parameters
    /// - `glue`: Is this record a glue record?
    ///
    /// # Returns
    ///
    /// A mutable reference to this record for method chaining
    pub fn set_glue(&mut self, glue: bool) -> &mut Self {
        self.glue = glue;
        self
    }

    /// Checks if this is a glue record.
    pub fn is_glue(&self) -> bool {
        self.glue
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

    pub fn rdata_mut(&mut self) -> &mut R {
        &mut self.rdata
    }

    pub fn map_rdata<RR: RecordData>(self, f: impl FnOnce(R) -> Option<RR>) -> Option<Record<RR>> {
        f(self.rdata).map(|rdata| Record {
            rdata,
            id: self.id,
            name_labels: self.name_labels,
            dns_class: self.dns_class,
            ttl: self.ttl,
            mdns_cache_flush: self.mdns_cache_flush,
            proof: self.proof,
            expires: self.expires,
            glue: self.glue,
        })
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

pub struct RecordRef<'r, R> {
    record: &'r Record,
    rdata: &'r R,
}

impl<R: RecordData> Clone for RecordRef<'_, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: RecordData> Copy for RecordRef<'_, R> {}

impl<R: RecordData> RecordRef<'_, R> {
    /// Allocates space for a Record with the same fields
    pub fn to_owned(&self) -> Record<R> {
        Record {
            id: self.record.id,
            name_labels: self.record.name_labels.to_owned(),
            dns_class: self.record.dns_class,
            ttl: self.record.ttl,
            rdata: self.rdata.clone(),
            mdns_cache_flush: self.record.mdns_cache_flush,
            proof: self.record.proof,
            glue: self.record.glue,
            expires: self.record.expires,
        }
    }

    /// Returns the name of the record
    #[inline]
    pub fn name(&self) -> &Name {
        &self.record.name_labels
    }

    /// Returns the type of the RecordData in the record
    #[inline]
    pub fn record_type(&self) -> RecordType {
        self.rdata.record_type()
    }

    /// Returns the DNSClass of the Record, generally IN fro internet
    #[inline]
    pub fn dns_class(&self) -> DNSClass {
        self.record.dns_class
    }

    /// Returns the time-to-live of the record, for caching purposes
    #[inline]
    pub fn ttl(&self) -> TimeToLive {
        self.record.ttl
    }

    /// Returns the Record Data, i.e. the record information
    #[inline]
    pub fn data(&self) -> &R {
        self.rdata
    }

    /// Returns if the mDNS cache-flush bit is set or not
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
    #[inline]
    pub fn mdns_cache_flush(&self) -> bool {
        self.record.mdns_cache_flush
    }

    /// The Proof of DNSSEC validation for this record, this is only valid if some form of validation has occurred
    #[inline]
    pub fn proof(&self) -> Proof {
        self.record.proof
    }
}

impl<'a, R: RecordData> TryFrom<&'a Record> for RecordRef<'a, R> {
    type Error = &'a Record;

    fn try_from(record: &'a Record) -> Result<Self, Self::Error> {
        match R::try_borrow(&record.rdata) {
            None => Err(record),
            Some(rdata) => Ok(Self { record, rdata }),
        }
    }
}

impl FromRow for RData {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized,
    {
        let buf: Vec<u8> = row.get("rdata")?;
        let record_type = row.get::<_, u16>("record_type")?.into();

        // A zero-length RDATA is how RFC 2136 dynamic-update records (the deletion markers stored in
        // the record log) are represented. Mirror hickory's `Record::read`, which maps empty RDATA
        // to `Update0` rather than trying to decode absent type-specific data (which would fail for
        // most record types, e.g. an A record with no address bytes).
        if buf.is_empty() {
            return Ok(RData::Update0(record_type));
        }

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
            glue: row.get("glue")?,
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
            glue: false,
        }
    }
}

impl<'r> BinDecodable<'r> for Record<RData> {
    fn read(decoder: &mut BinDecoder<'r>) -> Result<Self, ProtoError> {
        // NAME            an owner name, i.e., the name of the node to which this
        //                 resource record pertains.
        let name_labels: Name = Name::read(decoder)?;

        // TYPE            two octets containing one of the RR TYPE codes.
        let record_type: RecordType = RecordType::read(decoder)?;

        let mut mdns_cache_flush = false;

        // CLASS           two octets containing one of the RR CLASS codes.
        let class: DNSClass = if record_type == RecordType::OPT {
            // verify that the OPT record is Root
            if !name_labels.is_root() {
                return Err(ProtoErrorKind::EdnsNameNotRoot(name_labels).into());
            }

            //  DNS Class is overloaded for OPT records in EDNS - RFC 6891
            DNSClass::for_opt(
                decoder.read_u16()?.unverified(/*restricted to a min of 512 in for_opt*/),
            )
        } else {
            let dns_class_value =
                decoder.read_u16()?.unverified(/*DNSClass::from_u16 will verify the value*/);
            if dns_class_value & MDNS_ENABLE_CACHE_FLUSH > 0 {
                mdns_cache_flush = true;
                DNSClass::from(dns_class_value & !MDNS_ENABLE_CACHE_FLUSH)
            } else {
                DNSClass::from(dns_class_value)
            }
        };

        // TTL             a 32 bit signed integer that specifies the time interval
        //                that the resource record may be cached before the source
        //                of the information should again be consulted.  Zero
        //                values are interpreted to mean that the RR can only be
        //                used for the transaction in progress, and should not be
        //                cached.  For example, SOA records are always distributed
        //                with a zero TTL to prohibit caching.  Zero values can
        //                also be used for extremely volatile data.
        // note: u32 seems more accurate given that it can only be positive
        let ttl = TimeToLive::from_secs(decoder.read_u32()?.unverified(/*any u32 is valid*/));

        // RDLENGTH        an unsigned 16 bit integer that specifies the length in
        //                octets of the RDATA field.
        let rd_length = decoder
            .read_u16()?
            .verify_unwrap(|u| (*u as usize) <= decoder.len())
            .map_err(|u| {
                ProtoError::from(format!(
                    "rdata length too large for remaining bytes, need: {} remain: {}",
                    u,
                    decoder.len()
                ))
            })?;

        // this is to handle updates, RFC 2136, which uses 0 to indicate certain aspects of pre-requisites
        //   Null represents any data.
        let rdata = if rd_length == 0 {
            RData::Update0(record_type)
        } else {
            // RDATA           a variable length string of octets that describes the
            //                resource.  The format of this information varies
            //                according to the TYPE and CLASS of the resource record.
            // Adding restrict to the rdata length because it's used for many calculations later
            //  and must be validated before hand
            RData::read(decoder, record_type, Restrict::new(rd_length))?
        };

        Ok(Self {
            id: RecordID::new(),
            name_labels,
            dns_class: class,
            ttl,
            rdata,
            mdns_cache_flush,
            proof: Proof::default(),
            expires: None,
            glue: false,
        })
    }
}

impl<R: RecordData> BinEncodable for Record<R> {
    fn emit(
        &self,
        encoder: &mut hickory_proto::serialize::binary::BinEncoder<'_>,
    ) -> Result<(), ProtoError> {
        self.name_labels.emit(encoder)?;
        self.record_type().emit(encoder)?;
        if self.mdns_cache_flush {
            encoder.emit_u16(u16::from(self.dns_class()) | MDNS_ENABLE_CACHE_FLUSH)?;
        } else {
            self.dns_class.emit(encoder)?;
        }
        encoder.emit_u32(self.ttl.into())?;

        // place the RData length
        let place = encoder.place::<u16>()?;

        // write the RData
        //   the None case is handled below by writing `0` for the length of the RData
        //   this is in turn read as `None` during the `read` operation.
        if !self.rdata.is_update() {
            self.rdata.emit(encoder)?;
        }

        // get the length written
        let len = encoder.len_since_place(&place);
        assert!(len <= u16::MAX as usize);

        // replace the location with the length
        place.replace(encoder, len as u16)?;
        Ok(())
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

// FIXME: this should be a TryFrom
impl<'a> From<&'a Record> for Edns {
    fn from(value: &'a Record) -> Self {
        assert!(value.record_type() == RecordType::OPT);

        let ttl: u32 = value.ttl().into();
        let rcode_high = ((ttl & 0xFF00_0000u32) >> 24) as u8;
        let version = ((ttl & 0x00FF_0000u32) >> 16) as u8;
        let flags = EdnsFlags::from((ttl & 0x0000_FFFFu32) as u16);
        let max_payload = u16::from(value.dns_class());

        let options = match value.data() {
            RData::Update0(..) | RData::NULL(..) => {
                // NULL, there was no data in the OPT
                OPT::default()
            }
            RData::OPT(option_data) => {
                option_data.clone() // TODO: Edns should just refer to this, have the same lifetime as the Record
            }
            _ => {
                // this should be a coding error, as opposed to a parsing error.
                panic!("rr_type doesn't match the RData: {:?}", value.data()) // valid panic, never should happen
            }
        };

        let mut edns = Self::new();
        edns.set_rcode_high(rcode_high);
        edns.set_version(version);
        *edns.flags_mut() = flags;
        edns.set_max_payload(max_payload);
        *edns.options_mut() = options;

        edns
    }
}

impl<'a> From<&'a Edns> for Record {
    /// This returns a Resource Record that is formatted for Edns(0).
    /// Note: the rcode_high value is only part of the rcode, the rest is part of the base
    fn from(value: &'a Edns) -> Self {
        // rebuild the TTL field
        let mut ttl: u32 = u32::from(value.rcode_high()) << 24;
        ttl |= u32::from(value.version()) << 16;
        ttl |= u32::from(u16::from(*value.flags()));

        // now for each option, write out the option array
        //  also, since this is a hash, there is no guarantee that ordering will be preserved from
        //  the original binary format.
        // maybe switch to: https://crates.io/crates/linked-hash-map/
        let mut record = Self::from_rdata(
            Name::root(),
            TimeToLive::from_secs(ttl),
            RData::OPT(value.options().clone()),
        );

        record.set_dns_class(DNSClass::for_opt(value.max_payload()));

        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use hickory_proto::rr::{RecordType, rdata::A};

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com.").unwrap()
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

        assert!(record.name().to_utf8().starts_with("test.example.com."));
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

        assert!(display_str.contains("test.example.com."));
        assert!(display_str.contains("300"));
        assert!(display_str.contains("IN"));
        assert!(display_str.contains("A"));
        assert!(display_str.contains("192.168.1.1"));
    }

    #[test]
    fn test_record_ordering() {
        let name1 = Name::from_utf8("a.example.com.").unwrap();
        let name2 = Name::from_utf8("b.example.com.").unwrap();
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
