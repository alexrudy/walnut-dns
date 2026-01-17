use hickory_proto::rr::{DNSClass, LowerName, RData, RecordData, RecordType, RrKey};

use super::{AsHickory, SerialNumber, record::Record, ttl::TimeToLive};
use hickory_proto::rr::Name;

/// A collection of like resource records.
///
/// The collection consists of a list of resource records of the same type, and
/// a separate list of the singing records which secure these resource recrods.
///
/// The entire record set has a common TTL, and tracks the SOA Serial Number when
/// it was last updated.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordSet {
    name: Name,
    record_type: RecordType,
    dns_class: DNSClass,
    ttl: TimeToLive,
    records: Vec<Record>,
    rrsigs: Vec<Record>,
    serial: SerialNumber,
}

impl RecordSet {
    /// Create a new empty record set
    ///
    /// Creates a new record set for the specified name and record type.
    /// Records can be added later using the insert method.
    ///
    /// # Arguments
    ///
    /// * `name` - The DNS name for this record set
    /// * `record_type` - The DNS record type (A, AAAA, CNAME, etc.)
    ///
    /// # Returns
    ///
    /// A new empty record set
    pub fn new(name: Name, record_type: RecordType) -> Self {
        Self {
            name,
            record_type,
            dns_class: DNSClass::IN,
            ttl: TimeToLive::ZERO,
            records: Vec::new(),
            rrsigs: Vec::new(),
            serial: SerialNumber::ZERO,
        }
    }

    /// Create a record set from a single record
    ///
    /// Creates a new record set containing the specified record.
    ///
    /// # Arguments
    ///
    /// * `name` - The DNS name for this record set
    /// * `record` - The initial record to include
    ///
    /// # Returns
    ///
    /// A new record set containing the specified record
    pub fn from_record<R: RecordData>(name: Name, record: Record<R>) -> Self {
        let record = record.into_record_rdata();
        let mut rrset = Self {
            name,
            record_type: record.record_type(),
            dns_class: DNSClass::IN,
            ttl: record.ttl(),
            records: Vec::new(),
            rrsigs: Vec::new(),
            serial: SerialNumber::ZERO,
        };
        // This is a single record, so it is safe to skip the deduplication checks, updates, etc.
        rrset.records.push(record);
        rrset
    }

    /// Get the DNS name for this record set
    ///
    /// Returns the fully qualified domain name that all records in this set apply to.
    ///
    /// # Returns
    ///
    /// A reference to the DNS name
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Get the record type for this record set
    ///
    /// Returns the DNS record type (A, AAAA, CNAME, etc.) that all records
    /// in this set share.
    ///
    /// # Returns
    ///
    /// The DNS record type
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Get the DNS class for this record set
    ///
    /// Returns the DNS class (typically IN for Internet) that all records
    /// in this set share.
    ///
    /// # Returns
    ///
    /// The DNS class
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Set the DNS class for this record set
    ///
    /// Updates the DNS class for all records in this set.
    ///
    /// # Arguments
    ///
    /// * `dns_class` - The new DNS class
    ///
    /// # Returns
    ///
    /// A mutable reference to this record set for method chaining
    pub fn set_dns_class(&mut self, dns_class: DNSClass) -> &mut Self {
        self.dns_class = dns_class;
        self
    }

    /// Set the Time To Live for all records in this set
    ///
    /// Updates the TTL value for all records in this set, which determines
    /// how long DNS resolvers should cache these records.
    ///
    /// # Arguments
    ///
    /// * `ttl` - The new TTL value
    ///
    /// # Returns
    ///
    /// A mutable reference to this record set for method chaining
    pub fn set_ttl(&mut self, ttl: TimeToLive) -> &mut Self {
        self.ttl = ttl;
        for r in &mut self.records {
            r.set_ttl(ttl);
        }
        self
    }

    /// Create a copy of this record set with a different name
    ///
    /// Creates a new record set with the same records but a different DNS name.
    /// RRSIG signatures are cleared since they would be invalid for the new name.
    ///
    /// # Arguments
    ///
    /// * `name` - The new DNS name for the copied record set
    ///
    /// # Returns
    ///
    /// A new record set with the specified name
    pub fn with_name(&self, name: Name) -> Self {
        RecordSet {
            name: name.clone(),
            record_type: self.record_type,
            dns_class: self.dns_class,
            ttl: self.ttl,
            serial: self.serial,
            records: self.records.clone(),
            rrsigs: Default::default(),
        }
    }

    /// Get the Time To Live for this record set
    ///
    /// Returns the TTL value which determines how long DNS resolvers
    /// should cache records from this set.
    ///
    /// # Returns
    ///
    /// The TTL value
    pub fn ttl(&self) -> TimeToLive {
        self.ttl
    }

    /// Get the serial number for this record set
    ///
    /// Returns the serial number that tracks the last update to this record set.
    ///
    /// # Returns
    ///
    /// The serial number
    pub fn serial(&self) -> SerialNumber {
        self.serial
    }
}

impl RecordSet {
    /// Record Lookup Key for this Record Set
    pub fn rrkey(&self) -> RrKey {
        RrKey::new(self.name().into(), self.record_type())
    }

    /// Get an iterator over all records in this set
    ///
    /// Returns an iterator that yields all DNS records in the set,
    /// excluding any RRSIG signatures.
    ///
    /// # Returns
    ///
    /// An iterator over the records
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter()
    }

    pub(crate) fn records_mut(&mut self) -> impl Iterator<Item = &mut Record> {
        self.records.iter_mut()
    }

    /// Convert this record set into an iterator over its records
    ///
    /// Consumes the record set and returns an iterator over all DNS records,
    /// excluding any RRSIG signatures.
    ///
    /// # Returns
    ///
    /// An iterator that takes ownership of the records
    pub fn into_records(self) -> impl Iterator<Item = Record> {
        self.records.into_iter()
    }

    /// Convert this record set into an iterator over all records and signatures
    ///
    /// Consumes the record set and returns an iterator over all DNS records
    /// and their RRSIG signatures.
    ///
    /// # Returns
    ///
    /// An iterator that takes ownership of all records and signatures
    pub fn into_signed_records(self) -> impl Iterator<Item = Record> {
        self.records.into_iter().chain(self.rrsigs)
    }

    /// Get an iterator over all records and signatures in this set
    ///
    /// Returns an iterator that yields all DNS records in the set along
    /// with any RRSIG signatures.
    ///
    /// # Returns
    ///
    /// An iterator over all records and signatures
    pub fn signed_records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().chain(self.rrsigs.iter())
    }

    /// Get an iterator over all records in this set
    ///
    /// Returns an iterator that yields all DNS records in the set.
    ///
    /// # Returns
    ///
    /// An iterator over all records
    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().chain(self.rrsigs.iter())
    }

    /// Convert this record set into an iterator over all records and signatures
    ///
    /// Consumes the record set and returns an iterator over all DNS records
    /// and their RRSIG signatures.
    ///
    /// # Returns
    ///
    /// An iterator over all records and signatures
    pub fn into_hickory_iter(self) -> RecordSetIntoHickoryIter {
        RecordSetIntoHickoryIter(self.records.into_iter().chain(self.rrsigs.into_iter()))
    }

    /// Convert this record set into an iterator over all records and signatures
    ///
    /// Consumes the record set and returns an iterator over all DNS records
    /// and their RRSIG signatures.
    ///
    /// # Returns
    ///
    /// An iterator over all records and signatures
    pub fn hickory_iter(&self) -> RecordSetHickoryIter<'_> {
        RecordSetHickoryIter(self.records.iter().chain(self.rrsigs.iter()))
    }

    /// Check if this record set is empty
    ///
    /// Returns true if the record set contains no DNS records.
    /// RRSIG signatures are not counted.
    ///
    /// # Returns
    ///
    /// `true` if the record set contains no records
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get the number of records in this set
    ///
    /// Returns the count of DNS records in the set.
    /// RRSIG signatures are not counted.
    ///
    /// # Returns
    ///
    /// The number of records
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Get all RRSIG signatures for this record set
    ///
    /// Returns a slice containing all RRSIG records that provide
    /// DNSSEC signatures for the records in this set.
    ///
    /// # Returns
    ///
    /// A slice of RRSIG records
    pub fn rrsigs(&self) -> &[Record] {
        &self.rrsigs
    }

    #[allow(dead_code)]
    pub(crate) fn rrsigs_mut(&mut self) -> &mut Vec<Record> {
        &mut self.rrsigs
    }

    /// Insert an RRSIG signature for this record set
    ///
    /// Adds a DNSSEC signature (RRSIG) to this record set. The signature must
    /// cover the correct record type. Multiple signatures can be added.
    ///
    /// # Arguments
    ///
    /// * `rrsig` - The RRSIG record to add
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the signature is invalid
    ///
    /// # Errors
    ///
    /// Returns an error if the RRSIG doesn't cover the correct record type
    pub fn insert_rrsig(&mut self, rrsig: Record) -> Result<(), Mismatch> {
        if rrsig
            .rdata()
            .as_dnssec()
            .and_then(|dnssecdata| dnssecdata.as_rrsig())
            .map(|rrsig| rrsig.type_covered())
            != Some(self.record_type)
        {
            return Err(Mismatch("RRSIG Covered type"));
        }

        self.rrsigs.push(rrsig);
        Ok(())
    }

    /// Clear all RRSIG signatures from this record set
    ///
    /// Removes all DNSSEC signatures. This is useful when the record set
    /// is updated or when cryptographic keys are rotated.
    pub fn clear_rrsigs(&mut self) {
        self.rrsigs.clear()
    }

    /// Add a new record to this record set
    ///
    /// Creates a new record with the specified resource data and adds it
    /// to this record set. The record will use the set's name and TTL.
    ///
    /// # Arguments
    ///
    /// * `rdata` - The resource data for the new record
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the record was added, `Ok(false)` if it was a duplicate,
    /// or an error if the record is incompatible with this set
    ///
    /// # Errors
    ///
    /// Returns an error if the record type doesn't match this set
    pub fn push(&mut self, rdata: RData) -> Result<bool, Mismatch> {
        let record = Record::from_rdata(self.name.clone(), self.ttl, rdata);
        self.insert(record, SerialNumber::ZERO)
    }

    fn updated(&mut self, serial: SerialNumber) {
        self.serial = serial;
        self.rrsigs.clear(); // on updates, the rrsigs are invalid
    }

    /// Insert a record into this record set
    ///
    /// Adds a record to this set, handling deduplication and special rules
    /// for different record types (SOA, CNAME, etc.). Updates the serial number
    /// if the record set is modified.
    ///
    /// # Arguments
    ///
    /// * `record` - The record to insert
    /// * `serial` - The serial number for this update
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the record set was modified, `Ok(false)` if no change occurred,
    /// or an error if the record is incompatible
    ///
    /// # Errors
    ///
    /// Returns an error if the record's name or type doesn't match this set
    pub fn insert(&mut self, record: Record, serial: SerialNumber) -> Result<bool, Mismatch> {
        if record.name() != self.name() {
            return Err(Mismatch("name"));
        }
        if record.record_type() != self.record_type() {
            return Err(Mismatch("type"));
        }

        //TODO: Why only discard inserts when the SOA serials differ? The serial
        // argument is otherwise just used to track the last update?

        // 1.1.5. The following RR types cannot be appended to an RRset.  If the
        //  following comparison rules are met, then an attempt to add the new RR
        //  will result in the replacement of the previous RR:
        match record.record_type() {
            RecordType::SOA => {
                assert!(self.records.len() <= 1);

                // SOA    compare only NAME, CLASS and TYPE -- it is not possible to
                //         have more than one SOA per zone, even if any of the data
                //         fields differ.
                if let Some(soa_record) = self.records.first() {
                    match soa_record.rdata() {
                        RData::SOA(existing_soa) => {
                            if let RData::SOA(new_soa) = record.rdata() {
                                if SerialNumber::from(new_soa.serial())
                                    <= SerialNumber::from(existing_soa.serial())
                                {
                                    tracing::debug!(
                                        "update SOA ignored serial out of date: {:?} <= {:?}",
                                        new_soa,
                                        existing_soa
                                    );
                                    return Ok(false);
                                }
                            }
                        }
                        _ => unreachable!("Wrong rdata, expected SOA rdata"),
                    }
                }
                self.records.clear();
            }
            // CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
            //         to have more than one CNAME RR, even if their data fields
            //         differ.
            RecordType::CNAME | RecordType::ANAME => {
                assert!(self.records.len() <= 1);
                self.records.clear();
            }
            _ => (),
        };

        let mut ttl_modified = false;
        let mut found = false;

        for target in &mut self.records {
            if target.rdata() == record.rdata() {
                found = true;
                if target.ttl() != record.ttl() {
                    // Something is different, but RData is the same
                    ttl_modified = true
                }
                if target.expires() != record.expires() {
                    // The expiration date has updated. Since this isn't a canonical RR field,
                    // we don't trigger the serial number etc. in this case.
                    if let Some(expires) = record.expires() {
                        target.set_expires(expires);
                    } else {
                        target.clear_expires();
                    }
                }
            }
        }

        if ttl_modified {
            self.set_ttl(record.ttl());
            self.updated(serial);
            return Ok(true);
        }

        if !found {
            self.set_ttl(record.ttl());
            self.records.push(record);
            self.updated(serial);
            return Ok(true);
        }

        Ok(false)
    }

    /// Remove a record from this record set
    ///
    /// Removes records matching the specified record's resource data.
    /// Some record types (SOA, last NS) have special protection against removal.
    ///
    /// # Arguments
    ///
    /// * `record` - The record to remove (matched by resource data)
    /// * `serial` - The serial number for this update
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the record set was modified, `Ok(false)` if no change occurred,
    /// or an error if the record is incompatible
    ///
    /// # Errors
    ///
    /// Returns an error if the record's name or type doesn't match this set
    pub fn remove(&mut self, record: &Record, serial: SerialNumber) -> Result<bool, Mismatch> {
        if record.name() != self.name() {
            return Err(Mismatch("name"));
        }
        if record.record_type() != self.record_type() {
            return Err(Mismatch("type"));
        }

        match record.record_type() {
            // never delete the last NS record
            RecordType::NS => {
                if self.records.len() <= 1 {
                    tracing::warn!("ignoring delete of last NS record: {:?}", record);
                    return Ok(false);
                }
            }
            // never delete SOA
            RecordType::SOA => {
                tracing::warn!("ignored delete of SOA");
                return Ok(false);
            }
            _ => (), // move on to the delete
        }

        let before = self.records.len();
        self.records
            .retain(|target| target.rdata() != record.rdata());
        if before != self.records.len() {
            self.updated(serial);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Give a query type, if this record set points to a new name (e.g. via CNAME, ANAME, or another record which must be resolved)
    /// return the new name to resolve and the record type we are searching for now.
    pub(crate) fn next_lookup_name(
        &self,
        query_type: RecordType,
    ) -> Option<(LowerName, RecordType)> {
        match (self.record_type(), query_type) {
            (t @ RecordType::ANAME, RecordType::A)
            | (t @ RecordType::ANAME, RecordType::AAAA)
            | (t @ RecordType::ANAME, RecordType::ANAME) => {
                self.records().next().and_then(|record| {
                    record
                        .rdata()
                        .as_aname()
                        .map(|aname| (LowerName::new(&aname.0), t))
                        .inspect(|(name, record_type)| {
                            tracing::trace!("Next name: {}, record type: {:?}", name, record_type);
                        })
                })
            }
            (t @ RecordType::NS, RecordType::NS) => self
                .records()
                .next()
                .and_then(|record| record.rdata().as_ns().map(|ns| (LowerName::from(&ns.0), t)))
                .inspect(|(name, record_type)| {
                    tracing::trace!("Next name: {}, record type: {:?}", name, record_type);
                }),
            (t @ RecordType::CNAME, _) => self.records().next().and_then(|record| {
                record
                    .rdata()
                    .as_cname()
                    .map(|cname| (LowerName::from(&cname.0), t))
                    .inspect(|(name, record_type)| {
                        tracing::trace!("Next name: {}, record type: {:?}", name, record_type);
                    })
            }),
            (t @ RecordType::MX, RecordType::MX) => self.records().next().and_then(|record| {
                record
                    .rdata()
                    .as_mx()
                    .map(|mx| (LowerName::from(mx.exchange()), t))
                    .inspect(|(name, record_type)| {
                        tracing::trace!("Next name: {}, record type: {:?}", name, record_type);
                    })
            }),
            (t @ RecordType::SRV, RecordType::SRV) => self.records().next().and_then(|record| {
                record
                    .rdata()
                    .as_srv()
                    .map(|srv| (LowerName::from(srv.target()), t))
                    .inspect(|(name, record_type)| {
                        tracing::trace!("Next name: {}, record type: {:?}", name, record_type);
                    })
            }),
            _ => None,
        }
    }
}

impl From<Record> for RecordSet {
    fn from(record: Record) -> Self {
        let mut rrset = RecordSet::new(record.name().clone(), record.record_type());
        rrset.insert(record, SerialNumber::ZERO).unwrap();
        rrset
    }
}

impl From<hickory_proto::rr::RecordSet> for RecordSet {
    fn from(value: hickory_proto::rr::RecordSet) -> Self {
        let mut rrset = RecordSet::new(value.name().clone(), value.record_type());
        let parts = value.into_parts();

        for record in parts.records {
            rrset.insert(record.into(), parts.serial.into()).unwrap();
        }
        for record in parts.rrsigs {
            rrset.insert_rrsig(record.into()).unwrap();
        }

        rrset
    }
}

impl AsHickory for RecordSet {
    type Hickory = hickory_proto::rr::RecordSet;

    fn as_hickory(&self) -> Self::Hickory {
        let mut rset = hickory_proto::rr::RecordSet::new(
            self.name().clone(),
            self.record_type(),
            self.serial().get(),
        );
        for record in self.records() {
            rset.insert(
                record.as_hickory().into_record_of_rdata(),
                self.serial().get(),
            );
        }

        for record in self.rrsigs() {
            rset.insert_rrsig(record.as_hickory().into_record_of_rdata());
        }

        rset
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecordSetIter<'r>(
    std::iter::Chain<std::slice::Iter<'r, Record>, std::slice::Iter<'r, Record>>,
);

impl<'r> Iterator for RecordSetIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<'r> IntoIterator for &'r RecordSet {
    type Item = &'r Record;
    type IntoIter = RecordSetIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        RecordSetIter(self.records.iter().chain(self.rrsigs.iter()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecordSetHickoryIter<'r>(
    std::iter::Chain<std::slice::Iter<'r, Record>, std::slice::Iter<'r, Record>>,
);

impl<'r> Iterator for RecordSetHickoryIter<'r> {
    type Item = hickory_proto::rr::Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|record| record.as_hickory())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecordSetIntoIter(
    std::iter::Chain<std::vec::IntoIter<Record>, std::vec::IntoIter<Record>>,
);

impl Iterator for RecordSetIntoIter {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl IntoIterator for RecordSet {
    type Item = Record;
    type IntoIter = RecordSetIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        RecordSetIntoIter(self.records.into_iter().chain(self.rrsigs.into_iter()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecordSetIntoHickoryIter(
    std::iter::Chain<std::vec::IntoIter<Record>, std::vec::IntoIter<Record>>,
);

impl Iterator for RecordSetIntoHickoryIter {
    type Item = hickory_proto::rr::Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|record| record.as_hickory())
    }
}

/// Mismatch between record and recordset properties
///
/// An error that indicates a record is incompatible with an existing
/// record set.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Mismatched {0} between new record and record set")]
pub struct Mismatch(pub(super) &'static str);

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use hickory_proto::rr::{RecordType, rdata::A};

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com.").unwrap()
    }

    fn create_test_a_record() -> Record {
        let name = create_test_name();
        let ttl = TimeToLive::from(300);
        let rdata = A::new(192, 168, 1, 1);
        Record::from_rdata(name, ttl, rdata).into_record_rdata()
    }

    #[test]
    fn test_recordset_new() {
        let name = create_test_name();
        let rrset = RecordSet::new(name.clone(), RecordType::A);

        assert_eq!(rrset.name(), &name);
        assert_eq!(rrset.record_type(), RecordType::A);
        assert_eq!(rrset.dns_class(), DNSClass::IN);
        assert_eq!(rrset.ttl(), TimeToLive::ZERO);
        assert!(rrset.is_empty());
        assert_eq!(rrset.len(), 0);
        assert_eq!(rrset.serial(), SerialNumber::ZERO);
    }

    #[test]
    fn test_recordset_from_record() {
        let name = create_test_name();
        let record = create_test_a_record();
        let ttl = record.ttl();

        let rrset = RecordSet::from_record(name.clone(), record);

        assert_eq!(rrset.name(), &name);
        assert_eq!(rrset.record_type(), RecordType::A);
        assert_eq!(rrset.dns_class(), DNSClass::IN);
        assert_eq!(rrset.ttl(), ttl);
        assert!(!rrset.is_empty());
        assert_eq!(rrset.len(), 1);
    }

    #[test]
    fn test_recordset_with_name() {
        let name1 = create_test_name();
        let name2 = Name::from_utf8("other.example.com.").unwrap();
        let record = create_test_a_record();

        let rrset1 = RecordSet::from_record(name1, record);
        let rrset2 = rrset1.with_name(name2.clone());

        assert_eq!(rrset2.name(), &name2);
        assert_eq!(rrset2.record_type(), RecordType::A);
        assert_eq!(rrset2.len(), 1);
        assert!(rrset2.rrsigs().is_empty()); // RRSIGs should be cleared
    }

    #[test]
    fn test_recordset_push() {
        let name = create_test_name();
        let mut rrset = RecordSet::new(name, RecordType::A);
        let rdata = RData::A(A::new(192, 168, 1, 1));

        let result = rrset.push(rdata);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(rrset.len(), 1);
        assert!(!rrset.is_empty());
    }

    #[test]
    fn test_recordset_set_ttl() {
        let name = create_test_name();
        let record = create_test_a_record();
        let mut rrset = RecordSet::from_record(name, record);

        let new_ttl = TimeToLive::from(600);
        rrset.set_ttl(new_ttl);

        assert_eq!(rrset.ttl(), new_ttl);
        for record in rrset.records() {
            assert_eq!(record.ttl(), new_ttl);
        }
    }

    #[test]
    fn test_recordset_set_dns_class() {
        let name = create_test_name();
        let mut rrset = RecordSet::new(name, RecordType::A);

        rrset.set_dns_class(DNSClass::CH);
        assert_eq!(rrset.dns_class(), DNSClass::CH);
    }

    #[test]
    fn test_recordset_insert_duplicate() {
        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::A);
        let rdata = RData::A(A::new(192, 168, 1, 1));

        // Insert first record
        let record1 = Record::from_rdata(name.clone(), TimeToLive::from(300), rdata.clone())
            .into_record_rdata();
        let result1 = rrset.insert(record1, SerialNumber::from(1));
        assert!(result1.is_ok());
        assert!(result1.unwrap());
        assert_eq!(rrset.len(), 1);

        // Insert duplicate record
        let record2 = Record::from_rdata(name, TimeToLive::from(300), rdata).into_record_rdata();
        let result2 = rrset.insert(record2, SerialNumber::from(2));
        assert!(result2.is_ok());
        assert!(!result2.unwrap()); // Should return false for duplicate
        assert_eq!(rrset.len(), 1); // Length should not change
    }

    #[test]
    fn test_recordset_insert_wrong_name() {
        let name1 = create_test_name();
        let name2 = Name::from_utf8("other.example.com.").unwrap();
        let mut rrset = RecordSet::new(name1, RecordType::A);

        let record = Record::from_rdata(
            name2,
            TimeToLive::from(300),
            RData::A(A::new(192, 168, 1, 1)),
        )
        .into_record_rdata();
        let result = rrset.insert(record, SerialNumber::from(1));

        assert!(result.is_err());
        if let Err(Mismatch(msg)) = result {
            assert_eq!(msg, "name");
        }
    }

    #[test]
    fn test_recordset_insert_wrong_type() {
        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::A);

        let record = Record::from_rdata(
            name,
            TimeToLive::from(300),
            RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_utf8("target.example.com.").unwrap(),
            )),
        )
        .into_record_rdata();
        let result = rrset.insert(record, SerialNumber::from(1));

        assert!(result.is_err());
        if let Err(Mismatch(msg)) = result {
            assert_eq!(msg, "type");
        }
    }

    #[test]
    fn test_recordset_remove() {
        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::A);
        let rdata = RData::A(A::new(192, 168, 1, 1));
        let record = Record::from_rdata(name, TimeToLive::from(300), rdata).into_record_rdata();

        // Insert record
        rrset.insert(record.clone(), SerialNumber::from(1)).unwrap();
        assert_eq!(rrset.len(), 1);

        // Remove record
        let result = rrset.remove(&record, SerialNumber::from(2));
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(rrset.len(), 0);
        assert!(rrset.is_empty());
    }

    #[test]
    fn test_recordset_rrkey() {
        let name = create_test_name();
        let rrset = RecordSet::new(name.clone(), RecordType::A);
        let rrkey = rrset.rrkey();

        assert_eq!(rrkey.name(), &LowerName::from(name));
        assert_eq!(rrkey.record_type, RecordType::A);
    }

    #[test]
    fn test_recordset_iterators() {
        let name = create_test_name();
        let record = create_test_a_record();
        let rrset = RecordSet::from_record(name, record);

        // Test records iterator
        assert_eq!(rrset.records().count(), 1);

        // Test into_records
        let records: Vec<_> = rrset.clone().into_records().collect();
        assert_eq!(records.len(), 1);

        // Test signed_records (no signatures)
        assert_eq!(rrset.signed_records().count(), 1);

        // Test into_signed_records
        let signed_records: Vec<_> = rrset.into_signed_records().collect();
        assert_eq!(signed_records.len(), 1);
    }

    #[test]
    fn test_recordset_rrsigs() {
        let name = create_test_name();
        let mut rrset = RecordSet::new(name, RecordType::A);

        assert!(rrset.rrsigs().is_empty());

        // Clear RRSIGs (should be no-op when empty)
        rrset.clear_rrsigs();
        assert!(rrset.rrsigs().is_empty());
    }

    #[test]
    fn test_recordset_as_hickory() {
        let name = create_test_name();
        let record = create_test_a_record();
        let rrset = RecordSet::from_record(name.clone(), record);

        let hickory_rrset = rrset.as_hickory();
        assert_eq!(hickory_rrset.name(), &name);
        assert_eq!(hickory_rrset.record_type(), RecordType::A);
    }

    #[test]
    fn test_mismatch_error() {
        let mismatch = Mismatch("test");
        assert_eq!(
            format!("{mismatch}"),
            "Mismatched test between new record and record set"
        );
    }

    #[test]
    fn test_recordset_clone() {
        let name = create_test_name();
        let record = create_test_a_record();
        let rrset1 = RecordSet::from_record(name, record);
        let rrset2 = rrset1.clone();

        assert_eq!(rrset1, rrset2);
        assert_eq!(rrset1.name(), rrset2.name());
        assert_eq!(rrset1.len(), rrset2.len());
    }

    #[test]
    fn test_recordset_soa_serial_number_handling() {
        use hickory_proto::rr::rdata::SOA;

        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::SOA);

        // Create first SOA with serial 100
        let soa1 = SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            100, // serial
            3600,
            1800,
            604800,
            86400,
        );
        let record1 =
            Record::from_rdata(name.clone(), TimeToLive::from(3600), soa1).into_record_rdata();

        // Insert first SOA
        let result = rrset.insert(record1, SerialNumber::from(1));
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should succeed
        assert_eq!(rrset.len(), 1);

        // Try to insert SOA with older serial (50) - should be rejected
        let soa2 = SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            50, // older serial
            3600,
            1800,
            604800,
            86400,
        );
        let record2 =
            Record::from_rdata(name.clone(), TimeToLive::from(3600), soa2).into_record_rdata();

        let result = rrset.insert(record2, SerialNumber::from(2));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be rejected due to old serial
        assert_eq!(rrset.len(), 1); // Length should not change

        // Try to insert SOA with newer serial (200) - should succeed
        let soa3 = SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            200, // newer serial
            3600,
            1800,
            604800,
            86400,
        );
        let record3 = Record::from_rdata(name, TimeToLive::from(3600), soa3).into_record_rdata();

        let result = rrset.insert(record3, SerialNumber::from(3));
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should succeed
        assert_eq!(rrset.len(), 1); // Still only one SOA (replaced)

        // Verify the SOA has the newer serial
        let soa_record = rrset.records().next().unwrap();
        if let RData::SOA(soa) = soa_record.rdata() {
            assert_eq!(soa.serial(), 200);
        } else {
            panic!("Expected SOA record");
        }
    }

    #[test]
    fn test_recordset_ns_last_record_protection() {
        use hickory_proto::rr::rdata::NS;

        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::NS);

        // Add first NS record
        let ns1 = NS(Name::from_utf8("ns1.example.com.").unwrap());
        let record1 = Record::from_rdata(name.clone(), TimeToLive::from(86400), ns1.clone())
            .into_record_rdata();
        rrset
            .insert(record1.clone(), SerialNumber::from(1))
            .unwrap();
        assert_eq!(rrset.len(), 1);

        // Add second NS record
        let ns2 = NS(Name::from_utf8("ns2.example.com.").unwrap());
        let record2 =
            Record::from_rdata(name.clone(), TimeToLive::from(86400), ns2).into_record_rdata();
        rrset
            .insert(record2.clone(), SerialNumber::from(2))
            .unwrap();
        assert_eq!(rrset.len(), 2);

        // Remove first NS record - should succeed
        let result = rrset.remove(&record1, SerialNumber::from(3));
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should succeed
        assert_eq!(rrset.len(), 1);

        // Try to remove the last NS record - should be rejected
        let result = rrset.remove(&record2, SerialNumber::from(4));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be rejected
        assert_eq!(rrset.len(), 1); // Length should not change
    }

    #[test]
    fn test_recordset_soa_deletion_protection() {
        use hickory_proto::rr::rdata::SOA;

        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::SOA);

        // Add SOA record
        let soa = SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        let record = Record::from_rdata(name, TimeToLive::from(3600), soa).into_record_rdata();
        rrset.insert(record.clone(), SerialNumber::from(1)).unwrap();
        assert_eq!(rrset.len(), 1);

        // Try to remove SOA record - should be rejected
        let result = rrset.remove(&record, SerialNumber::from(2));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be rejected
        assert_eq!(rrset.len(), 1); // Length should not change
    }

    #[test]
    fn test_recordset_cname_replacement() {
        use hickory_proto::rr::rdata::CNAME;

        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::CNAME);

        // Add first CNAME record
        let cname1 = CNAME(Name::from_utf8("target1.example.com.").unwrap());
        let record1 =
            Record::from_rdata(name.clone(), TimeToLive::from(300), cname1).into_record_rdata();
        rrset.insert(record1, SerialNumber::from(1)).unwrap();
        assert_eq!(rrset.len(), 1);

        // Add second CNAME record - should replace the first
        let cname2 = CNAME(Name::from_utf8("target2.example.com.").unwrap());
        let record2 = Record::from_rdata(name, TimeToLive::from(300), cname2).into_record_rdata();
        rrset.insert(record2, SerialNumber::from(2)).unwrap();
        assert_eq!(rrset.len(), 1); // Still only one CNAME

        // Verify the CNAME points to the new target
        let cname_record = rrset.records().next().unwrap();
        if let RData::CNAME(cname) = cname_record.rdata() {
            assert!(cname.0.to_utf8().starts_with("target2.example.com."));
        } else {
            panic!("Expected CNAME record");
        }
    }

    #[test]
    fn test_recordset_aname_replacement() {
        use hickory_proto::rr::rdata::ANAME;

        let name = create_test_name();
        let mut rrset = RecordSet::new(name.clone(), RecordType::ANAME);

        // Add first ANAME record
        let aname1 = ANAME(Name::from_utf8("target1.example.com.").unwrap());
        let record1 =
            Record::from_rdata(name.clone(), TimeToLive::from(300), aname1).into_record_rdata();
        rrset.insert(record1, SerialNumber::from(1)).unwrap();
        assert_eq!(rrset.len(), 1);

        // Add second ANAME record - should replace the first
        let aname2 = ANAME(Name::from_utf8("target2.example.com.").unwrap());
        let record2 = Record::from_rdata(name, TimeToLive::from(300), aname2).into_record_rdata();
        rrset.insert(record2, SerialNumber::from(2)).unwrap();
        assert_eq!(rrset.len(), 1); // Still only one ANAME

        // Verify the ANAME points to the new target
        let aname_record = rrset.records().next().unwrap();
        if let RData::ANAME(aname) = aname_record.rdata() {
            assert!(aname.0.to_utf8().starts_with("target2.example.com."));
        } else {
            panic!("Expected ANAME record");
        }
    }

    #[test]
    #[allow(clippy::blocks_in_conditions)]
    fn test_get_filter() {
        use hickory_proto::dnssec::{
            Algorithm,
            rdata::{DNSSECRData, RRSIG},
        };

        let name = Name::root();
        let rsasha256 = RRSIG::new(
            RecordType::A,
            Algorithm::RSASHA256,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ecp256 = RRSIG::new(
            RecordType::A,
            Algorithm::ECDSAP256SHA256,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ecp384 = RRSIG::new(
            RecordType::A,
            Algorithm::ECDSAP384SHA384,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ed25519 = RRSIG::new(
            RecordType::A,
            Algorithm::ED25519,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );

        let rrsig_rsa = Record::from_rdata(
            name.clone(),
            3600.into(),
            RData::DNSSEC(DNSSECRData::RRSIG(rsasha256)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let rrsig_ecp256 = Record::from_rdata(
            name.clone(),
            3600.into(),
            RData::DNSSEC(DNSSECRData::RRSIG(ecp256)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let rrsig_ecp384 = Record::from_rdata(
            name.clone(),
            3600.into(),
            RData::DNSSEC(DNSSECRData::RRSIG(ecp384)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let rrsig_ed25519 = Record::from_rdata(
            name.clone(),
            3600.into(),
            RData::DNSSEC(DNSSECRData::RRSIG(ed25519)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        let a = Record::from_rdata(
            name,
            3600.into(),
            RData::A(Ipv4Addr::new(93, 184, 216, 24).into()),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        let mut rrset = RecordSet::from(a);
        rrset.insert_rrsig(rrsig_rsa).unwrap();
        rrset.insert_rrsig(rrsig_ecp256).unwrap();
        rrset.insert_rrsig(rrsig_ecp384).unwrap();
        rrset.insert_rrsig(rrsig_ed25519).unwrap();

        assert!(rrset.signed_records().any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.rdata() {
                sig.algorithm() == Algorithm::ED25519
            } else {
                false
            }
        },));

        assert!(rrset.signed_records().any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.rdata() {
                sig.algorithm() == Algorithm::ECDSAP384SHA384
            } else {
                false
            }
        }));

        assert!(rrset.signed_records().any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.rdata() {
                sig.algorithm() == Algorithm::ED25519
            } else {
                false
            }
        }));
    }
}
