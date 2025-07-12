use hickory_proto::rr::{DNSClass, LowerName, RData, RecordData, RecordType, RrKey};

use super::{AsHickory, SerialNumber, record::Record, ttl::TimeToLive};
use hickory_proto::rr::Name;

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

    /// Label of the Resource Record Set
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// `RecordType` of the Resource Record Set
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// `DNSClass` of the RecordSet
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Sets the `DNSClass` of the RecordSet
    pub fn set_dns_class(&mut self, dns_class: DNSClass) {
        self.dns_class = dns_class;
    }

    /// Sets the TTL, in seconds, to the specified value
    ///
    /// This will traverse every record and associate with it the specified ttl
    pub fn set_ttl(&mut self, ttl: TimeToLive) {
        self.ttl = ttl;
        for r in &mut self.records {
            r.set_ttl(ttl);
        }
    }

    /// Make a copy of this record set with a new name
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

    /// Time to Live for this RecordSet
    pub fn ttl(&self) -> TimeToLive {
        self.ttl
    }

    /// Serial number for updates to this RecordSet
    pub fn serial(&self) -> SerialNumber {
        self.serial
    }
}

impl RecordSet {
    /// Record Lookup Key for this Record Set
    pub(crate) fn rrkey(&self) -> RrKey {
        RrKey::new(self.name().into(), self.record_type())
    }

    /// Returns an iterator over all records in the set, without any RRSIGs.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter()
    }

    pub(crate) fn records_mut(&mut self) -> impl Iterator<Item = &mut Record> {
        self.records.iter_mut()
    }

    /// Returns an IntoIterator over all records in the set, without any RRSIGs.
    pub fn into_records(self) -> impl Iterator<Item = Record> {
        self.records.into_iter()
    }

    /// Returns an IntoIterator over all records and signatures in the set.
    pub fn into_signed_records(self) -> impl Iterator<Item = Record> {
        self.records.into_iter().chain(self.rrsigs)
    }

    /// Returns an iterator over all records in the set, with RRSIGs, if present.
    pub fn signed_records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().chain(self.rrsigs.iter())
    }

    /// Returns true if there are no records in this set
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of records in this set
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns a slice of all the Records signatures in the RecordSet
    pub fn rrsigs(&self) -> &[Record] {
        &self.rrsigs
    }

    #[allow(dead_code)]
    pub(crate) fn rrsigs_mut(&mut self) -> &mut Vec<Record> {
        &mut self.rrsigs
    }

    /// Inserts a Signature for the Record set
    ///
    /// Many can be associated with the RecordSet. Once added, the RecordSet should not be changed
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

    /// Useful for clearing all signatures when the RecordSet is updated, or keys are rotated.
    pub fn clear_rrsigs(&mut self) {
        self.rrsigs.clear()
    }

    pub fn push(&mut self, rdata: RData) -> Result<bool, Mismatch> {
        let record = Record::from_rdata(self.name.clone(), self.ttl, rdata);
        self.insert(record, SerialNumber::ZERO)
    }

    fn updated(&mut self, serial: SerialNumber) {
        self.serial = serial;
        self.rrsigs.clear(); // on updates, the rrsigs are invalid
    }

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
                            if let RData::SOA(new_soa) = record.rdata()
                                && SerialNumber::from(new_soa.serial())
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
                })
            }
            (t @ RecordType::NS, RecordType::NS) => self
                .records()
                .next()
                .and_then(|record| record.rdata().as_ns().map(|ns| (LowerName::from(&ns.0), t))),
            (t @ RecordType::CNAME, _) => self.records().next().and_then(|record| {
                record
                    .rdata()
                    .as_cname()
                    .map(|cname| (LowerName::from(&cname.0), t))
            }),
            (t @ RecordType::MX, RecordType::MX) => self.records().next().and_then(|record| {
                record
                    .rdata()
                    .as_mx()
                    .map(|mx| (LowerName::from(mx.exchange()), t))
            }),
            (t @ RecordType::SRV, RecordType::SRV) => self.records().next().and_then(|record| {
                record
                    .rdata()
                    .as_srv()
                    .map(|srv| (LowerName::from(srv.target()), t))
            }),
            _ => None,
        }
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

        rset
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Mismatched {0} between new record and record set")]
pub struct Mismatch(pub(super) &'static str);

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{rdata::A, RecordType};

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com").unwrap()
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
        let name2 = Name::from_utf8("other.example.com").unwrap();
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
        let record1 = Record::from_rdata(name.clone(), TimeToLive::from(300), rdata.clone()).into_record_rdata();
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
        let name2 = Name::from_utf8("other.example.com").unwrap();
        let mut rrset = RecordSet::new(name1, RecordType::A);
        
        let record = Record::from_rdata(name2, TimeToLive::from(300), RData::A(A::new(192, 168, 1, 1))).into_record_rdata();
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
        
        let record = Record::from_rdata(name, TimeToLive::from(300), RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_utf8("target.example.com").unwrap()))).into_record_rdata();
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
        assert_eq!(format!("{}", mismatch), "Mismatched test between new record and record set");
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
}
