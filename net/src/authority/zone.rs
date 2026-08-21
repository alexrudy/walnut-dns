//! Trait implementations for the zone item
use hickory_proto::rr::RrKey;
use walnut_proto::rr::{
    DNSClass, Mismatch, Name, Record, RecordSet, RecordType, SerialNumber, TimeToLive, Zone,
    ZoneType,
};

use super::{Records, ZoneInfo};

impl ZoneInfo for Zone {
    fn name(&self) -> &Name {
        &self.name
    }

    fn origin(&self) -> &Name {
        &self.origin
    }

    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr
    }

    fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    fn soa(&self) -> Option<&Record> {
        let rrset = self
            .records
            .get(&RrKey::new(self.name().into(), RecordType::SOA))?;

        rrset.records(false).next()
    }

    /// The serial number of this zone, from the SOA record.
    fn serial(&self) -> SerialNumber {
        self.soa()
            .and_then(|soa| soa.rdata().as_soa())
            .map_or(SerialNumber::ZERO, |soa| SerialNumber::from(soa.serial()))
    }

    /// The minimum TTL for this zone, from the SOA record.
    fn minimum_ttl(&self) -> TimeToLive {
        self.soa()
            .and_then(|soa| soa.rdata().as_soa())
            .map_or(TimeToLive::ZERO, |soa| TimeToLive::from(soa.minimum()))
    }

    /// Increment the serial number of this zone's SOA record.
    fn increment_soa_serial(&mut self) -> SerialNumber {
        let Some(rrset) = self
            .records
            .get_mut(&RrKey::new(self.name().into(), RecordType::SOA))
        else {
            return SerialNumber::ZERO;
        };

        let Some(soa_data) = rrset
            .records_mut()
            .next()
            .and_then(|record| record.rdata_mut().as_soa_mut())
        else {
            return SerialNumber::ZERO;
        };

        soa_data.increment_serial();
        SerialNumber::from(soa_data.serial())
    }
}

impl Records for Zone {
    fn get(&self, key: &RrKey) -> Option<&RecordSet> {
        self.records.get(key)
    }

    fn get_mut(&mut self, key: &RrKey) -> Option<&mut RecordSet> {
        self.records.get_mut(key)
    }

    fn keys(&self) -> impl Iterator<Item = &RrKey> {
        self.records.keys()
    }

    fn records(&self) -> impl Iterator<Item = &RecordSet> {
        self.records.values()
    }

    fn records_mut(&mut self) -> impl Iterator<Item = &mut RecordSet> {
        self.records.values_mut()
    }

    fn records_reversed(&self) -> impl Iterator<Item = &RecordSet> {
        self.records.values().rev()
    }

    fn upsert(&mut self, record: Record, serial: SerialNumber) -> Result<bool, Mismatch> {
        if record.dns_class() != self.dns_class() {
            return Err(Mismatch("DNS Class"));
        }

        fn is_nsec(upsert_type: RecordType, occupied_type: RecordType) -> bool {
            // NSEC is always allowed
            upsert_type == RecordType::NSEC
                || upsert_type == RecordType::NSEC3
                || occupied_type == RecordType::NSEC
                || occupied_type == RecordType::NSEC3
        }

        fn label_does_not_allow_multiple(
            upsert_type: RecordType,
            occupied_type: RecordType,
            check_type: RecordType,
        ) -> bool {
            // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
            (upsert_type == check_type && occupied_type != check_type) ||
                // it's a different record, but there is already a CNAME/ANAME here
                (upsert_type != check_type && occupied_type == check_type)
        }

        let start_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MAX));

        let multiple_records_at_label_disallowed = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .any(|(key, _)| {
                !is_nsec(record.record_type(), key.record_type)
                    && label_does_not_allow_multiple(
                        record.record_type(),
                        key.record_type,
                        RecordType::CNAME,
                    )
            });

        if multiple_records_at_label_disallowed {
            // consider making this an error?
            return Ok(false);
        }

        let rrset = self
            .records
            .entry(record.rrkey())
            .or_insert_with(|| RecordSet::new(record.name().clone(), record.record_type()));

        rrset.insert(record, serial)
    }

    fn range<T, R>(&self, range: R) -> impl Iterator<Item = (&RrKey, &RecordSet)>
    where
        T: Ord + ?Sized,
        RrKey: std::borrow::Borrow<T> + Ord,
        R: std::ops::RangeBounds<T>,
    {
        self.records.range(range)
    }

    fn remove(&mut self, key: &RrKey) -> Option<RecordSet> {
        self.records.remove(key)
    }

    fn replace(&mut self, rrset: RecordSet) -> Option<RecordSet> {
        self.records.insert(rrset.rrkey(), rrset)
    }
}

#[cfg(test)]
mod tests {
    use walnut_proto::rr::TimeToLive;

    use super::*;
    use hickory_proto::rr::{
        RecordType,
        rdata::{A, SOA},
    };

    fn create_test_name() -> Name {
        Name::from_utf8("test.example.com.").unwrap()
    }

    fn create_test_soa() -> Record<SOA> {
        let name = create_test_name();
        let soa = SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        Record::from_rdata(name, TimeToLive::from(3600), soa)
    }

    #[test]
    fn test_zone_type_debug() {
        assert!(format!("{:?}", ZoneType::Primary).contains("Primary"));
        assert!(format!("{:?}", ZoneType::Secondary).contains("Secondary"));
        assert!(format!("{:?}", ZoneType::External).contains("External"));
    }

    #[test]
    fn test_zone_creation() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        assert_eq!(zone.name(), &name);
        assert_eq!(zone.zone_type(), ZoneType::Primary);
        assert_eq!(zone.dns_class, DNSClass::IN);
        assert!(!zone.allow_axfr());
        assert_eq!(zone.records().count(), 1); // SOA record
        assert!(!zone.is_empty()); // Has SOA record
    }

    #[test]
    fn test_zone_with_allow_axfr() {
        let name = create_test_name();
        let soa = create_test_soa();

        let mut zone = Zone::empty(
            name.clone(),
            soa,
            ZoneType::Primary,
            true, // allow_axfr
        );

        assert_eq!(zone.name(), &name);
        assert_eq!(zone.zone_type(), ZoneType::Primary);
        assert!(zone.allow_axfr());

        // Test set_allow_axfr
        zone.set_allow_axfr(false);
        assert!(!zone.allow_axfr());
    }

    #[test]
    fn test_zone_upsert_record() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record = Record::from_rdata(name, TimeToLive::from(300), A::new(192, 168, 1, 1))
            .into_record_rdata();

        let result = zone.upsert(a_record.clone(), SerialNumber::from(1));
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(zone.records().count(), 2); // SOA + A record
    }

    #[test]
    fn test_zone_remove_record() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record = Record::from_rdata(name, TimeToLive::from(300), A::new(192, 168, 1, 1))
            .into_record_rdata();

        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();
        assert_eq!(zone.records().count(), 2);

        // Remove A record (using the key)
        let key = a_record.rrkey();
        let removed = zone.remove(&key);
        assert!(removed.is_some());
        assert_eq!(zone.records().count(), 1); // Only SOA remains
    }

    #[test]
    fn test_zone_get_by_key() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record =
            Record::from_rdata(name.clone(), TimeToLive::from(300), A::new(192, 168, 1, 1))
                .into_record_rdata();

        zone.upsert(a_record.clone(), SerialNumber::from(1))
            .unwrap();

        // Test get by key
        let key = a_record.rrkey();
        let result = zone.get(&key);
        assert!(result.is_some());

        let rrset = result.unwrap();
        assert_eq!(rrset.record_type(), RecordType::A);
        assert_eq!(rrset.len(), 1);
    }

    #[test]
    fn test_zone_soa_access() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Test SOA access
        let soa_record = zone.soa().unwrap();
        assert_eq!(soa_record.record_type(), RecordType::SOA);

        // Test serial number
        let serial = zone.serial();
        assert_eq!(serial.get(), 1); // From our test SOA
    }

    #[test]
    fn test_zone_is_empty() {
        let name = create_test_name();
        let soa = create_test_soa();
        let zone = Zone::empty(name, soa, ZoneType::Primary, false);

        // Zone with only SOA is not considered empty
        assert!(!zone.is_empty());
    }

    #[test]
    fn test_zone_iterators() {
        let name = create_test_name();
        let soa = create_test_soa();
        let mut zone = Zone::empty(name.clone(), soa, ZoneType::Primary, false);

        // Add A record
        let a_record = Record::from_rdata(name, TimeToLive::from(300), A::new(192, 168, 1, 1))
            .into_record_rdata();

        zone.upsert(a_record, SerialNumber::from(1)).unwrap();

        // Test records iterator
        assert_eq!(zone.records().count(), 2); // SOA + A
    }
}
