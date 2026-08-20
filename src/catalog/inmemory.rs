use std::{collections::BTreeMap, sync::Arc};

use hickory_proto::rr::Name;
use parking_lot::Mutex;
use tracing::trace;

use crate::ZoneInfo;

use super::{CatalogError, CatalogStore};

#[derive(Debug)]
struct InMemoryStoreInner<Z> {
    zones: Mutex<BTreeMap<Name, Vec<Z>>>,
}

impl<Z> Default for InMemoryStoreInner<Z> {
    fn default() -> Self {
        Self {
            zones: Mutex::new(BTreeMap::new()),
        }
    }
}

/// An in-memory catalog of DNS zones.
#[derive(Debug)]
pub struct InMemoryStore<Z> {
    inner: Arc<InMemoryStoreInner<Z>>,
}

impl<Z> Default for InMemoryStore<Z> {
    fn default() -> Self {
        Self {
            inner: Arc::new(InMemoryStoreInner::default()),
        }
    }
}

impl<Z> Clone for InMemoryStore<Z> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Z> InMemoryStore<Z> {
    pub fn new() -> Self {
        Default::default()
    }
}

impl<Z> InMemoryStore<Z>
where
    Z: ZoneInfo + Clone,
{
    pub fn insert(&self, zone: &Z) -> Result<(), CatalogError> {
        let mut inner = self.inner.zones.lock();
        inner
            .entry(zone.origin().clone())
            .or_default()
            .push(zone.clone());
        Ok(())
    }
}

#[async_trait::async_trait]
impl<Z> CatalogStore<Z> for InMemoryStore<Z>
where
    Z: ZoneInfo + Clone + Send + Sync + 'static,
{
    async fn find(&self, origin: &Name) -> Result<Option<Vec<Z>>, CatalogError> {
        let mut name = origin.clone();
        let inner = self.inner.zones.lock();
        loop {
            trace!("Searching for zone {name}");
            match inner.get(&name) {
                Some(zones) => return Ok(Some(zones.clone())),
                None => {}
            }

            if !name.is_root() {
                trace!(%name, base_name=%name.base_name(), "continue search to base name");
                name = name.base_name();
            } else {
                trace!(%name, "no more base names to search");
                return Ok(None);
            }
        }
    }

    async fn upsert(&self, name: Name, zones: &[&Z]) -> Result<(), CatalogError> {
        let mut zdb = self.inner.zones.lock();

        let entry = zdb.entry(name).or_default();
        entry.clear();
        entry.extend(zones.into_iter().map(|&z| z.clone()));
        Ok(())
    }

    async fn list(&self, origin: &Name) -> Result<Vec<Name>, CatalogError> {
        let inner = self.inner.zones.lock();
        let mut zones = Vec::new();

        for entry in inner.values() {
            for zone in entry {
                if origin.zone_of(zone.name()) {
                    zones.push(zone.name().clone());
                }
            }
        }

        Ok(zones)
    }

    async fn remove(&self, name: &Name) -> Result<Option<Vec<Z>>, CatalogError> {
        let mut zdb = self.inner.zones.lock();
        let entry = zdb.remove(name);
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::Records as _,
        rr::{Record, SerialNumber, TimeToLive, Zone, ZoneType},
    };
    use hickory_proto::rr::rdata;

    fn create_test_zone(name: &str) -> Zone {
        let name = Name::from_utf8(name).unwrap();
        let soa = rdata::SOA::new(
            name.clone(),
            Name::from_utf8("admin.example.com.").unwrap(),
            1,
            3600,
            1800,
            604800,
            86400,
        );
        let soa_record = Record::from_rdata(name.clone(), TimeToLive::from(3600), soa);
        Zone::empty(name, soa_record, ZoneType::Primary, false)
    }

    fn create_test_a_record() -> Record {
        let name = Name::from_utf8("www.test.example.com.").unwrap();
        let ttl = TimeToLive::from(300);
        let rdata = rdata::A::new(192, 168, 1, 1);
        Record::from_rdata(name, ttl, rdata).into_record_rdata()
    }

    #[tokio::test]
    async fn test_catalog_find_zone() {
        crate::subscribe();

        let catalog = InMemoryStore::new();
        let zone = create_test_zone("test.example.com.");
        let zone_name = zone.name().clone();

        // Upsert zone
        catalog.insert(&zone).unwrap();

        // Find zone by name
        let found_zones = catalog.find(&zone_name).await.unwrap().unwrap();
        assert_eq!(found_zones.len(), 1);
        assert_eq!(found_zones[0].name(), &zone_name);
    }

    #[tokio::test]
    async fn test_catalog_find_simple_zone() {
        let store = InMemoryStore::new();
        let mut zone = create_test_zone("example.com.");
        let record = create_test_a_record();
        zone.upsert(record.clone(), SerialNumber::from(1)).unwrap();
        store.upsert(zone.origin().clone(), &[&zone]).await.unwrap();

        let found = store
            .find(&Name::from_utf8("example.com.").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin(), &Name::from_utf8("example.com.").unwrap());
        assert!(!found[0].is_empty());
    }

    #[tokio::test]
    async fn test_catalog_find_empty_zone() {
        let store = InMemoryStore::new();
        let zone = create_test_zone("example.com.");
        store.upsert(zone.origin().clone(), &[&zone]).await.unwrap();

        let found = store
            .find(&Name::from_utf8("example.com.").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin(), &Name::from_utf8("example.com.").unwrap());
    }

    #[tokio::test]
    async fn test_catalog_find_nonexistent_zone() {
        crate::subscribe();
        let catalog = InMemoryStore::<Zone>::new();
        let nonexistent_name = Name::from_utf8("nonexistent.example.com.").unwrap();

        // Find nonexistent zone
        let found_zones = catalog.find(&nonexistent_name).await.unwrap();
        assert!(found_zones.is_none());
    }

    #[tokio::test]
    async fn test_catalog_list_zones() {
        crate::subscribe();
        let catalog = InMemoryStore::new();

        // Start with empty list
        let root = Name::root();
        let initial_list = catalog.list(&root).await.unwrap();
        assert!(initial_list.is_empty());

        // Add a zone
        let zone = create_test_zone("test.example.com.");
        let zone_name = zone.name().clone();
        catalog.insert(&zone).unwrap();

        let root = Name::root();
        // List should contain the zone
        let zone_list = catalog.list(&root).await.unwrap();
        assert_eq!(zone_list.len(), 1);
        assert_eq!(zone_list[0], zone_name);
    }

    #[tokio::test]
    async fn test_catalog_multiple_zones() {
        crate::subscribe();
        let catalog = InMemoryStore::new();

        // Create multiple zones
        let zone1 = create_test_zone("test.example.org.");
        let zone1_name = zone1.name().clone();
        let zone2 = {
            let name = Name::from_utf8("another.example.com.").unwrap();
            let soa = rdata::SOA::new(
                name.clone(),
                Name::from_utf8("admin.another.example.com.").unwrap(),
                1,
                3600,
                1800,
                604800,
                86400,
            );
            let soa_record = Record::from_rdata(name.clone(), TimeToLive::from(3600), soa);
            Zone::empty(name, soa_record, ZoneType::Secondary, true)
        };
        let zone2_name = zone2.name().clone();

        // Upsert both zones
        catalog.insert(&zone1).unwrap();
        catalog.insert(&zone2).unwrap();

        // List should contain both zones
        let root = Name::root();
        let zone_list = catalog.list(&root).await.unwrap();
        assert_eq!(zone_list.len(), 2);
        assert!(zone_list.contains(&zone1_name));
        assert!(zone_list.contains(&zone2_name));

        let zone_list = catalog.list(&zone1_name).await.unwrap();
        assert_eq!(zone_list.len(), 1);
        assert!(zone_list.contains(&zone1_name));
        assert!(!zone_list.contains(&zone2_name));
    }

    #[tokio::test]
    async fn test_catalog_chained_zones() {
        crate::subscribe();
        let catalog = InMemoryStore::new();

        // Create multiple zones
        let zone1 = create_test_zone("test.example.com.");
        let zone2 = create_test_zone("test.example.org.");
        let name = zone1.origin().clone();
        catalog
            .upsert(name.clone(), &[&zone1, &zone2])
            .await
            .unwrap();

        // List should contain both zones
        let root = Name::root();
        let zone_list = catalog.list(&root).await.unwrap();
        assert_eq!(zone_list.len(), 2);
        assert!(zone_list.contains(&name));
    }

    #[tokio::test]
    async fn test_catalog_concurrent_access() {
        crate::subscribe();

        let catalog = InMemoryStore::new();
        let zone = create_test_zone("test.example.com.");
        let zone_name = zone.name().clone();

        // Test that the catalog can handle concurrent access via Arc<Mutex<Connection>>
        let catalog_clone = catalog.clone();

        // Upsert in original
        catalog.insert(&zone).unwrap();

        // Read from clone
        let found_zones = catalog_clone.find(&zone_name).await.unwrap().unwrap();
        assert_eq!(found_zones.len(), 1);
    }

    #[tokio::test]
    async fn test_catalog_debug_format() {
        crate::subscribe();

        let catalog = InMemoryStore::<Zone>::new();
        let debug_string = format!("{catalog:?}");
        assert!(debug_string.contains("InMemory"));
    }

    #[tokio::test]
    async fn test_zone_name_case_insensitive_search() {
        crate::subscribe();

        let catalog = InMemoryStore::new();
        let zone = create_test_zone("test.example.com.");
        let expected_name = zone.name().clone();

        catalog.insert(&zone).unwrap();

        // Search with different case
        let upper_name = Name::from_utf8("TEST.EXAMPLE.COM.").unwrap();
        let found_zones = catalog.find(&upper_name).await.unwrap().unwrap();
        assert_eq!(found_zones.len(), 1);
        assert_eq!(found_zones[0].name(), &expected_name);
    }
}
