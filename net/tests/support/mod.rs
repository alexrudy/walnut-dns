#![allow(unused)]

use std::collections::BTreeMap;
use std::sync::{Mutex, Once};

use walnut_dns::catalog::CatalogError;
use walnut_dns::catalog::CatalogStore;
use walnut_proto::rr::Name;

pub mod examples;

/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
pub fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

pub struct TestZoneStore<Z> {
    zones: Mutex<BTreeMap<Name, Vec<Z>>>,
}

impl<Z> TestZoneStore<Z> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            zones: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl<Z: Clone + Send + Sync> CatalogStore<Z> for TestZoneStore<Z> {
    async fn find(&self, origin: &walnut_proto::rr::Name) -> Result<Option<Vec<Z>>, CatalogError> {
        let data = self.zones.lock().expect("poisoned");
        let mut name = origin.clone();
        loop {
            tracing::trace!("Looking for {name}");
            if let Some(zones) = data.get(&name) {
                return Ok(Some(zones.clone()));
            }
            if !name.is_root() {
                name = name.base_name();
            } else {
                return Ok(None);
            }
        }
    }

    async fn upsert(&self, name: walnut_proto::rr::Name, zones: &[&Z]) -> Result<(), CatalogError> {
        let mut data = self.zones.lock().expect("poisoned");
        data.insert(name, zones.iter().map(|z| (*z).clone()).collect());
        Ok(())
    }

    async fn list(&self, name: &Name) -> Result<Vec<Name>, CatalogError> {
        let data = self.zones.lock().expect("poisoned");
        Ok(data.keys().filter(|k| name.zone_of(k)).cloned().collect())
    }

    async fn remove(&self, name: &walnut_proto::rr::Name) -> Result<Option<Vec<Z>>, CatalogError> {
        let mut data = self.zones.lock().expect("poisoned");
        Ok(data.remove(name))
    }
}
