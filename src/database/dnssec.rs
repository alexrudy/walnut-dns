use std::fmt;
use std::sync::Arc;

use hickory_proto::dnssec::crypto::signing_key_from_der;
use hickory_proto::dnssec::{Algorithm, DnsSecResult};
use hickory_proto::dnssec::{SigSigner, rdata::DNSKEY};
use hickory_proto::rr::{LowerName, Name};
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::authority::{DNSSecZone, DnsSecZoneError};
use crate::catalog::{CatalogError, CatalogStore};
use crate::database::journal::SqliteJournal;
use crate::rr::{TimeToLive, Zone};
use crate::{SqliteCatalog, ZoneInfo as _};

/// DNSSEC key builder
#[derive(Clone)]
pub struct DNSKey {
    key_data: Zeroizing<Box<[u8]>>,
    algorithm: Algorithm,
    ttl: TimeToLive,
}

impl fmt::Debug for DNSKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBuilder")
            .field("algorithm", &self.algorithm)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl DNSKey {
    pub fn new(key_data: impl Into<Box<[u8]>>, algorithm: Algorithm, ttl: TimeToLive) -> Self {
        Self {
            key_data: Zeroizing::new(key_data.into()),
            ttl,
            algorithm,
        }
    }

    fn build(&self, name: Name) -> DnsSecResult<SigSigner> {
        let private = PrivateKeyDer::try_from(self.key_data.as_ref())?;
        let key = signing_key_from_der(&private, self.algorithm)?;

        Ok(SigSigner::dnssec(
            DNSKEY::from_key(&key.to_public_key().unwrap()),
            key,
            name,
            self.ttl.into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct DNSSecStore {
    catalog: SqliteCatalog,
    keys: Vec<Arc<DNSKey>>,
    allow_update: bool,
    dnssec_enabled: bool,
}

impl DNSSecStore {
    pub fn new(catalog: SqliteCatalog) -> Self {
        Self {
            catalog,
            keys: Vec::new(),
            allow_update: false,
            dnssec_enabled: false,
        }
    }

    pub fn add_zone_signing_key(
        &mut self,
        key: impl Into<Arc<DNSKey>>,
    ) -> Result<(), DnsSecZoneError> {
        self.keys.push(key.into());
        Ok(())
    }

    pub fn allow_update(&self) -> bool {
        self.allow_update
    }

    pub fn set_allow_update(&mut self, allow_update: bool) -> &mut Self {
        self.allow_update = allow_update;
        self
    }

    pub fn dnssec_enabled(&self) -> bool {
        self.dnssec_enabled
    }

    pub fn set_dnssec_enabled(&mut self, dnssec_enabled: bool) -> &mut Self {
        self.dnssec_enabled = dnssec_enabled;
        self
    }

    pub fn journal(&self) -> SqliteJournal {
        self.catalog.journal()
    }

    fn map_zone(&self, zone: Zone) -> Result<DNSSecZone<Zone>, DnsSecZoneError> {
        let mut dnsseczone = DNSSecZone::new(zone);
        dnsseczone
            .set_allow_update(self.allow_update)
            .set_dnssec_enabled(self.dnssec_enabled)
            .set_journal(self.catalog.journal());
        for key in &self.keys {
            dnsseczone.add_zone_signing_key(key.build(dnsseczone.origin().clone().into())?)?;
        }
        Ok(dnsseczone)
    }
}

impl CatalogStore<DNSSecZone<Zone>> for DNSSecStore {
    #[tracing::instrument(skip_all, fields(%origin), level = "debug")]
    fn find(&self, origin: &LowerName) -> Result<Option<Vec<DNSSecZone<Zone>>>, CatalogError> {
        let zones = self.catalog.find(origin)?;
        if let Some(zones) = zones {
            Ok(Some(
                zones
                    .into_iter()
                    .map(|z| self.map_zone(z.into_inner()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(CatalogError::new)?,
            ))
        } else {
            Ok(None)
        }
    }

    fn upsert(&self, name: LowerName, zones: &[DNSSecZone<Zone>]) -> Result<(), CatalogError> {
        let cc = self.catalog.connection();
        let mut conn = cc.lock().expect("connection poisoned");
        let tx = conn.transaction()?;
        let zx = crate::database::ZonePersistence::new(&tx);

        // First clear existing name
        zx.clear(&name)?;
        let mut n = 0;
        for zone in zones {
            n += zx.upsert(&zone)?;
        }
        tx.commit()?;
        tracing::debug!("upsert {n} zones");
        Ok(())
    }

    fn list(&self) -> Result<Vec<Name>, CatalogError> {
        self.catalog.list()
    }

    fn remove(&self, name: &LowerName) -> Result<Option<Vec<DNSSecZone<Zone>>>, CatalogError> {
        self.catalog.remove(name).map(|dz| {
            dz.map(|zs| {
                zs.into_iter()
                    .map(|z| DNSSecZone::new(z.into_inner()))
                    .collect()
            })
        })
    }
}
