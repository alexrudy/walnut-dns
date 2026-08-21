use std::fmt;
use std::ops::Deref as _;
use std::sync::Arc;

use hickory_proto::dnssec::crypto::signing_key_from_der;
use hickory_proto::dnssec::{Algorithm, DnsSecResult};
use hickory_proto::dnssec::{SigSigner, rdata::DNSKEY};
use hickory_proto::rr::Name;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::ZoneInfo as _;
use crate::authority::{DnsSecZone, DnsSecZoneError, Journal};
use crate::catalog::{CatalogError, CatalogStore};
use walnut_proto::rr::{TimeToLive, Zone};

use super::SqliteStore;
use super::journal::SqliteJournal;

/// DNSSEC cryptographic key for zone signing
///
/// DNSKey wraps cryptographic key material and provides the ability to create
/// DNSSEC signers for zone signing operations. It securely stores private key
/// data using zeroization to prevent key material from remaining in memory.
#[derive(Clone)]
pub struct DnsKey {
    key_data: Zeroizing<Box<[u8]>>,
    algorithm: Algorithm,
    ttl: TimeToLive,
}

impl fmt::Debug for DnsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBuilder")
            .field("algorithm", &self.algorithm)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl DnsKey {
    /// Create a new DNSSEC key
    ///
    /// Creates a new DNSSEC key from the provided key material, algorithm,
    /// and TTL. The key data should be in DER format.
    ///
    /// # Arguments
    ///
    /// * `key_data` - The private key data in DER format
    /// * `algorithm` - The DNSSEC algorithm to use
    /// * `ttl` - TTL for DNSKEY records created from this key
    ///
    /// # Returns
    ///
    /// A new DNSKey instance
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

/// DNSSEC-enabled DNS zone storage
///
/// DNSSecStore wraps a regular SqliteStore and adds DNSSEC capabilities,
/// including key management and automatic zone signing. It provides the same
/// storage interface as SqliteStore but returns DNSSEC-enabled zones.
#[derive(Debug, Clone)]
pub struct DnsSecStore<S, J> {
    store: S,
    journal: J,
    keys: Vec<Arc<DnsKey>>,
    allow_update: bool,
    dnssec_enabled: bool,
}

impl<S> DnsSecStore<S, ()> {
    /// Create a new DNSSEC store from a regular store
    ///
    ///
    /// # Arguments
    ///
    /// * `store` - The underlying SQLite store
    /// * `journal` - The journal store used for transaction tracking
    ///
    /// # Returns
    ///
    /// A new DNSSecStore instance
    pub fn new(store: S) -> Self {
        Self {
            store,
            journal: (),
            keys: Vec::new(),
            allow_update: false,
            dnssec_enabled: false,
        }
    }
}

impl DnsSecStore<SqliteStore, SqliteJournal> {
    /// Create a new DNSSEC store from a regular SQLite store and use that same
    /// store as the journal.
    ///
    /// # Arguments
    ///
    /// * `store` - The underlying SQLite store
    ///
    /// # Returns
    ///
    /// A new DNSSecStore instance
    pub fn new_sqlite(store: SqliteStore) -> Self {
        let journal = store.journal();
        Self {
            store,
            journal,
            keys: Vec::new(),
            allow_update: false,
            dnssec_enabled: false,
        }
    }
}

impl<S, J> DnsSecStore<S, J> {
    pub fn with_journal<J2>(self, journal: J2) -> DnsSecStore<S, J2> {
        DnsSecStore {
            store: self.store,
            journal,
            keys: self.keys,
            allow_update: self.allow_update,
            dnssec_enabled: self.dnssec_enabled,
        }
    }

    /// Add a zone signing key to this store
    ///
    /// Adds a DNSSEC key that will be used to sign all zones managed by
    /// this store. Multiple keys can be added for key rollover scenarios.
    ///
    /// # Arguments
    ///
    /// * `key` - The DNSSEC key to add
    ///
    /// # Returns
    ///
    /// Success or an error if the key cannot be added
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or cannot be processed
    pub fn add_zone_signing_key(
        &mut self,
        key: impl Into<Arc<DnsKey>>,
    ) -> Result<(), DnsSecZoneError> {
        self.keys.push(key.into());
        Ok(())
    }

    /// Check if DNS updates are allowed
    ///
    /// Returns whether this store allows DNS UPDATE operations.
    ///
    /// # Returns
    ///
    /// `true` if updates are allowed
    pub fn allow_update(&self) -> bool {
        self.allow_update
    }

    /// Set whether to allow DNS updates
    ///
    /// Enables or disables DNS UPDATE operations for zones managed by this store.
    ///
    /// # Arguments
    ///
    /// * `allow_update` - Whether to allow updates
    ///
    /// # Returns
    ///
    /// A mutable reference to this store for method chaining
    pub fn set_allow_update(&mut self, allow_update: bool) -> &mut Self {
        self.allow_update = allow_update;
        self
    }

    /// Check if DNSSEC is enabled
    ///
    /// Returns whether DNSSEC signing is enabled for zones managed by this store.
    ///
    /// # Returns
    ///
    /// `true` if DNSSEC is enabled
    pub fn dnssec_enabled(&self) -> bool {
        self.dnssec_enabled
    }

    /// Set whether to enable DNSSEC
    ///
    /// Enables or disables DNSSEC signing for zones managed by this store.
    /// When enabled, zones will be automatically signed with configured keys.
    ///
    /// # Arguments
    ///
    /// * `dnssec_enabled` - Whether to enable DNSSEC
    ///
    /// # Returns
    ///
    /// A mutable reference to this store for method chaining
    pub fn set_dnssec_enabled(&mut self, dnssec_enabled: bool) -> &mut Self {
        self.dnssec_enabled = dnssec_enabled;
        self
    }

    /// Get a journal for recording DNS operations
    ///
    /// Returns a journal that can be used to record DNS operations
    /// for zones managed by this store.
    ///
    /// # Returns
    ///
    /// A SqliteJournal instance
    pub fn journal(&self) -> &J {
        &self.journal
    }
}

impl<S, J> DnsSecStore<S, J>
where
    J: Journal<DnsSecZone<Zone>> + Clone + Send + Sync + 'static,
{
    fn map_zone(&self, zone: Zone) -> Result<DnsSecZone<Zone>, DnsSecZoneError> {
        let mut dnsseczone = DnsSecZone::new(zone);
        dnsseczone
            .set_allow_update(self.allow_update)
            .set_dnssec_enabled(self.dnssec_enabled)
            .set_journal(self.journal.clone());
        for key in &self.keys {
            dnsseczone.add_zone_signing_key(key.build(dnsseczone.origin().clone())?)?;
        }
        Ok(dnsseczone)
    }
}

#[async_trait::async_trait]
impl<S, J> CatalogStore<DnsSecZone<Zone>> for DnsSecStore<S, J>
where
    S: CatalogStore<Zone> + Sync + 'static,
    J: Journal<DnsSecZone<Zone>> + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip_all, fields(%origin), level = "debug")]
    async fn find(&self, origin: &Name) -> Result<Option<Vec<DnsSecZone<Zone>>>, CatalogError> {
        let zones = self.store.find(origin).await?;
        if let Some(zones) = zones {
            Ok(Some(
                zones
                    .into_iter()
                    .map(|z| self.map_zone(z))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(CatalogError::new)?,
            ))
        } else {
            Ok(None)
        }
    }

    async fn upsert(&self, name: Name, zones: &[&DnsSecZone<Zone>]) -> Result<(), CatalogError> {
        let zones = zones.iter().map(|&z| z.deref()).collect::<Vec<&Zone>>();
        self.store.upsert(name, &zones).await
    }

    async fn list(&self, name: &Name) -> Result<Vec<Name>, CatalogError> {
        self.store.list(name).await
    }

    async fn remove(&self, name: &Name) -> Result<Option<Vec<DnsSecZone<Zone>>>, CatalogError> {
        self.store
            .remove(name)
            .await
            .map(|dz| dz.map(|zs| zs.into_iter().map(DnsSecZone::new).collect()))
    }
}
