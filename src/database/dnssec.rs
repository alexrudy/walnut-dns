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
use crate::{SqliteStore, ZoneInfo as _};

/// DNSSEC cryptographic key for zone signing
///
/// DNSKey wraps cryptographic key material and provides the ability to create
/// DNSSEC signers for zone signing operations. It securely stores private key
/// data using zeroization to prevent key material from remaining in memory.
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
pub struct DNSSecStore {
    catalog: SqliteStore,
    keys: Vec<Arc<DNSKey>>,
    allow_update: bool,
    dnssec_enabled: bool,
}

impl DNSSecStore {
    /// Create a new DNSSEC store from a regular SQLite store
    ///
    /// Wraps an existing SqliteStore to provide DNSSEC functionality.
    /// The store starts with DNSSEC disabled and no keys configured.
    ///
    /// # Arguments
    ///
    /// * `catalog` - The underlying SQLite store
    ///
    /// # Returns
    ///
    /// A new DNSSecStore instance
    pub fn new(catalog: SqliteStore) -> Self {
        Self {
            catalog,
            keys: Vec::new(),
            allow_update: false,
            dnssec_enabled: false,
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
        key: impl Into<Arc<DNSKey>>,
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

#[async_trait::async_trait]
impl CatalogStore<DNSSecZone<Zone>> for DNSSecStore {
    #[tracing::instrument(skip_all, fields(%origin), level = "debug")]
    async fn find(
        &self,
        origin: &LowerName,
    ) -> Result<Option<Vec<DNSSecZone<Zone>>>, CatalogError> {
        let zones = self.catalog.find(origin).await?;
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

    async fn upsert(
        &self,
        name: LowerName,
        zones: &[DNSSecZone<Zone>],
    ) -> Result<(), CatalogError> {
        let mut conn = self.catalog.connection().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = crate::database::ZonePersistence::new(&tx);

            // First clear existing name
            zx.clear(&name)?;
            let mut n = 0;
            for zone in zones {
                n += zx.upsert(zone)?;
            }
            tx.commit()?;
            tracing::debug!("upsert {n} zones");
            Ok(())
        })
    }

    async fn list(&self, name: &LowerName) -> Result<Vec<Name>, CatalogError> {
        self.catalog.list(name).await
    }

    async fn remove(
        &self,
        name: &LowerName,
    ) -> Result<Option<Vec<DNSSecZone<Zone>>>, CatalogError> {
        self.catalog.remove(name).await.map(|dz| {
            dz.map(|zs| {
                zs.into_iter()
                    .map(|z| DNSSecZone::new(z.into_inner()))
                    .collect()
            })
        })
    }
}
