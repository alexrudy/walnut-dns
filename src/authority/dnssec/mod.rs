use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use chrono::Utc;
use hickory_proto::ProtoError;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, KEY, NSEC, NSEC3, NSEC3PARAM, RRSIG, SIG};
use hickory_proto::dnssec::{DnsSecError, DnsSecResult, Nsec3HashAlgorithm, SigSigner, TBS};
use hickory_proto::rr::{DNSClass, LowerName, RData, RecordType, RrKey};
use hickory_server::authority::{AuthLookup, Authority, UpdateRequest as _};
use hickory_server::authority::{LookupControlFlow, LookupError};
use hickory_server::authority::{LookupObject, LookupOptions, LookupRecords};
use hickory_server::authority::{MessageRequest, Nsec3QueryInfo, UpdateResult};
use hickory_server::{dnssec::NxProofKind, server::RequestInfo};

use crate::rr::{AsHickory as _, Mismatch, Name, Record, RecordSet, TimeToLive};

pub use self::catalog::{DNSKey, DNSSecStore};
use super::{CatalogError, Lookup, ZoneAuthority, ZoneInfo};

mod authorize;
mod catalog;
mod prerequisites;
mod update;

pub trait Journal<Z> {
    fn insert_records(&self, zone: &Z, records: &[Record]) -> Result<(), CatalogError>;
    fn upsert_zone(&self, zone: &Z) -> Result<(), CatalogError>;
}

/// Error type to unify Mismatch errors and generic DNSSEC errors
#[derive(Debug, thiserror::Error)]
pub enum DnsSecZoneError {
    #[error(transparent)]
    Mismatch(#[from] Mismatch),
    #[error(transparent)]
    DnsSec(#[from] DnsSecError),
}

/// Adapter for DNSZones to provide DNSSEC features.
#[derive(Clone)]
pub struct DNSSecZone<Z> {
    zone: ZoneAuthority<Z>,
    secure_keys: Vec<Arc<SigSigner>>,
    nx_proof_kind: Option<NxProofKind>,
    allow_update: bool,
    is_dnssec_enabled: bool,
    journal: Option<Arc<dyn Journal<Self> + Send + Sync + 'static>>,
}

impl<Z> Deref for DNSSecZone<Z> {
    type Target = ZoneAuthority<Z>;

    fn deref(&self) -> &Self::Target {
        &self.zone
    }
}

impl<Z> DerefMut for DNSSecZone<Z> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.zone
    }
}

impl<Z> AsRef<Z> for DNSSecZone<Z> {
    fn as_ref(&self) -> &Z {
        &*self.zone
    }
}

impl<Z: ZoneInfo> fmt::Debug for DNSSecZone<Z> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DNSSecZone")
            .field("zone", &self.zone.origin())
            .field("secure_keys", &self.secure_keys.len())
            .field("nx_proof_kind", &self.nx_proof_kind)
            .finish()
    }
}

impl<Z> DNSSecZone<Z>
where
    Z: ZoneInfo,
{
    pub fn new(zone: Z) -> Self {
        Self {
            zone: ZoneAuthority::new(zone),
            secure_keys: Vec::new(),
            nx_proof_kind: None,
            allow_update: false,
            is_dnssec_enabled: true,
            journal: None,
        }
    }

    pub fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.nx_proof_kind.as_ref()
    }

    pub fn set_nx_proof_kind(&mut self, kind: Option<NxProofKind>) -> &mut Self {
        self.nx_proof_kind = kind;
        self
    }

    pub fn dnssec_enabled(&self) -> bool {
        self.is_dnssec_enabled
    }

    pub fn set_dnssec_enabled(&mut self, enabled: bool) -> &mut Self {
        self.is_dnssec_enabled = enabled;
        self
    }

    pub fn allow_update(&self) -> bool {
        self.allow_update
    }

    pub fn set_allow_update(&mut self, allow_update: bool) -> &mut Self {
        self.allow_update = allow_update;
        self
    }

    pub fn set_journal<J>(&mut self, journal: J) -> &mut Self
    where
        J: Journal<Self> + Send + Sync + 'static,
    {
        self.journal = Some(Arc::new(journal));
        self
    }

    pub fn secure_keys(&self) -> &[Arc<SigSigner>] {
        &self.secure_keys
    }

    pub fn persist_to_journal(&self) -> Result<(), CatalogError> {
        if let Some(journal) = self.journal.as_ref() {
            journal.upsert_zone(self)?;
        }

        Ok(())
    }
}

/// DNSSEC helper functions
impl<Z> DNSSecZone<Z>
where
    Z: ZoneInfo + Lookup,
{
    fn get_hashed_owner_name(
        &self,
        info: &Nsec3QueryInfo<'_>,
        name: &LowerName,
    ) -> Result<LowerName, ProtoError> {
        let hash = info.algorithm.hash(info.salt, name, info.iterations)?;
        let label = data_encoding::BASE32_DNSSEC.encode(hash.as_ref());
        Ok(LowerName::new(&self.origin().prepend_label(label)?))
    }

    fn proof(&self, info: Nsec3QueryInfo<'_>) -> Result<Vec<RecordSet>, LookupError> {
        let Nsec3QueryInfo {
            qname,
            qtype,
            has_wildcard_match,
            ..
        } = info;

        let rr_key = RrKey::new(
            self.get_hashed_owner_name(&info, self.origin())?,
            RecordType::NSEC3,
        );
        let qname_match = self.get(&rr_key);

        if has_wildcard_match {
            // - Wildcard answer response.
            let closest_encloser_name = self.closest_encloser_proof(qname, &info)?;
            let Some((closest_encloser_name, _)) = closest_encloser_name else {
                return Ok(vec![]);
            };

            let cover = self.find_cover(&closest_encloser_name, &info)?;
            return Ok(cover.map_or_else(Vec::new, |rr_set| vec![rr_set]));
        }

        if let Some(rr_set) = qname_match {
            // - No data response if the QTYPE is not DS.
            // - No data response if the QTYPE is DS and there is an NSEC3 record matching QNAME.
            return Ok(vec![rr_set.clone()]);
        }

        // - Name error response.
        // - No data response if QTYPE is DS and there is not an NSEC3 record matching QNAME.
        // - Wildcard no data response.
        let mut records = Vec::new();
        let (next_closer_name, closest_encloser_match) =
            self.closest_encloser_proof(qname, &info)?.unzip();
        if let Some(cover) = closest_encloser_match {
            records.push(cover);
        }

        let Some(next_closer_name) = next_closer_name else {
            return Ok(records);
        };

        if let Some(cover) = self.find_cover(&next_closer_name, &info)? {
            records.push(cover);
        }

        let wildcard_match = {
            let wildcard = qname.clone().into_wildcard();
            self.keys().any(|rr_key| rr_key.name == wildcard)
        };

        if wildcard_match {
            let wildcard_at_closest_encloser = next_closer_name.into_wildcard();
            let rr_key = RrKey::new(
                self.get_hashed_owner_name(&info, &wildcard_at_closest_encloser)?,
                RecordType::NSEC3,
            );

            if let Some(record) = self.get(&rr_key) {
                records.push(record.clone());
            }
        } else if qtype != RecordType::DS {
            let wildcard_at_closest_encloser = next_closer_name.into_wildcard();
            if let Some(cover) = self.find_cover(&wildcard_at_closest_encloser, &info)? {
                records.push(cover);
            }
        }

        records.sort_by(|a, b| a.name().cmp(b.name()));
        records.dedup_by(|a, b| a.name() == b.name());
        Ok(records)
    }

    fn closest_encloser_proof(
        &self,
        name: &LowerName,
        info: &Nsec3QueryInfo<'_>,
    ) -> Result<Option<(LowerName, RecordSet)>, ProtoError> {
        let mut next_closer_name = name.clone();
        let mut closest_encloser = next_closer_name.base_name();

        while !closest_encloser.is_root() {
            let rr_key = RrKey::new(
                self.get_hashed_owner_name(info, &closest_encloser)?,
                RecordType::NSEC3,
            );
            if let Some(rrs) = self.get(&rr_key) {
                return Ok(Some((next_closer_name, rrs.clone())));
            }

            next_closer_name = next_closer_name.base_name();
            closest_encloser = closest_encloser.base_name();
        }

        Ok(None)
    }

    fn find_cover(
        &self,
        name: &LowerName,
        info: &Nsec3QueryInfo<'_>,
    ) -> Result<Option<RecordSet>, ProtoError> {
        let owner_name = self.get_hashed_owner_name(info, name)?;
        let records = self
            .records()
            .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3);

        // Find the record with the largest owner name such that its owner name is before the
        // hashed QNAME. If this record exist, it already covers QNAME. Otherwise, the QNAME
        // preceeds all the existing NSEC3 records' owner names, meaning that it is covered by
        // the NSEC3 record with the largest owner name.
        Ok(records
            .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3)
            .filter(|rr_set| rr_set.name() < &*owner_name)
            .max_by_key(|rr_set| rr_set.name())
            .or_else(|| {
                self.records()
                    .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3)
                    .max_by_key(|rr_set| rr_set.name())
            })
            .cloned())
    }

    fn closest_nsec(&self, name: &LowerName) -> Option<RecordSet> {
        for rr_set in self.records_reversed() {
            if rr_set.record_type() != RecordType::NSEC {
                continue;
            }

            if *name < rr_set.name().into() {
                continue;
            }

            // there should only be one record
            let Some(record) = rr_set.records().next() else {
                continue;
            };

            let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = record.rdata() else {
                continue;
            };

            let next_domain_name = nsec.next_domain_name();
            // the search name is less than the next NSEC record
            if *name < next_domain_name.into() ||
                // this is the last record, and wraps to the beginning of the zone
                next_domain_name < rr_set.name()
            {
                return Some(rr_set.clone());
            }
        }

        None
    }

    fn nsec_zone(&mut self) {
        // only create nsec records for secure zones

        use std::mem;
        if self.secure_keys.is_empty() {
            return;
        }
        tracing::debug!("generating nsec records: {}", self.origin());

        // first remove all existing nsec records
        let delete_keys: Vec<RrKey> = self
            .zone
            .keys()
            .filter(|k| k.record_type == RecordType::NSEC)
            .cloned()
            .collect();

        for key in delete_keys {
            self.zone.remove(&key);
        }

        // now go through and generate the nsec records
        let ttl = self.minimum_ttl();
        let serial = self.serial();
        let mut records: Vec<Record> = vec![];

        {
            let mut nsec_info: Option<(&hickory_proto::rr::Name, BTreeSet<RecordType>)> = None;
            for key in self.zone.keys() {
                match &mut nsec_info {
                    None => nsec_info = Some((&key.name, BTreeSet::from([key.record_type]))),
                    Some((name, vec)) if LowerName::new(name) == key.name => {
                        vec.insert(key.record_type);
                    }
                    Some((name, vec)) => {
                        // names aren't equal, create the NSEC record
                        let rdata = NSEC::new_cover_self(key.name.clone().into(), mem::take(vec));
                        let record = Record::from_rdata(name.clone(), ttl, rdata);
                        records.push(record.into_record_rdata());

                        // new record...
                        nsec_info = Some((&key.name, BTreeSet::from([key.record_type])))
                    }
                }
            }

            // the last record
            if let Some((name, vec)) = nsec_info {
                // names aren't equal, create the NSEC record
                let rdata = NSEC::new_cover_self(self.origin().clone().into(), vec);
                let record = Record::from_rdata(name.clone(), ttl, rdata);
                records.push(record.into_record_rdata());
            }
        }

        // insert all the nsec records
        for record in records {
            let upserted = self.upsert(record, serial);
            debug_assert!(upserted.is_ok());
        }
    }

    fn nsec3_zone(
        &mut self,
        hash_alg: Nsec3HashAlgorithm,
        salt: &[u8],
        iterations: u16,
        opt_out: bool,
    ) -> DnsSecResult<()> {
        // only create nsec records for secure zones
        if self.secure_keys.is_empty() {
            return Ok(());
        }
        tracing::debug!(
            "generating nsec3 records: {origin}",
            origin = self.zone.origin()
        );

        // first remove all existing nsec records
        let delete_keys = self
            .zone
            .keys()
            .filter(|k| k.record_type == RecordType::NSEC3)
            .cloned()
            .collect::<Vec<_>>();

        for key in delete_keys {
            self.zone.remove(&key);
        }

        // now go through and generate the nsec3 records
        let ttl = self.minimum_ttl();
        let serial = self.serial();

        // Store the record types of each domain name so we can generate NSEC3 records for each
        // domain name.
        let mut record_types = HashMap::new();
        record_types.insert(
            self.zone.origin().clone(),
            ([RecordType::NSEC3PARAM].into(), true),
        );

        let mut delegation_points = HashSet::<LowerName>::new();

        for key in self.zone.keys() {
            if !self.zone.origin().zone_of(&key.name) {
                // Non-authoritative record outside of zone
                continue;
            }
            if delegation_points
                .iter()
                .any(|name| name.zone_of(&key.name) && name != &key.name)
            {
                // Non-authoritative record below zone cut
                continue;
            }
            if key.record_type == RecordType::NS && &key.name != self.zone.origin() {
                delegation_points.insert(key.name.clone());
            }

            // Store the type of the current record under its domain name
            match record_types.entry(key.name.clone()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let (rtypes, exists): &mut (HashSet<RecordType>, bool) = entry.get_mut();
                    rtypes.insert(key.record_type);
                    *exists = true;
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((HashSet::from([key.record_type]), true));
                }
            }
        }

        if opt_out {
            // Delete owner names that have unsigned delegations.
            let ns_only = HashSet::from([RecordType::NS]);
            record_types.retain(|_name, (types, _exists)| types != &ns_only);
        }

        // For every domain name between the current name and the origin, add it to `record_types`
        // without any record types. This covers all the empty non-terminals that must have an NSEC3
        // record as well.
        for name in record_types.keys().cloned().collect::<Vec<_>>() {
            let mut parent = name.base_name();
            while parent.num_labels() > self.zone.origin().num_labels() {
                record_types
                    .entry(parent.clone())
                    .or_insert_with(|| (HashSet::new(), false));
                parent = parent.base_name();
            }
        }

        // Compute the hash of all the names.
        let mut record_types = record_types
            .into_iter()
            .map(|(name, (type_bit_maps, exists))| {
                let hashed_name = hash_alg.hash(salt, &name, iterations)?;
                Ok((hashed_name, (type_bit_maps, exists)))
            })
            .collect::<Result<Vec<_>, ProtoError>>()?;
        // Sort by hash.
        record_types.sort_by(|(a, _), (b, _)| a.as_ref().cmp(b.as_ref()));

        let mut records = vec![];

        // Generate an NSEC3 record for every name
        for (i, (hashed_name, (type_bit_maps, exists))) in record_types.iter().enumerate() {
            // Get the next hashed name following the hash order.
            let next_index = (i + 1) % record_types.len();
            let next_hashed_name = record_types[next_index].0.as_ref().to_vec();

            let rdata = NSEC3::new(
                hash_alg,
                opt_out,
                iterations,
                salt.to_vec(),
                next_hashed_name,
                type_bit_maps
                    .iter()
                    .copied()
                    .chain(exists.then_some(RecordType::RRSIG)),
            );

            let name = self
                .zone
                .origin()
                .prepend_label(data_encoding::BASE32_DNSSEC.encode(hashed_name.as_ref()))?;

            let record = Record::from_rdata(name, ttl, rdata);
            records.push(record.into_record_rdata());
        }

        // Include the NSEC3PARAM record.
        let rdata = NSEC3PARAM::new(hash_alg, opt_out, iterations, salt.to_vec());
        let record = Record::from_rdata(self.zone.origin().clone().into(), ttl, rdata);
        records.push(record.into_record_rdata());

        // insert all the NSEC3 records.
        for record in records {
            let upserted = self.zone.upsert(record, serial);
            debug_assert!(upserted.is_ok());
        }

        Ok(())
    }

    fn sign_zone(&mut self) -> DnsSecResult<()> {
        tracing::debug!("signing zone: {}", self.zone.origin());

        let dns_class = self.zone.dns_class();
        let minimum_ttl = self.minimum_ttl();
        let secure_keys = &self.secure_keys;

        // TODO: should this be an error?
        if secure_keys.is_empty() {
            tracing::warn!(
                "attempt to sign_zone {} for dnssec, but no keys available!",
                self.origin()
            )
        }

        // sign all record_sets, as of 0.12.1 this includes DNSKEY
        for rr_set in self.zone.records_mut() {
            Self::sign_rrset(rr_set, secure_keys, minimum_ttl, dns_class)?;
        }

        Ok(())
    }

    pub(super) fn sign_rrset(
        rr_set: &mut RecordSet,
        secure_keys: &[Arc<SigSigner>],
        zone_ttl: TimeToLive,
        zone_class: DNSClass,
    ) -> DnsSecResult<()> {
        let inception = Utc::now();

        rr_set.clear_rrsigs();

        let rrsig_temp = Record::update0(rr_set.name().clone(), zone_ttl, RecordType::RRSIG);

        for signer in secure_keys {
            tracing::debug!(
                "signing rr_set: {}, {} with: {}",
                rr_set.name(),
                rr_set.record_type(),
                signer.key().algorithm(),
            );

            let expiration = inception + signer.sig_duration();
            let records: Vec<_> = rr_set.records().map(|rr| rr.as_hickory()).collect();
            let tbs = TBS::from_sig(
                rr_set.name(),
                zone_class,
                &SIG::new(
                    rr_set.record_type(),
                    signer.key().algorithm(),
                    rr_set.name().num_labels(),
                    rr_set.ttl().into(),
                    expiration.timestamp() as u32,
                    inception.timestamp() as u32,
                    signer.calculate_key_tag()?,
                    signer.signer_name().clone(),
                    Vec::new(), // Gets thrown away anyways.
                ),
                records.iter(),
            );

            // TODO, maybe chain these with some ETL operations instead?
            let tbs = match tbs {
                Ok(tbs) => tbs,
                Err(err) => {
                    tracing::error!("could not serialize rrset to sign: {}", err);
                    continue;
                }
            };

            let signature = signer.sign(&tbs);
            let signature = match signature {
                Ok(signature) => signature,
                Err(err) => {
                    tracing::error!("could not sign rrset: {}", err);
                    continue;
                }
            };

            let mut rrsig = rrsig_temp.clone();
            rrsig.set_data(RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                // type_covered: RecordType,
                rr_set.record_type(),
                // algorithm: Algorithm,
                signer.key().algorithm(),
                // num_labels: u8,
                rr_set.name().num_labels(),
                // original_ttl: u32,
                rr_set.ttl().into(),
                // sig_expiration: u32,
                expiration.timestamp() as u32,
                inception.timestamp() as u32,
                // key_tag: u16,
                signer.calculate_key_tag()?,
                // signer_name: Name,
                signer.signer_name().clone(),
                // sig: Vec<u8>
                signature,
            ))));

            rr_set
                .insert_rrsig(rrsig)
                .map_err(|error| DnsSecError::from(error.to_string()))?;
        }

        Ok(())
    }
}

impl<Z> DNSSecZone<Z>
where
    Z: ZoneInfo + Lookup,
{
    /// Adds a zone signing key to the zone as a DNSSEC KEY record.
    pub fn add_update_auth_key(
        &mut self,
        name: Name,
        key: KEY,
        ttl: TimeToLive,
    ) -> Result<bool, Mismatch> {
        let rdata = RData::DNSSEC(DNSSECRData::KEY(key));
        let record = Record::from_rdata(name, ttl, rdata);

        let serial = self.zone.serial();
        self.zone.upsert(record, serial)
    }

    /// Adds a zone signing key to the zone.
    pub fn add_zone_signing_key(&mut self, signer: SigSigner) -> Result<(), DnsSecZoneError> {
        let zone_ttl = self.minimum_ttl();
        let dnskey = DNSKEY::from_key(&signer.key().to_public_key()?);
        let dnskey = Record::from_rdata(
            self.name().clone(),
            zone_ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );

        // TODO: also generate the CDS and CDNSKEY
        let serial = self.serial();
        self.zone.upsert(dnskey, serial)?;
        self.secure_keys.push(Arc::new(signer));
        Ok(())
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[tracing::instrument(skip_all, level = "trace")]
    pub fn secure_zone(&mut self) -> DnsSecResult<()> {
        match self.nx_proof_kind.as_ref() {
            Some(NxProofKind::Nsec) => self.nsec_zone(),
            Some(NxProofKind::Nsec3 {
                algorithm,
                salt,
                iterations,
                opt_out,
            }) => self.nsec3_zone(*algorithm, &salt.clone(), *iterations, *opt_out)?,
            None => (),
        }

        // need to resign any records at the current serial number and bump the number.
        // first bump the serial number on the SOA, so that it is resigned with the new serial.
        self.increment_soa_serial();

        // TODO: should we auto sign here? or maybe up a level...
        self.sign_zone()
    }
}

#[async_trait::async_trait]
impl<Z> Authority for DNSSecZone<Z>
where
    Z: Lookup + ZoneInfo + Clone + Send + Sync + 'static,
{
    type Lookup = AuthLookup;

    /// What type is this zone
    fn zone_type(&self) -> hickory_server::authority::ZoneType {
        self.zone.zone_type()
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.zone.is_axfr_allowed()
    }

    /// Takes the UpdateMessage, extracts the Records, and applies the changes to the record set.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.4 - Process Update Section
    ///
    ///   Next, the Update Section is processed as follows.
    ///
    /// 3.4.2 - Update
    ///
    ///   The Update Section is parsed into RRs and these RRs are processed in
    ///   order.
    ///
    /// 3.4.2.1. If any system failure (such as an out of memory condition,
    ///   or a hardware error in persistent storage) occurs during the
    ///   processing of this section, signal SERVFAIL to the requestor and undo
    ///   all updates applied to the zone during this transaction.
    ///
    /// 3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
    ///   the zone.  In case of duplicate RDATAs (which for SOA RRs is always
    ///   the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
    ///   fields both match), the Zone RR is replaced by Update RR.  If the
    ///   TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
    ///   lower (according to [RFC1982]) than or equal to the current Zone SOA
    ///   RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
    ///   Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
    ///   Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
    ///   RR.
    ///
    /// 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
    ///   all Zone RRs with the same NAME are deleted, unless the NAME is the
    ///   same as ZNAME in which case only those RRs whose TYPE is other than
    ///   SOA or NS are deleted.  For any Update RR whose CLASS is ANY and
    ///   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
    ///   deleted, unless the NAME is the same as ZNAME in which case neither
    ///   SOA or NS RRs will be deleted.
    ///
    /// 3.4.2.4. For any Update RR whose class is NONE, any Zone RR whose
    ///   NAME, TYPE, RDATA and RDLENGTH are equal to the Update RR is deleted,
    ///   unless the NAME is the same as ZNAME and either the TYPE is SOA or
    ///   the TYPE is NS and the matching Zone RR is the only NS remaining in
    ///   the RRset, in which case this Update RR is ignored.
    ///
    /// 3.4.2.5. Signal NOERROR to the requestor.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `update` - The `UpdateMessage` records will be extracted and used to perform the update
    ///              actions as specified in the above RFC.
    ///
    /// # Return value
    ///
    /// true if any of additions, updates or deletes were made to the zone, false otherwise. Err is
    ///  returned in the case of bad data, etc.
    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        //let this = &mut self.in_memory.lock().await;
        // the spec says to authorize after prereqs, seems better to auth first.
        self.authorize(update).await?;
        self.verify_prerequisites(update.prerequisites()).await?;
        self.pre_scan(update.updates()).await?;

        let mut updated_zone = self.clone();
        updated_zone.update_records(update.updates(), true).await?;

        Ok(true)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.zone.origin()
    }

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.zone.lookup(name, query_type, lookup_options).await
    }

    /// Consulting lookup for all Resource Records matching the given `Name` and `RecordType`.
    /// This will be called in a chained authority configuration after an authority in the chain
    /// has returned a lookup with a LookupControlFlow::Continue action. Every other authority in
    /// the chain will be called via this consult method, until one either returns a
    /// LookupControlFlow::Break action, or all authorities have been consulted.  The authority that
    /// generated the primary lookup (the one returned via 'lookup') will not be consulted.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    /// * `last_result` - The lookup returned by a previous authority in a chained configuration.
    ///                   If a subsequent authority does not modify this lookup, it will be returned
    ///                   to the client after consulting all authorities in the chain.
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.  This can
    /// be the same last_result that was passed in, or a new lookup, depending on the logic of the
    /// authority in question.
    async fn consult(
        &self,
        _name: &LowerName,
        _rtype: RecordType,
        _lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        last_result
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `request` - the query to perform the lookup with.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.zone.search(request_info, lookup_options).await
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    #[allow(unused_variables)]
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let rr_key = RrKey::new(name.clone(), RecordType::NSEC);
        let no_data = self
            .get(&rr_key)
            .map(|rr_set| LookupRecords::new(lookup_options, rr_set.as_hickory().into()));

        if let Some(no_data) = no_data {
            return LookupControlFlow::Continue(Ok(no_data.into()));
        }

        let closest_proof = self.closest_nsec(name);

        // we need the wildcard proof, but make sure that it's still part of the zone.
        let wildcard = name.base_name();
        let origin = self.origin();
        let wildcard = if origin.zone_of(&wildcard) {
            wildcard
        } else {
            origin.clone()
        };

        // don't duplicate the record...
        let wildcard_proof = if wildcard != *name {
            self.closest_nsec(&wildcard)
        } else {
            None
        };

        let proofs = match (closest_proof, wildcard_proof) {
            (Some(closest_proof), Some(wildcard_proof)) => {
                // dedup with the wildcard proof
                if wildcard_proof != closest_proof {
                    vec![wildcard_proof, closest_proof]
                } else {
                    vec![closest_proof]
                }
            }
            (None, Some(proof)) | (Some(proof), None) => vec![proof],
            (None, None) => vec![],
        };

        LookupControlFlow::Continue(Ok(LookupRecords::many(
            lookup_options,
            proofs
                .into_iter()
                .map(|rrset| rrset.as_hickory().into())
                .collect(),
        )
        .into()))
    }

    /// Return the NSEC3 records based on the information available for a query.
    #[allow(unused_variables)]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(self.proof(info).map(|proof| {
            LookupRecords::many(
                lookup_options,
                proof
                    .into_iter()
                    .map(|rrset| rrset.as_hickory().into())
                    .collect(),
            )
            .into()
        }))
    }

    /// Returns the kind of non-existence proof used for this zone.
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.nx_proof_kind.as_ref()
    }
}
