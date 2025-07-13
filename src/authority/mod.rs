use std::borrow::Borrow;
use std::collections::HashSet;
use std::ops::{Deref, DerefMut, RangeBounds};
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, LowerName, RecordType, RrKey};
use hickory_server::authority::{AnyRecords, AuthLookup, Authority, AuthorityObject};
use hickory_server::authority::{LookupControlFlow, LookupError};
use hickory_server::authority::{LookupObject, LookupOptions, LookupRecords};
use hickory_server::authority::{MessageRequest, Nsec3QueryInfo, UpdateResult};
use hickory_server::{dnssec::NxProofKind, server::RequestInfo};

use crate::rr::{
    AsHickory as _, Mismatch, Name, Record, RecordSet, SerialNumber, TimeToLive, ZoneType,
};

mod catalog;
mod dnssec;
mod edns;
mod response;

pub use self::catalog::{Catalog, CatalogError, CatalogStore};
pub use self::dnssec::{DNSKey, DNSSecStore};
pub use self::dnssec::{DNSSecZone, Journal};
use self::edns::EdnsResponse;

pub(crate) type LookupChain<L, E = LookupError> = (LookupControlFlow<L, E>, Option<LookupRecords>);

/// Provides basic information about a DNS Zone that can be used for lookups.
pub trait ZoneInfo {
    fn name(&self) -> &Name;
    fn origin(&self) -> &LowerName;
    fn zone_type(&self) -> ZoneType;
    fn is_axfr_allowed(&self) -> bool;
    fn dns_class(&self) -> DNSClass;
    fn serial(&self) -> SerialNumber;
    fn soa(&self) -> Option<&Record>;
    fn increment_soa_serial(&mut self) -> SerialNumber;
    fn minimum_ttl(&self) -> TimeToLive;
}

pub trait Lookup: ZoneInfo {
    fn get(&self, key: &RrKey) -> Option<&RecordSet>;
    fn get_mut(&mut self, key: &RrKey) -> Option<&mut RecordSet>;
    fn keys(&self) -> impl Iterator<Item = &RrKey>;
    fn records(&self) -> impl Iterator<Item = &RecordSet>;
    fn records_reversed(&self) -> impl Iterator<Item = &RecordSet>;
    fn records_mut(&mut self) -> impl Iterator<Item = &mut RecordSet>;
    fn upsert(&mut self, record: Record, serial: SerialNumber) -> Result<bool, Mismatch>;
    fn remove(&mut self, key: &RrKey) -> Option<RecordSet>;
    fn range<T, R>(&self, range: R) -> impl Iterator<Item = (&RrKey, &RecordSet)>
    where
        T: Ord + ?Sized,
        RrKey: Borrow<T> + Ord,
        R: RangeBounds<T>;

    fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let lz = LookupZone(self);
        lz.lookup(name, query_type, lookup_options)
    }
}

struct LookupZone<'z, Z: ?Sized>(&'z Z);

impl<'z, Z> LookupZone<'z, Z>
where
    Z: Lookup + ?Sized,
{
    #[tracing::instrument(level = "trace", skip_all, fields(query=%query_type))]
    fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let (result, additionals) = if matches!(query_type, RecordType::AXFR | RecordType::ANY) {
            self.lookup_any(name, query_type, lookup_options)
        } else {
            let answer = self.lookup_records(name, query_type, lookup_options);
            if let Some(rrset) = &answer {
                tracing::trace!("found {} records for {}", rrset.len(), rrset.record_type());
            }

            // evaluate any cnames for additional inclusion
            let additional_records_chain_root: Option<(_, _)> = answer
                .as_ref()
                .and_then(|rrset| rrset.next_lookup_name(query_type))
                .and_then(|(search_name, search_type)| {
                    self.additional_search(
                        name,
                        query_type,
                        search_name,
                        search_type,
                        lookup_options,
                    )
                    .map(|adds| (adds, search_type))
                });

            let (additionals, answer) = match (additional_records_chain_root, answer, query_type) {
                (Some((additionals, RecordType::ANAME)), Some(answer), RecordType::A)
                | (Some((additionals, RecordType::ANAME)), Some(answer), RecordType::AAAA) => {
                    // This should always be true...
                    debug_assert_eq!(answer.record_type(), RecordType::ANAME);
                    let last_rrset = additionals.last();
                    let last_ttl = last_rrset.map_or(TimeToLive::MAX, |rec| rec.ttl());
                    let rdatas: Option<Vec<_>> =
                        last_rrset.and_then(|rrset| match rrset.record_type() {
                            RecordType::A | RecordType::AAAA => Some(
                                rrset
                                    .records()
                                    .map(|record| record.rdata().clone())
                                    .collect(),
                            ),
                            _ => None,
                        });

                    let ttl = answer.ttl().min(last_ttl);
                    let mut new_answer = RecordSet::new(answer.name().clone(), query_type);
                    new_answer.set_ttl(ttl);
                    new_answer.set_dns_class(DNSClass::IN);
                    for rdata in rdatas.into_iter().flatten() {
                        new_answer.push(rdata).unwrap();
                    }

                    //TODO: New-answer needs to be re-signed for DNSSEC to work.
                    tracing::warn!("New answer created, need to re-sign it if DNSSEC is enabled");

                    let additionals = std::iter::once(answer).chain(additionals).collect();
                    (Some(additionals), Some(new_answer))
                }
                (Some((additionals, _)), answer, _) => (Some(additionals), answer),
                (None, answer, _) => (None, answer),
            };

            let answer = answer.map_or(
                LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::NXDomain))),
                |rr_set| {
                    LookupControlFlow::Continue(Ok(LookupRecords::new(
                        lookup_options,
                        Arc::new(rr_set.as_hickory()),
                    )))
                },
            );

            let additionals = additionals.map(|a| {
                tracing::trace!("Adding {} alternate lookup records", a.len());
                LookupRecords::many(
                    lookup_options,
                    a.into_iter()
                        .map(|rrset| Arc::new(rrset.as_hickory()))
                        .collect(),
                )
            });

            (answer, additionals)
        };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        // TODO: can we get rid of this?
        use LookupControlFlow::*;
        let result = match result {
            Continue(Err(LookupError::ResponseCode(ResponseCode::NXDomain))) => {
                if self
                    .0
                    .keys()
                    .any(|key| key.name() == name || name.zone_of(key.name()))
                {
                    tracing::trace!("Other types exist at the same name: NameExists");
                    return Continue(Err(LookupError::NameExists));
                } else {
                    let code = if self.0.origin().zone_of(name) {
                        tracing::trace!(
                            "{} is the parent zone of {name}, but no records exist at the same name: NXDomain",
                            self.0.origin()
                        );
                        ResponseCode::NXDomain
                    } else {
                        tracing::trace!("{} is not the parent zone of {name}", self.0.origin());
                        ResponseCode::Refused
                    };
                    return Continue(Err(LookupError::from(code)));
                }
            }
            Continue(Err(e)) => return Continue(Err(e)),
            o => o,
        };

        result.map(|answers| AuthLookup::answers(answers, additionals))
    }

    /// Perform an AXFR or ANY record lookup, returning all available records for this zone.
    fn lookup_any(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupChain<LookupRecords> {
        debug_assert!(matches!(query_type, RecordType::AXFR | RecordType::ANY));

        let records = AnyRecords::new(
            lookup_options,
            self.0
                .records()
                .map(|rset| Arc::new(rset.as_hickory()))
                .collect(),
            query_type,
            name.clone(),
        );

        tracing::trace!("Lookup AXFR|ANY {} records", self.0.records().count());
        (
            LookupControlFlow::Continue(Ok(LookupRecords::AnyRecords(records))),
            None,
        )
    }

    /// Perform a direct lookup for a set of records matching the query type
    fn lookup_records(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<RecordSet> {
        self.lookup_record(name, query_type, lookup_options)
            .cloned()
            .or_else(|| {
                tracing::trace!("No direct record found");
                self.lookup_wildcard(name, query_type, lookup_options)
            })
    }

    fn lookup_record(
        &self,
        name: &LowerName,
        query_type: RecordType,
        _lookup_options: LookupOptions,
    ) -> Option<&RecordSet> {
        tracing::trace!("Lookup {name} {query_type}");
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MAX));

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        self.0
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .find(|(key, _)| {
                key.record_type == query_type
                    || key.record_type == RecordType::CNAME
                    || aname_covers_type(key.record_type, query_type)
            })
            .map(|(_key, rr_set)| rr_set)
            .inspect(|rr_set| tracing::trace!("Found {} records", rr_set.len()))
    }

    #[tracing::instrument("wildcard", skip_all, level = "trace")]
    fn lookup_wildcard(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<RecordSet> {
        // if this is a wildcard or a root, both should break continued lookups
        if name.is_wildcard() || name.is_root() {
            tracing::trace!("Not recursing in root or wildcard name");
            return None;
        }
        tracing::debug!("Wildcard lookup for {}", name);
        let mut wildcard = name.clone().into_wildcard();

        loop {
            let Some(rrset) = self.lookup_record(&wildcard, query_type, lookup_options) else {
                let parent = wildcard.base_name();
                if parent.is_root() {
                    tracing::trace!("No wildcard records found");
                    return None;
                }

                wildcard = parent.into_wildcard();
                continue;
            };

            // we need to change the name to the query name in the result set since this was a wildcard
            let new_answer = rrset.with_name(name.clone().into());

            //TODO This needs to be signed.
            tracing::warn!("New answer created, need to re-sign it if DNSSEC is enabled");

            return Some(new_answer);
        }
    }

    fn additional_search(
        &self,
        original_name: &LowerName,
        original_query_type: RecordType,
        next_name: LowerName,
        _search_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Vec<RecordSet>> {
        tracing::trace!(
            "Additional search for name: {}, query type: {:?}",
            next_name,
            original_query_type
        );
        let mut additionals = Vec::new();
        let mut query_types_arr = [original_query_type; 2];
        let query_types: &[RecordType] = match original_query_type {
            RecordType::ANAME | RecordType::NS | RecordType::MX | RecordType::SRV => {
                query_types_arr = [RecordType::A, RecordType::AAAA];
                &query_types_arr[..]
            }
            _ => &query_types_arr[..1],
        };

        for query_type in query_types {
            let mut names = HashSet::new();
            if query_type == &original_query_type {
                names.insert(original_name.clone());
            }

            let mut next_name = Some(next_name.clone());
            while let Some(search) = next_name.take() {
                // If we've already looked up this name then bail out.
                if names.contains(&search) {
                    break;
                }

                let additional = self.lookup_records(&search, *query_type, lookup_options);
                names.insert(search);

                if let Some(additional) = additional {
                    // assuming no crazy long chains...
                    if !additionals.contains(&additional) {
                        additionals.push(additional.clone());
                    }

                    next_name = additional
                        .next_lookup_name(*query_type)
                        .map(|(name, _)| name);
                }
            }
        }

        if !additionals.is_empty() {
            tracing::trace!("Additional search found {} records", additionals.len());
            Some(additionals)
        } else {
            tracing::trace!("No additional seach found");
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZoneAuthority<Z>(Z);

impl<Z> ZoneAuthority<Z> {
    pub fn new(zone: Z) -> Self {
        Self(zone)
    }

    pub fn into_inner(self) -> Z {
        self.0
    }
}

impl<Z> AsRef<dyn AuthorityObject> for ZoneAuthority<Z>
where
    Z: Lookup + ZoneInfo + Send + Sync + 'static,
{
    fn as_ref(&self) -> &(dyn AuthorityObject + 'static) {
        self
    }
}

impl<Z> Deref for ZoneAuthority<Z> {
    type Target = Z;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Z> DerefMut for ZoneAuthority<Z> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[async_trait::async_trait]
impl<Z> Authority for ZoneAuthority<Z>
where
    Z: Lookup + ZoneInfo + Send + Sync + 'static,
{
    type Lookup = AuthLookup;

    /// What type is this zone
    fn zone_type(&self) -> hickory_server::authority::ZoneType {
        self.0.zone_type().into()
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.0.is_axfr_allowed()
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
    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        // No update for non-DNSSEC Zone
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.0.origin()
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
        tracing::trace!("Starting lookup for name: {}, type: {}", name, query_type);
        let result = self.0.lookup(name, query_type, lookup_options);
        match &result {
            LookupControlFlow::Continue(Ok(lookup)) => {
                tracing::trace!(
                    "Lookup for name: {}, type: {} found {} records (CONTINUE)",
                    name,
                    query_type,
                    lookup.iter().count()
                );
            }
            LookupControlFlow::Continue(Err(_)) => {
                tracing::trace!(
                    "Lookup for name: {}, type: {} error (CONTINUE)",
                    name,
                    query_type,
                );
            }
            LookupControlFlow::Break(Ok(lookup)) => {
                tracing::trace!(
                    "Lookup for name: {}, type: {} found {} records (BREAK)",
                    name,
                    query_type,
                    lookup.iter().count()
                );
            }
            LookupControlFlow::Break(Err(_)) => {
                tracing::trace!(
                    "Lookup for name: {}, type: {} error (Break)",
                    name,
                    query_type,
                );
            }
            LookupControlFlow::Skip => {
                tracing::trace!("Lookup for name: {}, type: {} skipped", name, query_type)
            }
        };
        result
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
    #[tracing::instrument(skip_all, fields(query=%request_info.query.query_type()), level="trace")]
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the Secondary or Primary
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            // TODO: support more advanced AXFR options
            if !self.0.is_axfr_allowed() {
                tracing::trace!(
                    "AXFR requested for zone {} but is not permitted",
                    self.0.name()
                );
                return LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)));
            }

            match self.0.zone_type() {
                ZoneType::Primary | ZoneType::Secondary => (),
                _ => {
                    tracing::trace!(
                        "AXFR requested for zone {} but zone is not Primary or Secondary",
                        self.0.name()
                    );
                    return LookupControlFlow::Continue(Err(LookupError::from(
                        ResponseCode::NXDomain,
                    )));
                }
            }
        }

        match record_type {
            RecordType::SOA => {
                tracing::trace!("SOA requested for zone {}", self.0.name());
                Authority::lookup(self, Authority::origin(self), record_type, lookup_options).await
            }
            RecordType::AXFR => {
                tracing::trace!("AXFR requested for zone {}", self.0.name());
                use LookupControlFlow::Continue;
                let start_soa =
                    if let Continue(Ok(res)) = Authority::soa_secure(self, lookup_options).await {
                        res.unwrap_records()
                    } else {
                        LookupRecords::Empty
                    };
                let end_soa = if let Continue(Ok(res)) = Authority::soa(self).await {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };

                let records = if let Continue(Ok(res)) =
                    Authority::lookup(self, lookup_name, record_type, lookup_options).await
                {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };

                LookupControlFlow::Continue(Ok(AuthLookup::AXFR {
                    start_soa,
                    end_soa,
                    records,
                }))
            }
            _ => {
                tracing::trace!("{record_type} requested for zone {}", self.0.name());
                Authority::lookup(self, lookup_name, record_type, lookup_options).await
            }
        }
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
        tracing::trace!("get NSEC recods for non-secure zonze");
        LookupControlFlow::Continue(Ok(AuthLookup::default()))
    }

    /// Return the NSEC3 records based on the information available for a query.
    #[allow(unused_variables)]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        tracing::trace!("get NSEC3 recods for non-secure zonze");
        LookupControlFlow::Continue(Ok(AuthLookup::default()))
    }

    /// Returns the kind of non-existence proof used for this zone.
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        tracing::trace!("get NxProofKind for non-secure zone");
        None
    }
}
