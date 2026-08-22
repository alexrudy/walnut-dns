//! DNS Authority implementation
//!
//! This module provides the core DNS authority functionality for the walnut-dns server.
//! It defines traits and structures for DNS zone management, record lookup, and query
//! processing that integrate with the hickory-dns server framework.
//!
//! # Core Components
//!
//! - [`ZoneInfo`] - Trait providing basic zone metadata and configuration
//! - [`Lookup`] - Trait for DNS record lookup and zone modification operations
//! - [`ZoneAuthority`] - Wrapper providing hickory-dns Authority trait implementation
//! - [`DnsSecZone`] - DNSSEC-enabled zone authority with cryptographic capabilities
//!
//! # Features
//!
//! - Complete DNS query processing with CNAME resolution and wildcard support
//! - AXFR (zone transfer) support for zone replication
//! - DNS UPDATE operations with proper authorization
//! - DNSSEC signing and validation
//! - Flexible zone storage backends through trait abstraction
//! - Integration with hickory-dns server framework

use std::borrow::Borrow;
use std::collections::HashSet;
use std::ops::RangeBounds;
use std::sync::Arc;

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType, RrKey};

use crate::messages::Message;
use crate::messages::server::Incoming;
use walnut_proto::rr::{Mismatch, Record, RecordSet, SerialNumber, TimeToLive, Zone, ZoneType};

pub mod dnssec;
pub(crate) mod edns;
pub(crate) mod error;
pub(crate) mod lookup;
pub(crate) mod zone;

pub use self::dnssec::Nsec3QueryInfo;
pub use self::dnssec::NxProofKind;
pub use self::dnssec::{DnsSecZone, DnsSecZoneError, Journal};
pub use self::error::LookupError;
pub use self::lookup::{LookupControlFlow, LookupOptions, LookupRecords};

pub(crate) type LookupChain<L, E = LookupError> =
    (LookupControlFlow<L, E>, Option<Vec<Arc<RecordSet>>>);

/// Provides basic information about a DNS Zone that can be used for lookups
///
/// This trait defines the essential metadata and properties of a DNS zone
/// that are required for DNS query processing and zone management operations.
/// It provides access to zone configuration, SOA records, and administrative
/// settings without exposing the internal zone data structure.
pub trait ZoneInfo {
    /// Get the zone name
    ///
    /// Returns the full domain name of this DNS zone.
    ///
    /// # Returns
    ///
    /// The zone's domain name
    fn name(&self) -> &Name;

    /// Get the zone origin name in lowercase
    ///
    /// Returns the zone origin as a Name, which is used for efficient
    /// DNS name comparisons and lookups.
    ///
    /// # Returns
    ///
    /// The zone's origin name in lowercase format
    fn origin(&self) -> &Name;

    /// Get the zone type
    ///
    /// Returns the type of this zone (Primary, Secondary, etc.) which
    /// determines how the zone behaves and what operations are allowed.
    ///
    /// # Returns
    ///
    /// The zone type (Primary, Secondary, Forward, etc.)
    fn zone_type(&self) -> ZoneType;

    /// Check if AXFR (zone transfer) is allowed
    ///
    /// Returns whether this zone permits AXFR requests, which allow
    /// clients to download the entire zone contents.
    ///
    /// # Returns
    ///
    /// `true` if AXFR is permitted, `false` otherwise
    fn is_axfr_allowed(&self) -> bool;

    /// Get the DNS class for this zone
    ///
    /// Returns the DNS class (typically IN for Internet) that this
    /// zone belongs to.
    ///
    /// # Returns
    ///
    /// The DNS class for this zone
    fn dns_class(&self) -> DNSClass;

    /// Get the current SOA serial number
    ///
    /// Returns the serial number from the zone's SOA record, which
    /// is used for change tracking and replication.
    ///
    /// # Returns
    ///
    /// The current SOA serial number
    fn serial(&self) -> SerialNumber;

    /// Get the SOA record for this zone
    ///
    /// Returns the Start of Authority record that contains essential
    /// zone metadata like serial number, refresh intervals, and
    /// responsible party information.
    ///
    /// # Returns
    ///
    /// The SOA record if present, None otherwise
    fn soa(&self) -> Option<&Record>;

    /// Increment the SOA serial number
    ///
    /// Increases the SOA serial number to indicate that the zone
    /// has been modified. This is essential for proper DNS replication
    /// and caching behavior.
    ///
    /// # Returns
    ///
    /// The new serial number after incrementing
    fn increment_soa_serial(&mut self) -> SerialNumber;

    /// Get the minimum TTL for this zone
    ///
    /// Returns the minimum time-to-live value that should be used
    /// for negative caching and other DNS operations in this zone.
    ///
    /// # Returns
    ///
    /// The minimum TTL value
    fn minimum_ttl(&self) -> TimeToLive;
}

pub trait Records {
    /// Get a record set by its key
    ///
    /// Retrieves a record set matching the specified name and type.
    ///
    /// # Arguments
    ///
    /// * `key` - The record key (name + type) to look up
    ///
    /// # Returns
    ///
    /// The record set if found, None otherwise
    fn get(&self, key: &RrKey) -> Option<&RecordSet>;

    /// Get a mutable reference to a record set by its key
    ///
    /// Retrieves a mutable record set matching the specified name and type,
    /// allowing for modifications to the record set.
    ///
    /// # Arguments
    ///
    /// * `key` - The record key (name + type) to look up
    ///
    /// # Returns
    ///
    /// A mutable reference to the record set if found, None otherwise
    fn get_mut(&mut self, key: &RrKey) -> Option<&mut RecordSet>;

    /// Get an iterator over all record keys in the zone
    ///
    /// Returns an iterator that yields all record keys (name + type pairs)
    /// stored in this zone.
    ///
    /// # Returns
    ///
    /// An iterator over record keys
    fn keys(&self) -> impl Iterator<Item = &RrKey>;

    /// Get an iterator over all record sets in the zone
    ///
    /// Returns an iterator that yields all record sets stored in this zone.
    ///
    /// # Returns
    ///
    /// An iterator over record sets
    fn records(&self) -> impl Iterator<Item = &RecordSet>;

    /// Get a reverse iterator over all record sets in the zone
    ///
    /// Returns a reverse iterator that yields all record sets stored in this zone,
    /// useful for AXFR operations that require specific ordering.
    ///
    /// # Returns
    ///
    /// A reverse iterator over record sets
    fn records_reversed(&self) -> impl Iterator<Item = &RecordSet>;

    /// Get a mutable iterator over all record sets in the zone
    ///
    /// Returns a mutable iterator that yields all record sets stored in this zone,
    /// allowing for batch modifications.
    ///
    /// # Returns
    ///
    /// A mutable iterator over record sets
    fn records_mut(&mut self) -> impl Iterator<Item = &mut RecordSet>;

    /// Insert or update a record in the zone
    ///
    /// Adds a new record to the zone or updates an existing record set.
    /// The operation respects DNS semantics for record replacement and
    /// CNAME exclusivity rules.
    ///
    /// # Arguments
    ///
    /// * `record` - The record to insert or update
    /// * `serial` - The serial number for this update operation
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the record was modified, `Ok(false)` if no change was made
    ///
    /// # Errors
    ///
    /// Returns `Mismatch` if the record conflicts with existing records
    /// (e.g., CNAME with other record types)
    fn upsert(&mut self, record: Record, serial: SerialNumber) -> Result<bool, Mismatch>;

    /// Remove a record set from the zone
    ///
    /// Removes all records matching the specified name and type.
    ///
    /// # Arguments
    ///
    /// * `key` - The record key (name + type) to remove
    ///
    /// # Returns
    ///
    /// The removed record set if it existed, None otherwise
    fn remove(&mut self, key: &RrKey) -> Option<RecordSet>;

    /// Replace a record set with a new one, returning the previous one if found.
    ///
    /// If the new record set has the same name and type as an existing record set,
    /// the existing record set is replaced with the new one and returned.
    /// If no matching record set is found, the new record set is inserted and None is returned.
    ///
    /// # Arguments
    ///
    /// * `rrset` - The new record set to replace the existing one
    ///
    /// # Returns
    ///
    /// The previous record set if it existed, None otherwise
    fn replace(&mut self, rrset: RecordSet) -> Option<RecordSet>;

    /// Get records within a specified range
    ///
    /// Returns an iterator over record keys and sets that fall within
    /// the specified range, useful for efficient range queries.
    ///
    /// # Arguments
    ///
    /// * `range` - The range bounds to search within
    ///
    /// # Returns
    ///
    /// An iterator over (key, record set) pairs within the range
    fn range<T, R>(&self, range: R) -> impl Iterator<Item = (&RrKey, &RecordSet)>
    where
        T: Ord + ?Sized,
        RrKey: Borrow<T> + Ord,
        R: RangeBounds<T>;
}

/// Provides DNS record lookup and modification capabilities for a zone
///
/// This trait extends ZoneInfo to provide the core functionality needed for
/// DNS query processing and zone updates. It defines methods for retrieving,
/// modifying, and managing DNS records within a zone.
///
/// The trait supports:
/// - Direct record access by name and type
/// - Record iteration and traversal
/// - Record insertion and deletion
/// - DNS query processing with CNAME resolution and wildcard support
#[async_trait::async_trait]
pub trait Lookup: ZoneInfo {
    /// Perform a DNS lookup against this zone
    ///
    /// Processes a DNS query by searching for matching records, handling
    /// CNAME resolution, wildcard expansion, and additional record lookup.
    /// This is the main entry point for DNS query processing.
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to look up
    /// * `query_type` - The record type to search for
    /// * `lookup_options` - Query options (DNSSEC, recursion, etc.)
    ///
    /// # Returns
    ///
    /// A lookup control flow indicating how the query should be processed
    async fn lookup(
        &self,
        name: &Name,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords>;

    /// Returns the SOA record for the zone
    async fn soa_secure(&self, lookup_options: LookupOptions) -> LookupControlFlow<LookupRecords> {
        self.lookup(self.origin(), RecordType::SOA, lookup_options)
            .await
    }

    /// Get the NS, NameServer, record for the zone
    async fn ns(&self, lookup_options: LookupOptions) -> LookupControlFlow<LookupRecords> {
        self.lookup(self.origin(), RecordType::NS, lookup_options)
            .await
    }
}

#[async_trait::async_trait]
impl<A> Lookup for A
where
    A: Records + ZoneInfo + Sync + 'static,
{
    async fn lookup(
        &self,
        name: &Name,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        let lz = LookupZone(self);
        lz.lookup(name, query_type, lookup_options).await
    }
}

#[async_trait::async_trait]
pub trait Search: Lookup + Sync {
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
    #[tracing::instrument(skip_all, fields(query=%query.query_type()), level="trace")]
    async fn search(
        &self,
        query: &Query,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        let lookup_name = query.name();
        let record_type: RecordType = query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the Secondary or Primary
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            // TODO: support more advanced AXFR options
            if !self.is_axfr_allowed() {
                tracing::trace!(
                    "AXFR requested for zone {} but is not permitted",
                    self.name()
                );
                return LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)));
            }

            match self.zone_type() {
                ZoneType::Primary | ZoneType::Secondary => (),
                _ => {
                    tracing::trace!(
                        "AXFR requested for zone {} but zone is not Primary or Secondary",
                        self.name()
                    );
                    return LookupControlFlow::Continue(Err(LookupError::from(
                        ResponseCode::NXDomain,
                    )));
                }
            }
        }

        match record_type {
            RecordType::SOA => {
                tracing::trace!("SOA requested for zone {}", self.name());
                Lookup::lookup(self, ZoneInfo::origin(self), record_type, lookup_options).await
            }
            RecordType::AXFR => {
                tracing::trace!("AXFR requested for zone {}", self.name());
                use LookupControlFlow::Continue;
                let soa = if let Continue(Ok(res)) =
                    Lookup::soa_secure(self, lookup_options.clone()).await
                {
                    res.unwrap_record()
                } else {
                    None
                };

                let records = if let Continue(Ok(res)) =
                    Lookup::lookup(self, lookup_name, record_type, lookup_options.clone()).await
                {
                    res.unwrap_records()
                } else {
                    None
                };

                LookupControlFlow::Continue(Ok(LookupRecords::axfr(
                    soa.unwrap_or_else(|| {
                        Arc::new(RecordSet::new(self.name().clone(), RecordType::SOA))
                    }),
                    records.unwrap_or_default(),
                    lookup_options,
                )))
            }
            _ => {
                tracing::trace!(lookup=%lookup_name, "{record_type} requested for zone {}", self.name());
                Lookup::lookup(self, lookup_name, record_type, lookup_options).await
            }
        }
    }
}

impl<A> Search for A where A: Lookup + Sync {}

#[async_trait::async_trait]
pub trait Update: ZoneInfo {
    /// Takes the UpdateMessage, extracts the Records, and applies the changes to the record set.
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
    ///
    /// # Specification
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
    async fn update(&mut self, _update: &Incoming<Message>) -> Result<bool, ResponseCode>;

    async fn get_nsec_records(
        &self,
        name: &Name,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords>;

    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords>;

    fn nx_proof_kind(&self) -> Option<&NxProofKind>;
}

#[async_trait::async_trait]
impl Update for Zone {
    async fn update(&mut self, _update: &Incoming<Message>) -> Result<bool, ResponseCode> {
        // No update for non-DNSSEC Zone
        if ZoneInfo::is_axfr_allowed(self) {
            tracing::warn!(origin=%ZoneInfo::origin(self), "No update for non-DNSSEC Zone");
        }
        Err(ResponseCode::NotImp)
    }

    #[expect(unused_variables)]
    async fn get_nsec_records(
        &self,
        name: &Name,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        LookupControlFlow::Continue(Ok(LookupRecords::empty()))
    }

    #[expect(unused_variables)]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        LookupControlFlow::Continue(Ok(LookupRecords::empty()))
    }

    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

struct LookupZone<'z, Z: ?Sized>(&'z Z);

impl<'z, Z> LookupZone<'z, Z>
where
    Z: Lookup + Records + ZoneInfo + Sync + ?Sized,
{
    #[tracing::instrument(level = "trace", skip_all, fields(query=%query_type))]
    async fn lookup(
        &self,
        name: &Name,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        let (result, additionals) = if matches!(query_type, RecordType::AXFR | RecordType::ANY) {
            self.lookup_any(name, query_type, lookup_options).await
        } else {
            let answer = self.lookup_records(name, query_type, lookup_options.clone());
            if let Some(rrset) = &answer {
                tracing::trace!(record=%rrset.record_type(), "Found {} records", rrset.len());
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
                        lookup_options.clone(),
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
                                    .records(false)
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
                    LookupControlFlow::Continue(Ok(LookupRecords::records(
                        vec![Arc::new(rr_set)],
                        lookup_options,
                    )))
                },
            );

            let additionals = additionals.map(|a| {
                tracing::trace!("Adding {} alternate lookup records", a.len());
                a.into_iter().map(Arc::new).collect()
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
                    .any(|key| (key.name() as &Name) == name || name.zone_of(key.name()))
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

        result.map(|mut answers| {
            tracing::trace!(%name, "found {} records ({} additionals)", answers.len(), additionals.as_ref().map_or(0, |addl| addl.len()));
            answers.set_additionals(additionals.unwrap_or_default());
            answers
        })
    }

    /// Perform an AXFR or ANY record lookup, returning all available records for this zone.
    async fn lookup_any(
        &self,
        name: &Name,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupChain<LookupRecords> {
        debug_assert!(matches!(query_type, RecordType::AXFR | RecordType::ANY));

        let records: Vec<Arc<RecordSet>> = self
            .0
            .records()
            .map(|rset| Arc::new(rset.clone()))
            .collect();
        tracing::trace!("Lookup AXFR|ANY {} records", records.len());

        let cf = match query_type {
            RecordType::AXFR => {
                let soa = if let LookupControlFlow::Continue(Ok(res)) =
                    Lookup::soa_secure(self.0, lookup_options.clone()).await
                {
                    res.unwrap_record()
                } else {
                    None
                };
                //TODO: Proper error handling for missing SOA records

                LookupControlFlow::Continue(Ok(LookupRecords::axfr(
                    soa.expect("SOA Record available in zone"),
                    records,
                    lookup_options,
                )))
            }
            RecordType::ANY => LookupControlFlow::Continue(Ok(LookupRecords::any(
                records,
                name.clone(),
                lookup_options,
            ))),
            _ => panic!("Lookup {query_type} on lookup_any arm"),
        };
        (cf, None)
    }

    /// Perform a direct lookup for a set of records matching the query type
    fn lookup_records(
        &self,
        name: &Name,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<RecordSet> {
        self.lookup_record(name, query_type, lookup_options.clone())
            .cloned()
            .or_else(|| {
                tracing::trace!("No direct record found");
                self.lookup_wildcard(name, query_type, lookup_options)
            })
    }

    #[tracing::instrument("lookup_record", skip_all, fields(name=%name, query=%query_type), level = "trace")]
    fn lookup_record(
        &self,
        name: &Name,
        query_type: RecordType,
        _lookup_options: LookupOptions,
    ) -> Option<&RecordSet> {
        tracing::trace!("Lookup {name} {query_type}");
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(Name::new(name), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(Name::new(name), RecordType::Unknown(u16::MAX));

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        {
            self.0
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .find(|(key, _)| {
                key.record_type == query_type
                    || key.record_type == RecordType::CNAME
                    || aname_covers_type(key.record_type, query_type)
            })
            .map(|(_key, rr_set)| rr_set)
            .inspect(
                |rr_set| tracing::trace!(record=%rr_set.record_type(), "Found {} records", rr_set.len()),
            )
        }
    }

    #[tracing::instrument("wildcard", skip_all, level = "trace")]
    fn lookup_wildcard(
        &self,
        name: &Name,
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
            let Some(rrset) = self.lookup_record(&wildcard, query_type, lookup_options.clone())
            else {
                let parent = wildcard.base_name();
                if parent.is_root() {
                    tracing::trace!("No wildcard records found");
                    return None;
                }

                wildcard = parent.into_wildcard();
                continue;
            };

            // we need to change the name to the query name in the result set since this was a wildcard
            let new_answer = rrset.with_name(name.clone());

            //TODO This needs to be signed.
            tracing::warn!("New answer created, need to re-sign it if DNSSEC is enabled");

            return Some(new_answer);
        }
    }

    #[tracing::instrument("additional_search", skip_all, fields(name=%original_name, query=%original_query_type), level = "trace")]
    fn additional_search(
        &self,
        original_name: &Name,
        original_query_type: RecordType,
        next_name: Name,
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

                let additional = self.lookup_records(&search, *query_type, lookup_options.clone());
                names.insert(search);

                if let Some(additional) = additional {
                    // assuming no crazy long chains...
                    if !additionals.contains(&additional) {
                        tracing::trace!(record=%additional.record_type(), n=additional.len(), "Adding additional records");
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
