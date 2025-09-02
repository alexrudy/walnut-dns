use hickory_proto::{
    op::ResponseCode,
    rr::{DNSClass, LowerName, RData, RecordType},
};
use hickory_server::authority::{LookupOptions, UpdateResult};
use tracing::warn;

use crate::Lookup;

use super::DnsSecZone;

impl<Z> DnsSecZone<Z>
where
    Z: Lookup,
{
    /// Verify DNS UPDATE prerequisites
    ///
    /// Validates that all prerequisite conditions specified in the UPDATE request
    /// are satisfied by the current state of the zone. This implements RFC 2136
    /// section 3.2 for prerequisite processing.
    ///
    /// Prerequisites can specify:
    /// - Name exists/doesn't exist in the zone
    /// - RRSet exists/doesn't exist
    /// - Specific records exist with exact values
    ///
    /// # Arguments
    ///
    /// * `pre_requisites` - The prerequisite records to verify
    ///
    /// # Returns
    ///
    /// Success if all prerequisites are satisfied
    ///
    /// # Errors
    ///
    /// * `ResponseCode::FormErr` - If prerequisite format is invalid
    /// * `ResponseCode::NotZone` - If record name is not in this zone
    /// * `ResponseCode::NXDomain` - If required name doesn't exist
    /// * `ResponseCode::YXDomain` - If name exists when it shouldn't
    /// * `ResponseCode::NXRRSet` - If required RRSet doesn't exist
    /// * `ResponseCode::YXRRSet` - If RRSet exists when it shouldn't
    ///
    /// # Specification
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.2 - Process Prerequisite Section
    ///
    ///   Next, the Prerequisite Section is checked to see that all
    ///   prerequisites are satisfied by the current state of the zone.  Using
    ///   the definitions expressed in Section 1.2, if any RR's NAME is not
    ///   within the zone specified in the Zone Section, signal NOTZONE to the
    ///   requestor.
    ///
    /// 3.2.1. For RRs in this section whose CLASS is ANY, test to see that
    ///   TTL and RDLENGTH are both zero (0), else signal FORMERR to the
    ///   requestor.  If TYPE is ANY, test to see that there is at least one RR
    ///   in the zone whose NAME is the same as that of the Prerequisite RR,
    ///   else signal NXDOMAIN to the requestor.  If TYPE is not ANY, test to
    ///   see that there is at least one RR in the zone whose NAME and TYPE are
    ///   the same as that of the Prerequisite RR, else signal NXRRSET to the
    ///   requestor.
    ///
    /// 3.2.2. For RRs in this section whose CLASS is NONE, test to see that
    ///   the TTL and RDLENGTH are both zero (0), else signal FORMERR to the
    ///   requestor.  If the TYPE is ANY, test to see that there are no RRs in
    ///   the zone whose NAME is the same as that of the Prerequisite RR, else
    ///   signal YXDOMAIN to the requestor.  If the TYPE is not ANY, test to
    ///   see that there are no RRs in the zone whose NAME and TYPE are the
    ///   same as that of the Prerequisite RR, else signal YXRRSET to the
    ///   requestor.
    ///
    /// 3.2.3. For RRs in this section whose CLASS is the same as the ZCLASS,
    ///   test to see that the TTL is zero (0), else signal FORMERR to the
    ///   requestor.  Then, build an RRset for each unique <NAME,TYPE> and
    ///   compare each resulting RRset for set equality (same members, no more,
    ///   no less) with RRsets in the zone.  If any Prerequisite RRset is not
    ///   entirely and exactly matched by a zone RRset, signal NXRRSET to the
    ///   requestor.  If any RR in this section has a CLASS other than ZCLASS
    ///   or NONE or ANY, signal FORMERR to the requestor.
    ///
    /// 3.2.4 - Table Of Metavalues Used In Prerequisite Section
    ///
    ///   CLASS    TYPE     RDATA    Meaning
    ///   ------------------------------------------------------------
    ///   ANY      ANY      empty    Name is in use
    ///   ANY      rrset    empty    RRset exists (value independent)
    ///   NONE     ANY      empty    Name is not in use
    ///   NONE     rrset    empty    RRset does not exist
    ///   zone     rrset    rr       RRset exists (value dependent)
    /// ```
    pub async fn verify_prerequisites(
        &self,
        pre_requisites: &[hickory_proto::rr::Record],
    ) -> UpdateResult<()> {
        //   3.2.5 - Pseudocode for Prerequisite Section Processing
        //
        //      for rr in prerequisites
        //           if (rr.ttl != 0)
        //                return (FORMERR)
        //           if (zone_of(rr.name) != ZNAME)
        //                return (NOTZONE);
        //           if (rr.class == ANY)
        //                if (rr.rdlength != 0)
        //                     return (FORMERR)
        //                if (rr.type == ANY)
        //                     if (!zone_name<rr.name>)
        //                          return (NXDOMAIN)
        //                else
        //                     if (!zone_rrset<rr.name, rr.type>)
        //                          return (NXRRSET)
        //           if (rr.class == NONE)
        //                if (rr.rdlength != 0)
        //                     return (FORMERR)
        //                if (rr.type == ANY)
        //                     if (zone_name<rr.name>)
        //                          return (YXDOMAIN)
        //                else
        //                     if (zone_rrset<rr.name, rr.type>)
        //                          return (YXRRSET)
        //           if (rr.class == zclass)
        //                temp<rr.name, rr.type> += rr
        //           else
        //                return (FORMERR)
        //
        //      for rrset in temp
        //           if (zone_rrset<rrset.name, rrset.type> != rrset)
        //                return (NXRRSET)
        for require in pre_requisites {
            let required_name = LowerName::from(require.name());

            if require.ttl() != 0 {
                warn!("ttl must be 0 for: {:?}", require);
                return Err(ResponseCode::FormErr);
            }

            let origin = self.origin();
            if !origin.zone_of(&require.name().into()) {
                warn!("{} is not a zone_of {}", require.name(), origin);
                return Err(ResponseCode::NotZone);
            }

            match require.dns_class() {
                DNSClass::ANY => {
                    if let RData::Update0(_) | RData::NULL(..) = require.data() {
                        match require.record_type() {
                            // ANY      ANY      empty    Name is in use
                            RecordType::ANY => {
                                if self
                                    .lookup(
                                        &required_name,
                                        RecordType::ANY,
                                        LookupOptions::default(),
                                    )
                                    .unwrap_or_default()
                                    .was_empty()
                                {
                                    return Err(ResponseCode::NXDomain);
                                } else {
                                    continue;
                                }
                            }
                            // ANY      rrset    empty    RRset exists (value independent)
                            rrset => {
                                if self
                                    .lookup(&required_name, rrset, LookupOptions::default())
                                    .unwrap_or_default()
                                    .was_empty()
                                {
                                    return Err(ResponseCode::NXRRSet);
                                } else {
                                    continue;
                                }
                            }
                        }
                    } else {
                        return Err(ResponseCode::FormErr);
                    }
                }
                DNSClass::NONE => {
                    if let RData::Update0(_) | RData::NULL(..) = require.data() {
                        match require.record_type() {
                            // NONE     ANY      empty    Name is not in use
                            RecordType::ANY => {
                                if !self
                                    .lookup(
                                        &required_name,
                                        RecordType::ANY,
                                        LookupOptions::default(),
                                    )
                                    .unwrap_or_default()
                                    .was_empty()
                                {
                                    return Err(ResponseCode::YXDomain);
                                } else {
                                    continue;
                                }
                            }
                            // NONE     rrset    empty    RRset does not exist
                            rrset => {
                                if !self
                                    .lookup(&required_name, rrset, LookupOptions::default())
                                    .unwrap_or_default()
                                    .was_empty()
                                {
                                    return Err(ResponseCode::YXRRSet);
                                } else {
                                    continue;
                                }
                            }
                        }
                    } else {
                        return Err(ResponseCode::FormErr);
                    }
                }
                class if class == self.dns_class() =>
                // zone     rrset    rr       RRset exists (value dependent)
                {
                    if !self
                        .lookup(
                            &required_name,
                            require.record_type(),
                            LookupOptions::default(),
                        )
                        .unwrap_or_default()
                        .iter()
                        .any(|rr| rr == require)
                    {
                        return Err(ResponseCode::NXRRSet);
                    } else {
                        continue;
                    }
                }
                _ => return Err(ResponseCode::FormErr),
            }
        }

        // if we didn't bail everything checked out...
        Ok(())
    }

    /// Pre-scan DNS UPDATE records for validity
    ///
    /// Validates the format and structure of UPDATE records before processing.
    /// This implements RFC 2136 section 3.4.1 for update section validation.
    ///
    /// The pre-scan verifies:
    /// - All record names are within this zone
    /// - Record classes are valid (zone class, ANY, or NONE)
    /// - TTL values are appropriate for the operation
    /// - Record types are valid for the operation
    ///
    /// # Arguments
    ///
    /// * `records` - The update records to validate
    ///
    /// # Returns
    ///
    /// Success if all records are valid for processing
    ///
    /// # Errors
    ///
    /// * `ResponseCode::FormErr` - If record format is invalid
    /// * `ResponseCode::NotZone` - If record name is not in this zone
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
    /// 3.4.1 - Prescan
    ///
    ///   The Update Section is parsed into RRs and each RR's CLASS is checked
    ///   to see if it is ANY, NONE, or the same as the Zone Class, else signal
    ///   a FORMERR to the requestor.  Using the definitions in Section 1.2,
    ///   each RR's NAME must be in the zone specified by the Zone Section,
    ///   else signal NOTZONE to the requestor.
    ///
    /// 3.4.1.2. For RRs whose CLASS is not ANY, check the TYPE and if it is
    ///   ANY, AXFR, MAILA, MAILB, or any other QUERY metatype, or any
    ///   unrecognized type, then signal FORMERR to the requestor.  For RRs
    ///   whose CLASS is ANY or NONE, check the TTL to see that it is zero (0),
    ///   else signal a FORMERR to the requestor.  For any RR whose CLASS is
    ///   ANY, check the RDLENGTH to make sure that it is zero (0) (that is,
    ///   the RDATA field is empty), and that the TYPE is not AXFR, MAILA,
    ///   MAILB, or any other QUERY metatype besides ANY, or any unrecognized
    ///   type, else signal FORMERR to the requestor.
    /// ```
    #[allow(clippy::unused_unit)]
    pub async fn pre_scan(&self, records: &[hickory_proto::rr::Record]) -> UpdateResult<()> {
        // 3.4.1.3 - Pseudocode For Update Section Prescan
        //
        //      [rr] for rr in updates
        //           if (zone_of(rr.name) != ZNAME)
        //                return (NOTZONE);
        //           if (rr.class == zclass)
        //                if (rr.type & ANY|AXFR|MAILA|MAILB)
        //                     return (FORMERR)
        //           elsif (rr.class == ANY)
        //                if (rr.ttl != 0 || rr.rdlength != 0
        //                    || rr.type & AXFR|MAILA|MAILB)
        //                     return (FORMERR)
        //           elsif (rr.class == NONE)
        //                if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB)
        //                     return (FORMERR)
        //           else
        //                return (FORMERR)
        for rr in records {
            if !self.origin().zone_of(&rr.name().into()) {
                return Err(ResponseCode::NotZone);
            }

            let class: DNSClass = rr.dns_class();
            if class == self.dns_class() {
                match rr.record_type() {
                    RecordType::ANY | RecordType::AXFR | RecordType::IXFR => {
                        return Err(ResponseCode::FormErr);
                    }
                    _ => (),
                }
            } else {
                match class {
                    DNSClass::ANY => {
                        if rr.ttl() != 0 {
                            return Err(ResponseCode::FormErr);
                        }
                        if let RData::Update0(_) | RData::NULL(..) = rr.data() {
                            ()
                        } else {
                            return Err(ResponseCode::FormErr);
                        }
                        match rr.record_type() {
                            RecordType::AXFR | RecordType::IXFR => {
                                return Err(ResponseCode::FormErr);
                            }
                            _ => (),
                        }
                    }
                    DNSClass::NONE => {
                        if rr.ttl() != 0 {
                            return Err(ResponseCode::FormErr);
                        }
                        match rr.record_type() {
                            RecordType::ANY | RecordType::AXFR | RecordType::IXFR => {
                                return Err(ResponseCode::FormErr);
                            }
                            _ => (),
                        }
                    }
                    _ => return Err(ResponseCode::FormErr),
                }
            }
        }

        Ok(())
    }
}
