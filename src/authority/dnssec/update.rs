use hickory_proto::{
    op::ResponseCode,
    rr::{DNSClass, LowerName, RData, Record, RecordType, RrKey},
};
use hickory_server::authority::UpdateResult;
use tracing::{error, info};

use crate::Lookup;

use super::DNSSecZone;

impl<Z> DNSSecZone<Z>
where
    Z: Lookup,
{
    /// Updates the specified records according to the update section.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.4.2.6 - Table Of Metavalues Used In Update Section
    ///
    ///   CLASS    TYPE     RDATA    Meaning
    ///   ---------------------------------------------------------
    ///   ANY      ANY      empty    Delete all RRsets from a name
    ///   ANY      rrset    empty    Delete an RRset
    ///   NONE     rrset    rr       Delete an RR from an RRset
    ///   zone     rrset    rr       Add to an RRset
    /// ```
    ///
    /// # Arguments
    ///
    /// * `records` - set of record instructions for update following above rules
    /// * `auto_signing_and_increment` - if true, the zone will sign and increment the SOA, this
    ///   should be disabled during recovery.
    pub async fn update_records(
        &mut self,
        records: &[Record],
        auto_signing_and_increment: bool,
    ) -> UpdateResult<bool> {
        let mut updated = false;
        let serial = self.serial();

        // the persistence act as a write-ahead log. The WAL will also be used for recovery of a zone
        //  subsequent to a failure of the server.
        if let Some(journal) = self.journal.as_ref() {
            let records = records.iter().cloned().map(Into::into).collect::<Vec<_>>();
            if let Err(error) = journal.insert_records(self, &records) {
                error!("could not persist update records: {}", error);
                return Err(ResponseCode::ServFail);
            }
        }

        // 3.4.2.7 - Pseudocode For Update Section Processing
        //
        //      [rr] for rr in updates
        //           if (rr.class == zclass)
        //                if (rr.type == CNAME)
        //                     if (zone_rrset<rr.name, ~CNAME>)
        //                          next [rr]
        //                elsif (zone_rrset<rr.name, CNAME>)
        //                     next [rr]
        //                if (rr.type == SOA)
        //                     if (!zone_rrset<rr.name, SOA> ||
        //                         zone_rr<rr.name, SOA>.serial > rr.soa.serial)
        //                          next [rr]
        //                for zrr in zone_rrset<rr.name, rr.type>
        //                     if (rr.type == CNAME || rr.type == SOA ||
        //                         (rr.type == WKS && rr.proto == zrr.proto &&
        //                          rr.address == zrr.address) ||
        //                         rr.rdata == zrr.rdata)
        //                          zrr = rr
        //                          next [rr]
        //                zone_rrset<rr.name, rr.type> += rr
        //           elsif (rr.class == ANY)
        //                if (rr.type == ANY)
        //                     if (rr.name == zname)
        //                          zone_rrset<rr.name, ~(SOA|NS)> = Nil
        //                     else
        //                          zone_rrset<rr.name, *> = Nil
        //                elsif (rr.name == zname &&
        //                       (rr.type == SOA || rr.type == NS))
        //                     next [rr]
        //                else
        //                     zone_rrset<rr.name, rr.type> = Nil
        //           elsif (rr.class == NONE)
        //                if (rr.type == SOA)
        //                     next [rr]
        //                if (rr.type == NS && zone_rrset<rr.name, NS> == rr)
        //                     next [rr]
        //                zone_rr<rr.name, rr.type, rr.data> = Nil
        //      return (NOERROR)
        for rr in records {
            let rr_name = LowerName::from(rr.name());
            let rr_key = RrKey::new(rr_name.clone(), rr.record_type());

            match rr.dns_class() {
                class if class == self.dns_class() => {
                    // RFC 2136 - 3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
                    //  the zone.  In case of duplicate RDATAs (which for SOA RRs is always
                    //  the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
                    //  fields both match), the Zone RR is replaced by Update RR.  If the
                    //  TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
                    //  lower (according to [RFC1982]) than or equal to the current Zone SOA
                    //  RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
                    //  Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
                    //  Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
                    //  RR.

                    // zone     rrset    rr       Add to an RRset
                    info!("upserting record: {:?}", rr);
                    let upserted = self.upsert(rr.clone().into(), serial).unwrap();

                    updated = upserted || updated
                }
                DNSClass::ANY => {
                    // This is a delete of entire RRSETs, either many or one. In either case, the spec is clear:
                    match rr.record_type() {
                        t @ RecordType::SOA | t @ RecordType::NS if rr_name == *self.origin() => {
                            // SOA and NS records are not to be deleted if they are the origin records
                            info!("skipping delete of {:?} see RFC 2136 - 3.4.2.3", t);
                            continue;
                        }
                        RecordType::ANY => {
                            // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
                            //   all Zone RRs with the same NAME are deleted, unless the NAME is the
                            //   same as ZNAME in which case only those RRs whose TYPE is other than
                            //   SOA or NS are deleted.

                            // ANY      ANY      empty    Delete all RRsets from a name
                            info!(
                                "deleting all records at name (not SOA or NS at origin): {:?}",
                                rr_name
                            );
                            let origin = self.origin();
                            let to_delete = self
                                .keys()
                                .filter(|k| {
                                    !((k.record_type == RecordType::SOA
                                        || k.record_type == RecordType::NS)
                                        && k.name != *origin)
                                })
                                .filter(|k| k.name == rr_name)
                                .cloned()
                                .collect::<Vec<RrKey>>();

                            for delete in to_delete {
                                self.remove(&delete);
                                updated = true;
                            }
                        }
                        _ => {
                            // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and
                            //   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
                            //   deleted, unless the NAME is the same as ZNAME in which case neither
                            //   SOA or NS RRs will be deleted.

                            // ANY      rrset    empty    Delete an RRset
                            if let RData::Update0(_) | RData::NULL(..) = rr.data() {
                                let deleted = self.remove(&rr_key);
                                info!("deleted rrset: {:?}", deleted);
                                updated = updated || deleted.is_some();
                            } else {
                                info!("expected empty rdata: {:?}", rr);
                                return Err(ResponseCode::FormErr);
                            }
                        }
                    }
                }
                DNSClass::NONE => {
                    info!("deleting specific record: {:?}", rr);
                    // NONE     rrset    rr       Delete an RR from an RRset
                    if let Some(rrset) = self.get_mut(&rr_key) {
                        // b/c this is an Arc, we need to clone, then remove, and replace the node.
                        let rr = rr.clone().into();
                        let deleted = rrset.remove(&rr, serial).unwrap();
                        info!("deleted ({}) specific record: {:?}", deleted, rr);
                        updated = updated || deleted;
                    }
                }
                class => {
                    info!("unexpected DNS Class: {:?}", class);
                    return Err(ResponseCode::FormErr);
                }
            }
        }

        // update the serial...
        if updated && auto_signing_and_increment {
            if self.is_dnssec_enabled {
                self.secure_zone().map_err(|e| {
                    error!("failure securing zone: {}", e);
                    ResponseCode::ServFail
                })?
            } else {
                // the secure_zone() function increments the SOA during it's operation, if we're not
                //  dnssec, then we need to do it here...
                self.increment_soa_serial();
            }
        }

        if let Some(journal) = self.journal.as_ref() {
            if let Err(error) = journal.upsert_zone(self) {
                error!("could not persist updated zone: {}", error);
                return Err(ResponseCode::ServFail);
            }
        }

        Ok(updated)
    }
}
