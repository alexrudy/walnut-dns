use hickory_proto::{
    dnssec::{Verifier as _, rdata::DNSSECRData},
    op::ResponseCode,
    rr::{LowerName, RecordType},
};
use hickory_server::authority::{LookupControlFlow, LookupOptions, MessageRequest, UpdateResult};
use tracing::{info, warn};

use crate::Lookup;

use super::DnsSecZone;

impl<Z> DnsSecZone<Z>
where
    Z: Lookup,
{
    /// Authorize a DNS UPDATE request using cryptographic authentication
    ///
    /// Verifies that the UPDATE request is properly authenticated using SIG(0)
    /// signatures. The signature must be created with a key that exists in the zone
    /// as a KEY record.
    ///
    /// This implements RFC 2136 section 3.3 for authentication of UPDATE requests.
    ///
    /// # Arguments
    ///
    /// * `update_message` - The DNS UPDATE message to authorize
    ///
    ///  # Returns
    ///
    /// Success if the request is authorized, or a response code indicating failure
    ///
    /// # Errors
    ///
    /// * `ResponseCode::Refused` - If updates are not allowed or authentication fails
    /// * `ResponseCode::FormErr` - If the request format is invalid
    ///
    /// # Security
    ///
    /// This method performs cryptographic signature verification to ensure that
    ///  only authorized parties can modify the zone.
    ///
    /// # Specification
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.3 - Check Requestor's Permissions
    ///
    /// 3.3.1. Next, the requestor's permission to update the RRs named in
    ///   the Update Section may be tested in an implementation dependent
    ///   fashion or using mechanisms specified in a subsequent Secure DNS
    ///   Update protocol.  If the requestor does not have permission to
    ///   perform these updates, the server may write a warning message in its
    ///   operations log, and may either signal REFUSED to the requestor, or
    ///   ignore the permission problem and proceed with the update.
    ///
    /// 3.3.2. While the exact processing is implementation defined, if these
    ///   verification activities are to be performed, this is the point in the
    ///   server's processing where such performance should take place, since
    ///   if a REFUSED condition is encountered after an update has been
    ///   partially applied, it will be necessary to undo the partial update
    ///   and restore the zone to its original state before answering the
    ///   requestor.
    /// ```
    ///
    pub async fn authorize(&self, update_message: &MessageRequest) -> UpdateResult<()> {
        use tracing::debug;

        // 3.3.3 - Pseudocode for Permission Checking
        //
        //      if (security policy exists)
        //           if (this update is not permitted)
        //                if (local option)
        //                     log a message about permission problem
        //                if (local option)
        //                     return (REFUSED)

        // does this authority allow_updates?
        if !self.allow_update {
            warn!(
                "update attempted on non-updatable Authority: {}",
                self.origin()
            );
            return Err(ResponseCode::Refused);
        }

        // verify sig0, currently the only authorization that is accepted.
        let sig0s: &[hickory_proto::rr::Record] = update_message.sig0();
        debug!("authorizing with: {:?}", sig0s);
        if !sig0s.is_empty() {
            let mut found_key = false;
            for sig in sig0s
                .iter()
                .filter_map(|sig0| sig0.data().as_dnssec().and_then(DNSSECRData::as_sig))
            {
                let name = LowerName::from(sig.signer_name());
                let keys = self.lookup(&name, RecordType::KEY, LookupOptions::default());

                let keys = match keys {
                    LookupControlFlow::Continue(Ok(keys)) => keys,
                    _ => continue, // error trying to lookup a key by that name, try the next one.
                };

                debug!("found keys {:?}", keys);
                // TODO: check key usage flags and restrictions
                found_key = keys
                    .iter()
                    .filter_map(|rr_set| rr_set.data().as_dnssec().and_then(DNSSECRData::as_key))
                    .any(|key| {
                        key.verify_message(update_message, sig.sig(), sig)
                            .map(|_| {
                                info!("verified sig: {:?} with key: {:?}", sig, key);
                                true
                            })
                            .unwrap_or_else(|_| {
                                debug!("did not verify sig: {:?} with key: {:?}", sig, key);
                                false
                            })
                    });

                if found_key {
                    break; // stop searching for matching keys, we found one
                }
            }

            if found_key {
                return Ok(());
            }
        } else {
            warn!(
                "no sig0 matched registered records: id {}",
                update_message.id()
            );
        }

        // getting here, we will always default to rejecting the request
        //  the code will only ever explicitly return authorized actions.
        Err(ResponseCode::Refused)
    }
}
