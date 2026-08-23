use chrono::{DateTime, Utc};
use tracing::{debug, warn};
use walnut_proto::{
    op::{Message, ResponseCode},
    rr::{
        rdata::{TSIG, tsig::TsigError},
        tsig::TSigResponseContext,
    },
};

use crate::{
    Lookup,
    messages::server::{Decoded, UpdateRequest as _},
};
use walnut_proto::rr::Record;

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
    pub async fn authorize(
        &self,
        update_message: &Decoded<Message>,
        now: DateTime<Utc>,
    ) -> (Result<(), ResponseCode>, Option<TSigResponseContext>) {
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
            return (Err(ResponseCode::Refused), None);
        }

        match update_message.signature() {
            Some(tsig) => {
                let (resp, signer) = self.authorized_tsig(tsig, update_message, now).await;
                (resp, Some(signer))
            }
            None => (Err(ResponseCode::Refused), None),
        }
        // getting here, we will always default to rejecting the request
        //  the code will only ever explicitly return authorized actions.
    }

    async fn authorized_tsig(
        &self,
        tsig: &Record<TSIG>,
        request: &Decoded<Message>,
        now: DateTime<Utc>,
    ) -> (Result<(), ResponseCode>, TSigResponseContext) {
        let req_id = request.id();

        debug!("authorizing with: {tsig:?}");
        // RFC 8945 Section 5.5: "To prevent cross-algorithm attacks, there SHOULD only be
        // one algorithm associated with any given key name." We rely on this and only check
        // the key name when filtering TSIG keys.
        let Some(tsigner) = self
            .tsig_signers
            .iter()
            .find(|tsigner| tsigner.signer_name() == tsig.name())
        else {
            warn!("no TSIG key name matched: id {req_id}");
            return (
                Err(ResponseCode::NotAuth),
                TSigResponseContext::unknown_key(
                    req_id,
                    now.timestamp() as u64,
                    tsig.name().clone(),
                ),
            );
        };

        let Ok((_, _, range)) = tsigner.verify_message_byte(request.raw(), None, true) else {
            warn!("invalid TSIG signature: id {req_id}");
            return (
                Err(ResponseCode::NotAuth),
                TSigResponseContext::bad_signature(req_id, now.timestamp() as u64, tsigner.clone()),
            );
        };

        let mut error = None;
        let mut response = Ok(());

        if !range.contains(&(now.timestamp() as u64)) {
            warn!("expired TSIG signature: id {req_id}");
            // "A response indicating a BADTIME error MUST be signed by the same key as the request."
            response = Err(ResponseCode::NotAuth);
            error = Some(TsigError::BadTime);
        }

        (
            response,
            TSigResponseContext::new(
                req_id,
                now.timestamp() as u64,
                tsigner.clone(),
                tsig.rdata.mac.clone(),
                error,
            ),
        )
    }
}
