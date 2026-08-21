use hickory_proto::op::Edns;

use super::lookup::LookupOptions;

pub(crate) fn lookup_options_for_edns(edns: Option<&Edns>) -> LookupOptions {
    edns.map(|edns| LookupOptions::for_dnssec(edns.flags().dnssec_ok))
        .unwrap_or_default()
}
