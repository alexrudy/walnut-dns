use hickory_proto::op::Edns;
use hickory_server::{authority::LookupOptions, server::ResponseInfo};

#[derive(Debug)]
pub(super) enum EdnsResponse {
    None,
    Response(Edns),
    Sent(ResponseInfo),
}

pub(super) fn lookup_options_for_edns(edns: Option<&Edns>) -> LookupOptions {
    edns.map(|edns| LookupOptions::for_dnssec(edns.flags().dnssec_ok))
        .unwrap_or_default()
}
