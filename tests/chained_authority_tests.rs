//! Tests for the catalog's "chained authority" behaviour.
//!
//! walnut-dns no longer uses the `hickory_server::authority::Authority` trait, so these tests are
//! written against the traits in [`walnut_dns::authority`] ([`ZoneInfo`] and [`Lookup`]) and the
//! chateau/tower based [`Catalog`] serving model.
//!
//! The catalog resolves a query by iterating over every authority registered for the matching zone
//! (in order) and asking each one to [`Search::search`] the request:
//!
//! * [`LookupControlFlow::Skip`] tells the catalog to move on to the next authority.
//! * [`LookupControlFlow::Continue`] and [`LookupControlFlow::Break`] both cause the catalog to
//!   build a response from that authority's result and return it immediately.
//! * If every authority skips, the catalog returns `SERVFAIL`.
//!
//! Unlike the old hickory model there is no `consult` step, so a later authority can never overwrite
//! or rescue an earlier authority's answer.

use std::sync::Arc;

use hickory_proto::op::{MessageType, Query, ResponseCode};
use hickory_proto::rr::{LowerName, Name, RData, RecordType, rdata::A};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

mod support;
use support::TestZoneStore;
use support::subscribe;
use walnut_dns::Catalog;
use walnut_dns::authority::{
    Lookup, LookupControlFlow, LookupError, LookupOptions, LookupRecords, ZoneInfo,
};
use walnut_dns::messages::{Message, Protocol, server::Incoming};
use walnut_dns::rr::{Record, RecordSet, SerialNumber, TimeToLive, ZoneType};

/// Tests the catalog's chained-authority resolution.
#[tokio::test]
async fn chained_authority_test() {
    subscribe();
    let catalog: Catalog<TestAuthority> = Catalog::new(TestZoneStore::new());

    let all_zeros = A::new(0, 0, 0, 0);
    let pri_lookup_ip = A::new(192, 0, 2, 1);
    let sec_lookup_ip = A::new(192, 0, 2, 2);

    // Records handled by the primary authority.
    let primary_records = vec![
        // Only the primary knows about this name.
        (
            "primaryonly.example.com.",
            (ResponseType::ContinueOk, pri_lookup_ip),
        ),
        // Both authorities know about this name; the primary is queried first and wins.
        (
            "inboth.example.com.",
            (ResponseType::ContinueOk, pri_lookup_ip),
        ),
        // The primary answers with Break; the response is returned immediately.
        (
            "breakok.example.com.",
            (ResponseType::BreakOk, pri_lookup_ip),
        ),
        // The primary skips, deferring to the secondary authority.
        (
            "skiptosecondary.example.com.",
            (ResponseType::Skip, all_zeros),
        ),
        // Both authorities skip.
        ("skipboth.example.com.", (ResponseType::Skip, all_zeros)),
        // The primary returns Continue(Err); there is no fall-through to the secondary.
        (
            "primaryerr.example.com.",
            (ResponseType::ContinueErr, all_zeros),
        ),
    ];

    // Records handled by the secondary authority.
    let secondary_records = vec![
        (
            "inboth.example.com.",
            (ResponseType::ContinueOk, sec_lookup_ip),
        ),
        (
            "skiptosecondary.example.com.",
            (ResponseType::ContinueOk, sec_lookup_ip),
        ),
        ("skipboth.example.com.", (ResponseType::Skip, all_zeros)),
    ];

    let origin = Name::from_ascii("example.com.").unwrap();

    let primary_authority = TestAuthority::new(origin.clone(), primary_records);
    let secondary_authority = TestAuthority::new(origin.clone(), secondary_records);

    catalog
        .upsert(origin, vec![primary_authority, secondary_authority])
        .await
        .unwrap();

    // The record only exists in the primary authority.
    basic_test(&catalog, "primaryonly.example.com.", pri_lookup_ip).await;

    // The record exists in both authorities; the primary (first) authority answers.
    basic_test(&catalog, "inboth.example.com.", pri_lookup_ip).await;

    // The primary answers with Break(Ok); its record is returned.
    basic_test(&catalog, "breakok.example.com.", pri_lookup_ip).await;

    // The primary skips and the secondary answers.
    basic_test(&catalog, "skiptosecondary.example.com.", sec_lookup_ip).await;

    // Both authorities skip; the catalog returns SERVFAIL.
    error_test(&catalog, "skipboth.example.com.", ResponseCode::ServFail).await;

    // The primary returns Continue(Err(NXDomain)); there is no consult step, so the error is
    // returned to the client rather than falling through to the secondary authority.
    error_test(&catalog, "primaryerr.example.com.", ResponseCode::NXDomain).await;
}

/// A minimal in-memory authority used to exercise the catalog's chaining behaviour.
///
/// It implements walnut-dns's [`ZoneInfo`] and [`Lookup`] traits directly (rather than storing real
/// records) so that each query can return a precise [`LookupControlFlow`] value.
#[derive(Clone)]
struct TestAuthority {
    origin: Name,
    zone_type: ZoneType,
    records: TestRecords,
}

impl TestAuthority {
    fn new(origin: Name, records: TestRecords) -> Self {
        TestAuthority {
            origin,
            zone_type: ZoneType::Primary,
            records,
        }
    }
}

impl ZoneInfo for TestAuthority {
    fn name(&self) -> &Name {
        &self.origin
    }

    fn origin(&self) -> &Name {
        &self.origin
    }

    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn dns_class(&self) -> hickory_proto::rr::DNSClass {
        hickory_proto::rr::DNSClass::IN
    }

    fn serial(&self) -> SerialNumber {
        SerialNumber::ZERO
    }

    fn soa(&self) -> Option<&walnut_dns::rr::Record> {
        None
    }

    fn increment_soa_serial(&mut self) -> SerialNumber {
        SerialNumber::ZERO
    }

    fn minimum_ttl(&self) -> TimeToLive {
        3600.into()
    }
}

#[async_trait::async_trait]
impl Lookup for TestAuthority {
    async fn lookup(
        &self,
        name: &Name,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        // SOA lookups are issued by the catalog while building negative responses (see
        // `soa_secure`). We don't model an SOA record here, so return an empty answer.
        if query_type == RecordType::SOA {
            return LookupControlFlow::Continue(Ok(LookupRecords::default()));
        }

        match inner_lookup(name, &self.records, lookup_options) {
            Some(result) => result,
            None => panic!(
                "unexpected query for {name} ({query_type}) against authority {}",
                self.origin
            ),
        }
    }
}

#[derive(Debug, Clone)]
enum ResponseType {
    ContinueOk,
    BreakOk,
    ContinueErr,
    Skip,
}

/// A lookup table mapping query names to the control-flow response the authority should produce.
///
/// Each entry is a query string paired with a [`ResponseType`] and the `A` record data that should
/// be returned for the `*Ok` variants. The record is used to distinguish which authority produced
/// the answer returned by the catalog.
type TestRecords = Vec<(&'static str, (ResponseType, A))>;

fn inner_lookup(
    name: &Name,
    records: &TestRecords,
    lookup_options: LookupOptions,
) -> Option<LookupControlFlow<LookupRecords>> {
    let ascii_name = LowerName::from(name).to_string();
    tracing::debug!("inner_lookup {ascii_name}");
    for (record_name, (response_type, response_record)) in records.iter() {
        tracing::trace!("inner_lookup check {record_name}");
        if *record_name == ascii_name {
            let mut rset = RecordSet::new(name.clone(), RecordType::A);
            rset.insert(
                Record::from_rdata(name.clone(), 3600.into(), RData::A(*response_record)),
                1.into(),
            )
            .unwrap();

            let lookup = LookupRecords::answers(vec![Arc::new(rset)], Vec::new(), lookup_options);

            use LookupControlFlow::*;
            return Some(match response_type {
                ResponseType::ContinueOk => Continue(Ok(lookup)),
                ResponseType::BreakOk => Break(Ok(lookup)),
                ResponseType::ContinueErr => {
                    Continue(Err(LookupError::ResponseCode(ResponseCode::NXDomain)))
                }
                ResponseType::Skip => LookupControlFlow::Skip,
            });
        }
    }

    None
}

// Boilerplate to query the catalog.
async fn do_query(catalog: &Catalog<TestAuthority>, query_name: &str) -> Message {
    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::from_ascii(query_name).unwrap());
    question.add_query(query);
    question.set_recursion_desired(true);
    question.set_authentic_data(true);

    let question_bytes = question.to_bytes().unwrap();
    let question_req = Message::from_bytes(&question_bytes).unwrap();
    let question_req = Incoming::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);
    catalog.lookup(&question_req, None).await.unwrap()
}

// Handle boilerplate for the most common test case pattern: a positive response with a single A
// record.
async fn basic_test(catalog: &Catalog<TestAuthority>, query_name: &'static str, answer: A) {
    let result = do_query(catalog, query_name).await;

    let answers: &[Record] = result.answers();

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().record_type(), RecordType::A);
    assert_eq!(answers.first().unwrap().data(), &RData::A(answer));
}

async fn error_test(catalog: &Catalog<TestAuthority>, query_name: &str, r_code: ResponseCode) {
    let res = do_query(catalog, query_name).await;

    assert_eq!(res.response_code(), r_code);
    assert!(res.answers().is_empty());
}
