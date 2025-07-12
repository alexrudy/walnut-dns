use std::sync::Once;

use hickory_proto::rr::{IntoName as _, rdata};
use walnut_dns::authority::ZoneCatalog;
use walnut_dns::rr::{Name, Record, Zone};
use walnut_dns::{database::SqliteCatalog, rr::ZoneType};

/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
pub fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

fn soa(primary: Name, email: Name) -> rdata::SOA {
    rdata::SOA::new(primary.into(), email.into(), 0, 60, 60, 60, 60)
}

fn into_email(email: &str) -> Name {
    email.replace('@', ".").into_name().unwrap().into()
}

#[test]
fn persistence() {
    subscribe();
    let catalog = SqliteCatalog::new_in_memory().unwrap();

    let primary = "example.com".into_name().unwrap();
    let email = into_email("admin@example.com");

    let zone = Zone::empty(
        primary.clone().into(),
        Record::from_rdata(
            primary.clone().into(),
            60.into(),
            soa(primary.clone().into(), email.clone()),
        ),
        ZoneType::Primary,
        false,
    );

    catalog.upsert(zone).unwrap();

    let zone = catalog
        .find(&hickory_proto::rr::LowerName::from(Name::from(primary)))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(zone.records().count(), 1);
}
