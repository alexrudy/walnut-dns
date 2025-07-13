use hickory_proto::rr::rdata;
use walnut_dns::ZoneInfo as _;
use walnut_dns::catalog::CatalogStore;
use walnut_dns::rr::{LowerName, Name, NameExt, Record, Zone};
use walnut_dns::{database::SqliteStore, rr::ZoneType};

mod support;
use support::subscribe;

fn soa(primary: Name, email: Name) -> rdata::SOA {
    rdata::SOA::new(primary, email, 0, 60, 60, 60, 60)
}

fn example_zone(name: &str) -> Zone {
    let origin: Name = name.parse().unwrap();
    let email = Name::parse_soa_email(format!("admin@{name}")).unwrap();

    Zone::empty(
        origin.clone(),
        Record::from_rdata(
            origin.clone(),
            60.into(),
            soa(origin.clone(), email.clone()),
        ),
        ZoneType::Primary,
        false,
    )
}

#[tokio::test]
async fn upsert_one() {
    subscribe();
    let catalog = SqliteStore::new_in_memory().unwrap();

    let example = example_zone("example.com.");

    catalog
        .upsert(example.origin().clone(), &vec![example.into()])
        .await
        .unwrap();

    let zone = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(zone.records().count(), 1);
}

#[tokio::test]
async fn upsert_multiple() {
    subscribe();
    let catalog = SqliteStore::new_in_memory().unwrap();

    let example1 = example_zone("example.com.");
    let example2 = example_zone("example.com.");
    let example3 = example_zone("example.com.");

    catalog
        .upsert(
            example1.origin().clone(),
            &vec![example1.into(), example2.into()],
        )
        .await
        .unwrap();

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 2, "Two initial zones");

    catalog
        .upsert(example3.origin().clone(), &vec![example3.into()])
        .await
        .unwrap();

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 1, "Expected upsert to replace zones");
}

#[tokio::test]
async fn find_heirarchical_name() {
    subscribe();
    let catalog = SqliteStore::new_in_memory().unwrap();

    let example1 = example_zone("example.com.");
    let example2 = example_zone("example.com.");

    catalog
        .upsert(
            example1.origin().clone(),
            &vec![example1.into(), example2.into()],
        )
        .await
        .unwrap();

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"www.example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 2);
}

#[tokio::test]
async fn remove_name() {
    subscribe();
    let catalog = SqliteStore::new_in_memory().unwrap();

    let example1 = example_zone("example.com.");
    let example2 = example_zone("example.com.");

    catalog
        .upsert(
            example1.origin().clone(),
            &vec![example1.into(), example2.into()],
        )
        .await
        .unwrap();

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"www.example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 2);

    catalog
        .remove(&LowerName::new(&"example.com.".parse().unwrap()))
        .await
        .unwrap();

    assert!(
        catalog
            .find(&hickory_proto::rr::LowerName::new(
                &"www.example.com.".parse().unwrap(),
            ))
            .await
            .unwrap()
            .is_none()
    )
}

#[tokio::test]
async fn get_insert_delete() {
    subscribe();
    let catalog = SqliteStore::new_in_memory().unwrap();

    let example1 = example_zone("example.com.");
    let example2 = example_zone("example.com.");

    catalog
        .upsert(
            example1.origin().clone(),
            &vec![example1.into(), example2.into()],
        )
        .await
        .unwrap();

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"www.example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 2);

    let zone_id = zones[0].id();
    let zone = catalog.get(zone_id).await.unwrap();

    catalog.delete(zone_id).await.unwrap();

    let mut zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"www.example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 1);
    let example1 = zones.pop().unwrap();

    let example3 = example_zone("example.com.");

    assert_eq!(catalog.insert(&zone).await.unwrap(), 1);
    assert_eq!(catalog.insert(&example3).await.unwrap(), 1);

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"www.example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 3);

    // Already exists in the database, gets upserted.
    assert_eq!(catalog.insert(&example1.into_inner()).await.unwrap(), 1);

    let zones = catalog
        .find(&hickory_proto::rr::LowerName::new(
            &"www.example.com.".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(zones.len(), 3);
}

#[tokio::test]
async fn read_zone_to_db() {
    subscribe();
    let catalog = SqliteStore::new_in_memory().unwrap();
    let zone = Zone::read_from_file(
        Name::root(),
        concat!(env!("CARGO_MANIFEST_DIR"), "/zones/root.zone"),
        ZoneType::External,
    )
    .unwrap();
    catalog.insert(&zone).await.unwrap();

    let zones = catalog
        .find(&"www.example.com.".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(zones.len(), 1);
    assert!(zones[0].name().is_root());
}
