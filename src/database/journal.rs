use super::{ConnectionManager, RecordPersistence, ZonePersistence};
use crate::{authority::Journal, catalog::CatalogError, rr::Zone};

/// SQLite-based journal for DNS operations
///
/// The SqliteJournal provides a way to record DNS operations (like record insertions
/// and zone updates) to a SQLite database. This is useful for auditing, replication,
/// and maintaining operation history.
pub struct SqliteJournal {
    manager: ConnectionManager,
}

impl SqliteJournal {
    pub(super) fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl<Z> Journal<Z> for SqliteJournal
where
    Z: AsRef<Zone> + Sync + 'static,
{
    async fn insert_records(
        &self,
        zone: &Z,
        records: &[crate::rr::Record],
    ) -> Result<(), CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let rx = RecordPersistence::new(&tx);
            let zone = zone.as_ref();
            rx.insert_records_for_zone(zone, records.iter())?;
            tx.commit()?;
            Ok(())
        })
    }

    async fn upsert_zone(&self, zone: &Z) -> Result<(), CatalogError> {
        let mut conn = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = conn.transaction()?;
            let zx = ZonePersistence::new(&tx);
            let zone = zone.as_ref();
            zx.upsert(zone)?;
            tx.commit()?;
            Ok(())
        })
    }
}
