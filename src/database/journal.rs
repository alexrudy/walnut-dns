use rusqlite::Connection;
use std::sync::{Arc, Mutex};

use super::RecordPersistence;
use crate::{authority::Journal, rr::Zone};

pub struct SqliteJournal {
    connection: Arc<Mutex<Connection>>,
}

impl<Z> Journal<Z> for SqliteJournal
where
    Z: AsRef<Zone>,
{
    fn insert(
        &self,
        zone: &Z,
        records: &[crate::rr::Record],
    ) -> Result<(), crate::authority::CatalogError> {
        let mut conn = self.connection.lock().expect("poisoned");
        let tx = conn.transaction()?;
        let rx = RecordPersistence::new(&tx);
        let zone = zone.as_ref();
        rx.insert_records(zone, records.iter())?;
        tx.commit()?;
        Ok(())
    }
}
