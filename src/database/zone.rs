use hickory_proto::rr::{LowerName, Name};
use rusqlite::named_params;

use crate::database::record::RecordPersistence;
use crate::{
    ZoneInfo as _,
    database::FromRow as _,
    rr::{SqlName, Zone, ZoneID},
};

use super::QueryBuilder;

#[derive(Debug, Clone)]
pub(crate) struct ZonePersistence<'c> {
    connection: &'c rusqlite::Connection,
}

impl<'c> ZonePersistence<'c> {
    pub(crate) fn new(connection: &'c rusqlite::Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<5> = QueryBuilder {
        table: "zone",
        columns: ["id", "name", "zone_type", "allow_axfr", "dns_class"],
        primary: "id",
    };

    /// Get a single zone by ID
    #[tracing::instrument(skip_all, fields(zone=%id), level = "trace")]
    pub(crate) fn get(&self, id: ZoneID) -> rusqlite::Result<Zone> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE id = :zone_id"))?;
        let mut zone = stmt.query_one(named_params! { ":zone_id": id }, Zone::from_row)?;

        let rx = RecordPersistence::new(self.connection);
        rx.populate_zone(&mut zone)?;

        Ok(zone)
    }

    /// Find zones based on zone name
    #[tracing::instrument(skip_all, fields(zone=%name), level = "debug")]
    pub(crate) fn find(&self, name: &LowerName) -> rusqlite::Result<Option<Vec<Zone>>> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE lower(name) = lower(:name)"))?;

        let mut name = name.clone();
        loop {
            tracing::debug!(%name, "searching for zone with name={}", name);
            let mut zones = stmt
                .query_map(
                    named_params! { ":name": SqlName::from(name.clone()) },
                    Zone::from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;

            if !zones.is_empty() {
                tracing::trace!("found {} zones", zones.len());
                let rx = RecordPersistence::new(self.connection);
                rx.populate_zones(&name, zones.as_mut_slice())?;
                return Ok(Some(zones));
            }

            if !name.is_root() {
                tracing::trace!("name is not root, base_name={}", name.base_name());
                name = name.base_name();
            } else {
                tracing::trace!("name is root");
                return Ok(None);
            }
        }
    }

    #[tracing::instrument(skip_all, fields(zone=%zone.name()), level = "trace")]
    pub(crate) fn upsert(&self, zone: &Zone) -> rusqlite::Result<usize> {
        let guard = tracing::trace_span!("zone").entered();

        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        tracing::trace!("preparing statement for insert with name={}", zone.name());
        let n = stmt.execute(named_params! { ":id": zone.id(), ":name": SqlName::from(zone.name().clone()), ":zone_type": zone.zone_type(), ":allow_axfr": zone.allow_axfr(), ":dns_class": u16::from(zone.dns_class()) })?;
        if n > 0 {
            tracing::trace!("affected {} rows", n);
        } else {
            tracing::trace!("no rows affected")
        }
        drop(guard);

        if !zone.is_empty() {
            let rx = RecordPersistence::new(self.connection);
            rx.upsert_records(zone)?;
        }

        Ok(n)
    }

    #[tracing::instrument(skip_all, fields(zone=%id), level = "trace")]
    pub(crate) fn delete(&self, id: ZoneID) -> rusqlite::Result<usize> {
        // CASCADE will handle deleting the associated records.
        let mut stmt = self.connection.prepare(&Self::TABLE.delete())?;
        let n = stmt.execute(named_params! { ":id": id })?;
        Ok(n)
    }

    #[tracing::instrument(skip_all, fields(zone=%name), level = "trace")]
    pub(crate) fn clear(&self, name: &LowerName) -> rusqlite::Result<usize> {
        // CASCADE will handle deleting the associated records.
        let mut stmt = self.connection.prepare(&format!(
            "DELETE FROM {} WHERE lower(name) = lower(:name)",
            Self::TABLE.table
        ))?;
        let n = stmt.execute(named_params! { ":name": SqlName::from(name.clone()) })?;
        Ok(n)
    }

    #[tracing::instrument(skip_all, level = "trace")]
    pub(crate) fn list(&self, root: &LowerName) -> rusqlite::Result<Vec<Name>> {
        let mut stmt = self.connection.prepare(&format!(
            "SELECT DISTINCT name FROM {table} WHERE lower(name) LIKE :name",
            table = Self::TABLE.table
        ))?;

        let name = format!("%{root}");
        tracing::trace!("Listing records for root: {}", name);

        let names = stmt
            .query_map(named_params! {":name": name}, |row| {
                Ok(row.get::<_, SqlName>("name")?.into())
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }
}
