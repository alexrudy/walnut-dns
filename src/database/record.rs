use std::collections::BTreeMap;

use hickory_proto::rr::LowerName;
use hickory_proto::serialize::binary::BinEncodable;
use rusqlite::named_params;

use crate::cache::{EntryMeta, Lookup};
use crate::rr::QueryID;
use crate::{
    Lookup as _, ZoneInfo as _,
    database::FromRow as _,
    rr::{Record, SerialNumber, SqlName, Zone, ZoneID},
};

use super::QueryBuilder;

#[derive(Debug, Clone)]
pub(crate) struct RecordPersistence<'c> {
    connection: &'c rusqlite::Connection,
}

impl<'c> RecordPersistence<'c> {
    pub(crate) fn new(connection: &'c rusqlite::Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<12> = QueryBuilder {
        table: "record",
        columns: [
            "id",
            "zone_id",
            "query_id",
            "soa_serial",
            "name_labels",
            "dns_class",
            "ttl",
            "record_type",
            "rdata",
            "mdns_cache_flush",
            "expires",
            "glue",
        ],
        primary: "id",
    };

    /// Populate a series of zones with records
    #[tracing::instrument("populate_many", skip_all, level = "trace")]
    pub(crate) fn populate_zones(
        &self,
        origin: &LowerName,
        zones: &mut [Zone],
    ) -> rusqlite::Result<()> {
        tracing::trace!("Joined load for {} zones", zones.len());
        let mut stmt = self.connection.prepare(&Self::TABLE.select_for_join(
            "JOIN zone ON record.zone_id = zone.id WHERE lower(zone.name) == lower(:name)",
        ))?;

        let riter = stmt.query_map(
            named_params! { ":name": SqlName::from(origin.clone()) },
            |row| {
                let record = Record::from_row(row)?;
                let zone_id: ZoneID = row.get("zone_id")?;
                let serial: SerialNumber = row.get("soa_serial")?;
                Ok((zone_id, record, serial))
            },
        )?;

        let mut records: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut n = 0usize;
        for result in riter {
            let (zone, record, serial) = result?;
            records.entry(zone).or_default().push((record, serial));
            n += 1;
        }
        tracing::trace!("Populating {} zones from {} records", records.len(), n);
        for zone in zones {
            for (record, serial) in records.remove(&zone.id()).unwrap_or_default() {
                if record.expired() {
                    continue;
                }
                zone.upsert(record, serial)
                    .expect("Zone and record mismatch during DB Load");
            }
        }

        Ok(())
    }

    /// Populate a single zone with records
    #[tracing::instrument("populate", skip_all, level = "trace")]
    pub(crate) fn populate_zone(&self, zone: &mut Zone) -> rusqlite::Result<()> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE zone_id = :zone_id"))?;
        let records = stmt
            .query_map(named_params! { ":zone_id": zone.id() }, Record::from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        for record in records {
            if record.expired() {
                continue;
            }
            zone.upsert(record, SerialNumber::ZERO)
                .expect("Zone and record mismatch during DB Load");
        }

        Ok(())
    }

    /// Populate a single zone with records
    #[tracing::instrument("populate", skip_all, level = "trace")]
    pub(crate) fn populate_lookup(&self, params: EntryMeta) -> rusqlite::Result<Lookup> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE query_id = :query_id"))?;
        let records = stmt
            .query_map(named_params! { ":query_id": params.id() }, Record::from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(params.into_lookup(records))
    }

    #[tracing::instrument("delete_orphans", skip_all, level = "trace")]
    pub(crate) fn delete_orphaned_records(&self, zone: &Zone) -> rusqlite::Result<()> {
        let params: Vec<_> = zone
            .records()
            .filter(|r| !r.expired())
            .map(|record| record.id())
            .collect();
        let param_template = std::iter::repeat_n("?", params.len())
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            "DELETE FROM {table} WHERE zone_id = :zone_id AND id NOT IN ({param_template})",
            table = Self::TABLE.table
        );
        let mut stmt = self.connection.prepare(&query)?;
        stmt.raw_bind_parameter(c":zone_id", zone.id())?;
        tracing::trace!("retaining {} records", params.len());
        for (idx, param) in params.into_iter().enumerate() {
            let pidx = idx + 2;
            stmt.raw_bind_parameter(pidx, param)?;
        }
        let nrows = stmt.raw_execute()?;
        tracing::trace!("dropped {} records", nrows);
        Ok(())
    }

    /// Upsert the set of records which belong to this zone.
    #[tracing::instrument("upsert", skip_all, level = "trace")]
    pub(crate) fn upsert_records(&self, zone: &Zone) -> rusqlite::Result<()> {
        self.delete_orphaned_records(zone)?;
        self.insert_records_for_zone(zone, zone.records())?;

        Ok(())
    }

    #[tracing::instrument("insert", skip_all, level = "trace")]
    pub(crate) fn insert_records_for_query<'q>(
        &self,
        id: QueryID,
        records: impl Iterator<Item = &'q Record>,
    ) -> rusqlite::Result<()> {
        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        let mut n = 0;
        for record in records {
            if record.expired() {
                continue;
            }
            n += stmt.execute(named_params! {
                ":id": record.id(),
                ":zone_id": Option::<ZoneID>::None,
                ":query_id": id,
                ":soa_serial": Option::<u32>::None,
                ":name_labels": SqlName::from(record.name().clone()),
                ":dns_class": u16::from(record.dns_class()),
                ":ttl": record.ttl(),
                ":record_type": u16::from(record.record_type()),
                ":rdata": record.rdata().to_bytes().map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
                ":mdns_cache_flush": record.mdns_cache_flush(),
                ":expires": record.expires(),
                ":glue": record.is_glue(),
            })?;
        }

        tracing::trace!("inserted {n} records");
        Ok(())
    }

    #[tracing::instrument("insert", skip_all, level = "trace")]
    pub(crate) fn insert_records_for_zone<'z>(
        &self,
        zone: &'z Zone,
        records: impl Iterator<Item = &'z Record>,
    ) -> rusqlite::Result<()> {
        let mut stmt = self.connection.prepare(&Self::TABLE.upsert())?;
        let mut n = 0;
        for record in records {
            if record.expired() {
                continue;
            }
            n += stmt.execute(named_params! {
                ":id": record.id(),
                ":zone_id": zone.id(),
                ":query_id": Option::<QueryID>::None,
                ":soa_serial": zone.serial(),
                ":name_labels": SqlName::from(record.name().clone()),
                ":dns_class": u16::from(record.dns_class()),
                ":ttl": record.ttl(),
                ":record_type": u16::from(record.record_type()),
                ":rdata": record.rdata().to_bytes().map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
                ":mdns_cache_flush": record.mdns_cache_flush(),
                ":expires": record.expires(),
                ":glue": record.is_glue(),
            })?;
        }

        tracing::trace!("inserted {n} records");
        Ok(())
    }
}
