use std::collections::BTreeMap;

use hickory_proto::rr::{DNSClass, LowerName, Name, RecordType, RrKey};
use hickory_proto::serialize::binary::BinEncodable;
use rusqlite::named_params;

use crate::authority::Records as _;
use crate::lookup::{EntryMeta, QueryLookup};
use crate::rr::QueryID;
use crate::{
    ZoneInfo as _,
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
    pub(crate) fn populate_zones(&self, origin: &Name, zones: &mut [Zone]) -> rusqlite::Result<()> {
        tracing::trace!("Joined load for {} zones", zones.len());
        // Records form a log that may contain RFC 2136 deletion markers, so they must be replayed
        // in the order they were written: ascending SOA serial, then insertion order (rowid).
        let mut stmt = self.connection.prepare(&Self::TABLE.select_for_join(
            "JOIN zone ON record.zone_id = zone.id WHERE lower(zone.name) == lower(:name) \
             ORDER BY record.soa_serial ASC, record.rowid ASC",
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
                replay_persisted_record(zone, record, serial);
            }
        }

        Ok(())
    }

    /// Populate a single zone with records
    #[tracing::instrument("populate", skip_all, level = "trace")]
    pub(crate) fn populate_zone(&self, zone: &mut Zone) -> rusqlite::Result<()> {
        // See `populate_zones`: replay records in log order so deletion markers apply correctly.
        let mut stmt = self.connection.prepare(
            &Self::TABLE.select("WHERE zone_id = :zone_id ORDER BY soa_serial ASC, rowid ASC"),
        )?;
        let records = stmt
            .query_map(named_params! { ":zone_id": zone.id() }, |row| {
                let record = Record::from_row(row)?;
                let serial: SerialNumber = row.get("soa_serial")?;
                Ok((record, serial))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (record, serial) in records {
            if record.expired() {
                continue;
            }
            replay_persisted_record(zone, record, serial);
        }

        Ok(())
    }

    /// Populate a single zone with records
    #[tracing::instrument("populate", skip_all, level = "trace")]
    pub(crate) fn populate_lookup(&self, params: EntryMeta) -> rusqlite::Result<QueryLookup> {
        let mut stmt = self
            .connection
            .prepare(&Self::TABLE.select("WHERE query_id = :query_id"))?;
        let records = stmt
            .query_map(named_params! { ":query_id": params.id() }, Record::from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(params.into_lookup(records))
    }

    /// Delete every persisted record belonging to a zone.
    #[tracing::instrument("delete_zone_records", skip_all, level = "trace")]
    pub(crate) fn delete_records_for_zone(&self, zone: &Zone) -> rusqlite::Result<()> {
        let query = format!(
            "DELETE FROM {table} WHERE zone_id = :zone_id",
            table = Self::TABLE.table
        );
        let mut stmt = self.connection.prepare(&query)?;
        let nrows = stmt.execute(named_params! { ":zone_id": zone.id() })?;
        tracing::trace!("cleared {} records for zone", nrows);
        Ok(())
    }

    /// Upsert the set of records which belong to this zone.
    ///
    /// This compacts the record log into a clean snapshot: the persisted records are fully replaced
    /// by the zone's current in-memory records. Compaction is what keeps the log bounded and, just
    /// as importantly, is the only way some deletions become durable — e.g. DNSSEC re-signing
    /// removes the old RRSIG records without writing deletion markers for them, so an incremental
    /// (append-only) persist would resurrect them on reload.
    ///
    /// Between a write-ahead log append ([`Self::insert_records_for_zone`], which may record
    /// `DNSClass::NONE`/`DNSClass::ANY` deletion markers) and the next call to this method, the log
    /// can contain those markers. Loading such a log is handled by replaying the entries rather than
    /// inserting them verbatim (see `populate_zones`/`populate_zone`).
    #[tracing::instrument("upsert", skip_all, level = "trace")]
    pub(crate) fn upsert_records(&self, zone: &Zone) -> rusqlite::Result<()> {
        self.delete_records_for_zone(zone)?;
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

/// Apply a single persisted record to a zone while loading it from the database.
///
/// The record log stores DNS UPDATE operations more or less verbatim, so in addition to normal
/// additive records (in the zone's own class) it can contain the RFC 2136 deletion markers:
///
/// * `DNSClass::NONE` — delete a single resource record from an RRset (RFC 2136 §3.4.2.4).
/// * `DNSClass::ANY` — delete an entire RRset, or every RRset at a name (RFC 2136 §3.4.2.3).
///
/// Replaying these markers (instead of blindly inserting them) lets a zone be reconstructed from a
/// log that still contains pending deletions, for example after a crash between the write-ahead log
/// write and the compacting snapshot in [`RecordPersistence::upsert_records`].
fn replay_persisted_record(zone: &mut Zone, record: Record, serial: SerialNumber) {
    match record.dns_class() {
        // An additive record in the zone's own class (RFC 2136 §3.4.2.2).
        class if class == zone.dns_class() => {
            if let Err(error) = zone.upsert(record, serial) {
                tracing::warn!("skipping record while loading zone: {error}");
            }
        }
        // Delete a single resource record from an RRset.
        DNSClass::NONE => {
            let key = record.rrkey();
            if let Some(rrset) = zone.get_mut(&key) {
                if let Err(error) = rrset.remove(&record, serial) {
                    tracing::warn!("could not delete record while loading zone: {error}");
                }
            }
        }
        // Delete an entire RRset, or every RRset at a name.
        DNSClass::ANY => {
            let name = LowerName::from(record.name());
            let origin = LowerName::from(zone.origin());

            match record.record_type() {
                RecordType::ANY => {
                    let to_delete = zone
                        .keys()
                        .filter(|key| key.name == name)
                        // The SOA and NS records at the zone origin are never deleted.
                        .filter(|key| {
                            !(matches!(key.record_type, RecordType::SOA | RecordType::NS)
                                && key.name == origin)
                        })
                        .cloned()
                        .collect::<Vec<RrKey>>();
                    for key in to_delete {
                        zone.remove(&key);
                    }
                }
                // The SOA and NS records at the zone origin are never deleted.
                RecordType::SOA | RecordType::NS if name == origin => {}
                _ => {
                    zone.remove(&record.rrkey());
                }
            }
        }
        other => {
            tracing::warn!(
                "ignoring record with unexpected DNS class {other:?} while loading zone"
            );
        }
    }
}
