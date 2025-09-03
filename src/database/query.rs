use hickory_proto::op::Query;
use rusqlite::named_params;
use tracing::trace;

use crate::database::record::RecordPersistence;
use crate::lookup::{CacheTimestamp, EntryMeta, Lookup};
use crate::rr::{QueryID, SqlName, TimeToLive};

use super::{FromRow, QueryBuilder};

#[derive(Debug, Clone)]
pub(crate) struct QueryPersistence<'c> {
    connection: &'c rusqlite::Connection,
}

impl<'c> QueryPersistence<'c> {
    pub(crate) fn new(connection: &'c rusqlite::Connection) -> Self {
        Self { connection }
    }

    const TABLE: QueryBuilder<7> = QueryBuilder {
        table: "query",
        columns: [
            "id",
            "name",
            "record_type",
            "dns_class",
            "response_code",
            "expires",
            "last_access",
        ],
        primary: "id",
    };

    #[allow(dead_code)]
    pub(crate) fn get(&self, query: QueryID, now: CacheTimestamp) -> rusqlite::Result<Lookup> {
        let columns = Self::TABLE.columns.join(", ");

        let mut stmt = self.connection.prepare(&format!(
            "UPDATE OR IGNORE {table} SET last_access = :now WHERE id = :query_id AND expires >= :now RETURNING {columns}",
            table = Self::TABLE.table
        ))?;
        let entry = stmt.query_one(
            named_params! { ":query_id": query, ":now": now },
            EntryMeta::from_row,
        )?;

        let rx = RecordPersistence::new(self.connection);
        rx.populate_lookup(entry)
    }

    pub(crate) fn find(&self, query: Query, now: CacheTimestamp) -> rusqlite::Result<Lookup> {
        let columns = Self::TABLE.columns.join(", ");

        let mut stmt = self.connection.prepare(&format!(
            "UPDATE OR IGNORE {table} SET last_access = :now WHERE name = :name AND record_type = :record_type AND dns_class = :dns_class AND expires >= :now RETURNING {columns}",
            table= Self::TABLE.table
        ))?;

        let entry = stmt.query_one(
            named_params! { ":name": SqlName::from(query.name().clone()), ":record_type": u16::from(query.query_type()), ":dns_class": u16::from(query.query_class()), ":now": now },
            EntryMeta::from_row,
        )?;

        let rx = RecordPersistence::new(self.connection);
        rx.populate_lookup(entry)
    }

    pub(crate) fn insert_lookup(
        &self,
        lookup: &Lookup,
        now: CacheTimestamp,
        ttl: TimeToLive,
    ) -> rusqlite::Result<()> {
        let mut stmt = self.connection.prepare(&Self::TABLE.insert_or_replace())?;

        trace!("Inserting lookup query {id}", id = lookup.id());
        let expires = now + ttl;

        stmt.execute(named_params! {
            ":id": lookup.id(),
            ":name": SqlName::from(lookup.query().name().clone()),
            ":record_type": u16::from(lookup.query().query_type()),
            ":dns_class": u16::from(lookup.query().query_class()),
            ":response_code": u16::from(lookup.response_code()),
            ":expires": expires,
            ":last_access": now,
        })?;
        trace!("Adding {n} records", n = lookup.records().len());
        let rx = RecordPersistence::new(self.connection);
        rx.insert_records_for_query(lookup.id(), lookup.records().iter())?;

        Ok(())
    }

    pub(crate) fn remove_expired(&self, now: CacheTimestamp) -> rusqlite::Result<()> {
        let mut stmt = self.connection.prepare(&format!(
            "DELETE FROM {table} WHERE expires < :deadline",
            table = Self::TABLE.table
        ))?;
        let nrows = stmt.execute(named_params! { ":deadline": now })?;
        trace!(n = nrows, "Removed {nrows} expired records");
        Ok(())
    }
}
