use std::sync::Arc;

use chrono::{DateTime, Utc};
use hickory_proto::op::Query;

use monarch_db::MonarchDB;

use thiserror::Error;

use crate::database::{ConnectionManager, query::QueryPersistence};
use crate::database::{MONARCH, Result};
use crate::rr::TimeToLive;

pub use self::config::CacheConfig;
pub use self::lookup::{CacheTimestamp, CachedQuery, EntryMeta, Lookup, NxDomain};
pub use self::service::DnsCacheService;

mod config;
mod lookup;
mod service;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Timed Out waiting for SQLite connection")]
    TimedOut,
    #[error("SQLite: {0}")]
    Database(#[from] rusqlite::Error),
}

#[cfg(feature = "pool")]
impl From<bb8::RunError<rusqlite::Error>> for CacheError {
    fn from(error: bb8::RunError<rusqlite::Error>) -> Self {
        match error {
            bb8::RunError::User(sql_error) => sql_error.into(),
            bb8::RunError::TimedOut => CacheError::TimedOut,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DNSCache {
    manager: ConnectionManager,
    config: Arc<CacheConfig>,
}

impl DNSCache {
    pub async fn new(manager: ConnectionManager, config: CacheConfig) -> Result<Self> {
        let db = MonarchDB::from(MONARCH);
        {
            let mut connection = manager.get().await?;
            db.migrations(&mut connection).prepare()?;
        };

        Ok(Self {
            manager,
            config: Arc::new(config),
        })
    }

    async fn insert_query(
        &self,
        lookup: &Lookup,
        now: DateTime<Utc>,
        ttl: TimeToLive,
    ) -> Result<(), CacheError> {
        let rng = self.config.positive_ttl(lookup.query().query_type());

        let mut connection = self.manager.get().await?;

        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            qx.insert_lookup(&lookup, now.into(), ttl.clamp(*rng.start(), *rng.end()))?;
            tx.commit()?;
            Ok(())
        })
    }

    async fn insert_nxdomain(
        &self,
        nxdomain: &NxDomain,
        now: DateTime<Utc>,
        ttl: TimeToLive,
    ) -> Result<(), CacheError> {
        let rng = self.config.negative_ttl(nxdomain.query().query_type());

        let mut connection = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            qx.insert_nxdomain(&nxdomain, now.into(), ttl.clamp(*rng.start(), *rng.end()))?;
            tx.commit()?;
            Ok(())
        })
    }

    pub async fn insert(&self, query: &CachedQuery, now: DateTime<Utc>) -> Result<(), CacheError> {
        match query.lookup() {
            Ok(lookup) => self.insert_query(lookup, now, lookup.ttl(now)).await,
            Err(nx_domain) => {
                self.insert_nxdomain(
                    nx_domain,
                    now,
                    nx_domain.negative_ttl().unwrap_or(TimeToLive::MIN),
                )
                .await
            }
        }
    }

    pub async fn get(
        &self,
        query: Query,
        now: DateTime<Utc>,
    ) -> Result<Option<CachedQuery>, CacheError> {
        let mut connection = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            let entry = match qx.find(query, now.into()) {
                Ok(entry) => Ok(Some(entry)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(err),
            }?;
            tx.commit()?;
            Ok(entry)
        })
    }

    pub async fn cleanup(&self, now: DateTime<Utc>) -> Result<(), CacheError> {
        let mut connection = self.manager.get().await?;
        crate::block_in_place(|| {
            let tx = connection.transaction()?;
            let qx = QueryPersistence::new(&tx);
            qx.remove_expired(now.into())?;
            tx.commit()?;
            Ok(())
        })
    }
}
