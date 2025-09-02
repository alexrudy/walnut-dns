//! Resolver for reserved names

use std::collections::BTreeMap;

use hickory_proto::{
    op::{Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, RecordType,
        domain::usage::{self, ResolverUsage, ZoneUsage},
        rdata::{A, AAAA, PTR},
    },
};
use once_cell::sync::Lazy;

use super::{QueryLookup, Resolver, ResolverError};

static LOCALHOST_PTR: Lazy<RData> =
    Lazy::new(|| RData::PTR(PTR(Name::from_ascii("localhost.").unwrap())));
static LOCALHOST_V4: Lazy<RData> = Lazy::new(|| RData::A(A::new(127, 0, 0, 1)));
static LOCALHOST_V6: Lazy<RData> = Lazy::new(|| RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageArea {
    User,
    Application,
    Resolver,
    Cache,
    Auth,
    Op,
    Registry,
}

pub struct ReservedNamesResolver {
    names: BTreeMap<Name, &'static ZoneUsage>,
    area: UsageArea,
}

impl ReservedNamesResolver {
    pub fn new(area: UsageArea) -> Self {
        Self {
            names: BTreeMap::new(),
            area,
        }
    }

    /// Add a new reserved name to this resolver
    pub fn insert(&mut self, usage: &'static ZoneUsage) {
        self.names.insert(usage.name().clone(), usage);
    }

    pub fn default_reserved_local_names(area: UsageArea) -> Self {
        let mut resolver = Self::new(area);
        resolver.insert(&usage::LOCALHOST);
        resolver.insert(&usage::DEFAULT);
        resolver.insert(&usage::ONION);
        resolver.insert(&usage::INVALID);
        resolver.insert(&usage::IN_ADDR_ARPA_127);
        resolver.insert(&usage::IP6_ARPA_1);
        resolver.insert(&usage::LOCAL);
        resolver
    }

    fn get(&self, mut name: Name) -> Option<&'static ZoneUsage> {
        loop {
            tracing::trace!("Looking for {name}");
            if let Some(&usage) = self.names.get(&name) {
                return Some(usage);
            }
            if name.is_root() {
                return None;
            }
            name = name.base_name();
        }
    }

    fn check_resolver_usage(&self, query: Query, usage: &'static ZoneUsage) -> QueryLookup {
        match usage.resolver() {
            ResolverUsage::Loopback => match query.query_type() {
                RecordType::A => QueryLookup::from_rdata(query, LOCALHOST_V4.clone()),
                RecordType::AAAA => QueryLookup::from_rdata(query, LOCALHOST_V6.clone()),
                RecordType::PTR => QueryLookup::from_rdata(query, LOCALHOST_PTR.clone()),
                _ => QueryLookup::no_records(query, ResponseCode::NoError),
            },
            ResolverUsage::Normal | ResolverUsage::LinkLocal | ResolverUsage::NxDomain => {
                QueryLookup::no_records(query, ResponseCode::NXDomain)
            }
        }
    }
}

#[async_trait::async_trait]
impl Resolver for ReservedNamesResolver {
    async fn query(&self, query: Query) -> Result<QueryLookup, ResolverError> {
        if query.query_class() != DNSClass::IN {
            tracing::trace!(DNSClass=?query.query_class(), "Skipping reserved names handler");
            return Ok(QueryLookup::no_records(query, ResponseCode::NXDomain));
        }
        if let Some(usage) = self.get(query.name().clone()) {
            return match self.area {
                UsageArea::User => todo!(),
                UsageArea::Application => todo!(),
                UsageArea::Resolver => Ok(self.check_resolver_usage(query, usage)),
                UsageArea::Cache => todo!(),
                UsageArea::Auth => todo!(),
                UsageArea::Op => todo!(),
                UsageArea::Registry => todo!(),
            };
        }

        Ok(QueryLookup::no_records(query, ResponseCode::NXDomain))
    }
}
