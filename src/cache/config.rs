use std::{collections::BTreeMap, ops::RangeInclusive};

use hickory_proto::rr::RecordType;

use crate::rr::TimeToLive;

#[derive(Debug, Clone, Default)]
pub struct CacheConfig {
    default: CacheTTLBounds,
    records: BTreeMap<RecordType, CacheTTLBounds>,
}

impl CacheConfig {
    pub fn positive_ttl(&self, record: RecordType) -> RangeInclusive<TimeToLive> {
        self.records
            .get(&record)
            .unwrap_or(&self.default)
            .positive
            .range()
    }

    pub fn negative_ttl(&self, record: RecordType) -> RangeInclusive<TimeToLive> {
        self.records
            .get(&record)
            .unwrap_or(&self.default)
            .negative
            .range()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct TTLBounds {
    min: Option<TimeToLive>,
    max: Option<TimeToLive>,
}

impl TTLBounds {
    fn range(&self) -> RangeInclusive<TimeToLive> {
        self.min.unwrap_or(TimeToLive::ZERO)..=self.max.unwrap_or(TimeToLive::MAX)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct CacheTTLBounds {
    positive: TTLBounds,
    negative: TTLBounds,
}
