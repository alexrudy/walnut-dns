//! Configuration types for DNS cache TTL management.
//!
//! This module provides configuration structures for controlling how long DNS query
//! results are cached. It supports different TTL bounds for positive responses
//! (successful lookups) and negative responses (NXDOMAIN), with per-record-type
//! customization.

use std::{collections::BTreeMap, ops::RangeInclusive};

use hickory_proto::rr::RecordType;

use crate::rr::TimeToLive;

/// Configuration for DNS cache TTL bounds.
///
/// This structure allows configuring minimum and maximum TTL values for both
/// positive and negative DNS responses, with optional per-record-type overrides.
///
/// # Examples
///
/// ```rust,ignore
/// use walnut_dns::cache::CacheConfig;
///
/// // Use default configuration
/// let config = CacheConfig::default();
///
/// // Get TTL bounds for A records
/// let positive_range = config.positive_ttl(RecordType::A);
/// let negative_range = config.negative_ttl(RecordType::A);
/// ```
#[derive(Debug, Clone, Default)]
pub struct CacheConfig {
    default: CacheTTLBounds,
    records: BTreeMap<RecordType, CacheTTLBounds>,
}

impl CacheConfig {
    /// Returns the positive TTL range for the specified record type.
    ///
    /// If no specific configuration exists for the record type, returns the default range.
    /// Positive TTLs apply to successful DNS lookups.
    ///
    /// # Arguments
    ///
    /// * `record` - The DNS record type to get TTL bounds for
    ///
    /// # Returns
    ///
    /// A range representing the minimum and maximum allowed TTL values.
    pub fn positive_ttl(&self, record: RecordType) -> RangeInclusive<TimeToLive> {
        self.records
            .get(&record)
            .unwrap_or(&self.default)
            .positive
            .range()
    }

    /// Returns the negative TTL range for the specified record type.
    ///
    /// If no specific configuration exists for the record type, returns the default range.
    /// Negative TTLs apply to NXDOMAIN responses.
    ///
    /// # Arguments
    ///
    /// * `record` - The DNS record type to get TTL bounds for
    ///
    /// # Returns
    ///
    /// A range representing the minimum and maximum allowed TTL values.
    pub fn negative_ttl(&self, record: RecordType) -> RangeInclusive<TimeToLive> {
        self.records
            .get(&record)
            .unwrap_or(&self.default)
            .negative
            .range()
    }

    /// Sets positive TTL bounds for a specific record type.
    ///
    /// # Arguments
    ///
    /// * `record_type` - The DNS record type to configure
    /// * `min` - Minimum TTL value
    /// * `max` - Maximum TTL value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_positive_ttl(mut self, record_type: RecordType, min: TimeToLive, max: TimeToLive) -> Self {
        let bounds = self.records.entry(record_type).or_default();
        bounds.positive = TTLBounds::between(min, max);
        self
    }

    /// Sets negative TTL bounds for a specific record type.
    ///
    /// # Arguments
    ///
    /// * `record_type` - The DNS record type to configure
    /// * `min` - Minimum TTL value
    /// * `max` - Maximum TTL value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_negative_ttl(mut self, record_type: RecordType, min: TimeToLive, max: TimeToLive) -> Self {
        let bounds = self.records.entry(record_type).or_default();
        bounds.negative = TTLBounds::between(min, max);
        self
    }

    /// Sets default positive TTL bounds for all record types.
    ///
    /// # Arguments
    ///
    /// * `min` - Minimum TTL value
    /// * `max` - Maximum TTL value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_default_positive_ttl(mut self, min: TimeToLive, max: TimeToLive) -> Self {
        self.default.positive = TTLBounds::between(min, max);
        self
    }

    /// Sets default negative TTL bounds for all record types.
    ///
    /// # Arguments
    ///
    /// * `min` - Minimum TTL value
    /// * `max` - Maximum TTL value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_default_negative_ttl(mut self, min: TimeToLive, max: TimeToLive) -> Self {
        self.default.negative = TTLBounds::between(min, max);
        self
    }
}

/// TTL bounds with optional minimum and maximum values.
///
/// If min is None, defaults to `TimeToLive::ZERO`.
/// If max is None, defaults to `TimeToLive::MAX`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct TTLBounds {
    min: Option<TimeToLive>,
    max: Option<TimeToLive>,
}

impl TTLBounds {
    /// Creates TTL bounds with specific minimum and maximum values.
    ///
    /// # Arguments
    ///
    /// * `min` - Minimum TTL value
    /// * `max` - Maximum TTL value
    pub fn between(min: TimeToLive, max: TimeToLive) -> Self {
        Self {
            min: Some(min),
            max: Some(max),
        }
    }

    /// Converts the bounds into an inclusive range.
    ///
    /// Missing bounds are filled with appropriate defaults.
    fn range(&self) -> RangeInclusive<TimeToLive> {
        self.min.unwrap_or(TimeToLive::ZERO)..=self.max.unwrap_or(TimeToLive::MAX)
    }
}

/// TTL bounds for both positive and negative DNS responses.
///
/// Allows separate configuration of caching behavior for successful lookups
/// and NXDOMAIN responses.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct CacheTTLBounds {
    positive: TTLBounds,
    negative: TTLBounds,
}

impl CacheTTLBounds {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cache_config() {
        let config = CacheConfig::default();
        assert_eq!(config.positive_ttl(RecordType::A), TimeToLive::ZERO..=TimeToLive::MAX);
        assert_eq!(config.negative_ttl(RecordType::A), TimeToLive::ZERO..=TimeToLive::MAX);
    }

    #[test]
    fn test_ttl_bounds_range() {
        let bounds = TTLBounds {
            min: Some(TimeToLive::from_secs(300)),
            max: Some(TimeToLive::from_secs(3600)),
        };
        assert_eq!(bounds.range(), TimeToLive::from_secs(300)..=TimeToLive::from_secs(3600));
    }

    #[test]
    fn test_ttl_bounds_none() {
        let bounds = TTLBounds::default();
        assert_eq!(bounds.range(), TimeToLive::ZERO..=TimeToLive::MAX);
    }

    #[test]
    fn test_cache_config_with_specific_record() {
        let mut config = CacheConfig::default();
        let bounds = CacheTTLBounds {
            positive: TTLBounds {
                min: Some(TimeToLive::from_secs(60)),
                max: Some(TimeToLive::from_secs(1800)),
            },
            negative: TTLBounds {
                min: Some(TimeToLive::from_secs(30)),
                max: Some(TimeToLive::from_secs(300)),
            },
        };
        config.records.insert(RecordType::A, bounds);

        assert_eq!(config.positive_ttl(RecordType::A), TimeToLive::from_secs(60)..=TimeToLive::from_secs(1800));
        assert_eq!(config.negative_ttl(RecordType::A), TimeToLive::from_secs(30)..=TimeToLive::from_secs(300));
        assert_eq!(config.positive_ttl(RecordType::AAAA), TimeToLive::ZERO..=TimeToLive::MAX);
    }

    #[test]
    fn test_cache_config_builder_methods() {
        let config = CacheConfig::default()
            .with_positive_ttl(RecordType::A, TimeToLive::from_secs(60), TimeToLive::from_secs(1800))
            .with_negative_ttl(RecordType::A, TimeToLive::from_secs(30), TimeToLive::from_secs(300))
            .with_default_positive_ttl(TimeToLive::from_secs(300), TimeToLive::from_secs(3600))
            .with_default_negative_ttl(TimeToLive::from_secs(60), TimeToLive::from_secs(600));

        assert_eq!(config.positive_ttl(RecordType::A), TimeToLive::from_secs(60)..=TimeToLive::from_secs(1800));
        assert_eq!(config.negative_ttl(RecordType::A), TimeToLive::from_secs(30)..=TimeToLive::from_secs(300));
        assert_eq!(config.positive_ttl(RecordType::AAAA), TimeToLive::from_secs(300)..=TimeToLive::from_secs(3600));
        assert_eq!(config.negative_ttl(RecordType::AAAA), TimeToLive::from_secs(60)..=TimeToLive::from_secs(600));
    }

    #[test]
    fn test_ttl_bounds_constructors() {
        let bounds1 = TTLBounds {
            min: Some(TimeToLive::from_secs(60)),
            max: Some(TimeToLive::from_secs(300)),
        };
        let bounds2 = TTLBounds::between(TimeToLive::from_secs(60), TimeToLive::from_secs(300));
        
        assert_eq!(bounds1, bounds2);
        assert_eq!(bounds1.range(), TimeToLive::from_secs(60)..=TimeToLive::from_secs(300));
    }

    #[test]
    fn test_cache_ttl_bounds_constructor() {
        let positive = TTLBounds::between(TimeToLive::from_secs(60), TimeToLive::from_secs(1800));
        let negative = TTLBounds::between(TimeToLive::from_secs(30), TimeToLive::from_secs(300));
        let bounds = CacheTTLBounds { positive, negative };
        
        assert_eq!(bounds.positive, positive);
        assert_eq!(bounds.negative, negative);
    }
}
