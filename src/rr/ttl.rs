use std::fmt;
use std::time::Duration;

use chrono::Utc;

use rusqlite::types::{FromSql, ToSql};

/// DNS Cache Time-to-live, in seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeToLive(u32);

impl Default for TimeToLive {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TimeToLive {
    pub const MAX: TimeToLive = TimeToLive(u32::MAX);
    pub const MIN: TimeToLive = TimeToLive(u32::MIN);
    pub const DEFAULT: TimeToLive = TimeToLive(86400u32);
    pub const ZERO: TimeToLive = TimeToLive(0u32);

    /// Create a TimeToLive from seconds
    ///
    /// Creates a new TimeToLive value from the specified number of seconds.
    ///
    /// # Arguments
    ///
    /// * `secs` - The TTL value in seconds
    ///
    /// # Returns
    ///
    /// A new TimeToLive instance
    pub fn from_secs(secs: u32) -> Self {
        TimeToLive(secs)
    }

    /// Create a TimeToLive from days
    ///
    /// Creates a new TimeToLive value from the specified number of days.
    ///
    /// # Arguments
    ///
    /// * `days` - The TTL value in days
    ///
    /// # Returns
    ///
    /// A new TimeToLive instance
    pub fn from_days(days: u32) -> Self {
        TimeToLive(days * 86400)
    }

    /// Calculate the deadline for this TTL
    ///
    /// Returns the UTC timestamp when a record with this TTL would expire
    /// if cached now.
    ///
    /// # Returns
    ///
    /// The expiration timestamp
    pub fn deadline(&self) -> chrono::DateTime<Utc> {
        Utc::now() + Duration::from(*self)
    }
}

impl fmt::Display for TimeToLive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for TimeToLive {
    fn from(value: u32) -> Self {
        TimeToLive(value)
    }
}

impl From<TimeToLive> for u32 {
    fn from(value: TimeToLive) -> Self {
        value.0
    }
}

impl From<TimeToLive> for i64 {
    fn from(value: TimeToLive) -> Self {
        value.0 as i64
    }
}

impl From<Duration> for TimeToLive {
    fn from(value: Duration) -> Self {
        TimeToLive(
            value
                .as_secs()
                .try_into()
                .expect("Duration does not fit in u32 seconds"),
        )
    }
}

impl From<TimeToLive> for Duration {
    fn from(value: TimeToLive) -> Self {
        Duration::from_secs(value.0 as u64)
    }
}

impl ToSql for TimeToLive {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for TimeToLive {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        u32::column_result(value).map(TimeToLive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_ttl_constants() {
        assert_eq!(TimeToLive::ZERO.0, 0);
        assert_eq!(TimeToLive::MIN.0, u32::MIN);
        assert_eq!(TimeToLive::MAX.0, u32::MAX);
    }

    #[test]
    fn test_ttl_from_secs() {
        let ttl = TimeToLive::from_secs(3600);
        assert_eq!(ttl.0, 3600);
    }

    #[test]
    fn test_ttl_from_u32() {
        let ttl = TimeToLive::from(300);
        assert_eq!(ttl.0, 300);

        let value: u32 = ttl.into();
        assert_eq!(value, 300);
    }

    #[test]
    fn test_ttl_from_duration() {
        let duration = Duration::from_secs(1800);
        let ttl = TimeToLive::from(duration);
        assert_eq!(ttl.0, 1800);

        let back_to_duration: Duration = ttl.into();
        assert_eq!(back_to_duration, duration);
    }

    #[test]
    #[should_panic(expected = "Duration does not fit in u32 seconds")]
    fn test_ttl_from_duration_overflow() {
        let duration = Duration::from_secs(u64::MAX);
        let _ttl = TimeToLive::from(duration);
    }

    #[test]
    fn test_ttl_display() {
        let ttl = TimeToLive::from(3600);
        assert_eq!(format!("{ttl}"), "3600");
    }

    #[test]
    fn test_ttl_ordering() {
        let ttl1 = TimeToLive::from(60);
        let ttl2 = TimeToLive::from(120);
        let ttl3 = TimeToLive::from(60);

        assert!(ttl1 < ttl2);
        assert!(ttl2 > ttl1);
        assert_eq!(ttl1, ttl3);
        assert!(ttl1 <= ttl3);
        assert!(ttl1 >= ttl3);
    }

    #[test]
    fn test_ttl_deadline() {
        let ttl = TimeToLive::from(3600); // 1 hour
        let deadline = ttl.deadline();
        let now = Utc::now();

        // Deadline should be roughly 1 hour from now (within a few seconds for test execution time)
        let diff = deadline - now;
        assert!(diff.num_seconds() >= 3590); // At least 59:50
        assert!(diff.num_seconds() <= 3610); // At most 60:10
    }

    #[test]
    fn test_ttl_clone_and_copy() {
        let ttl1 = TimeToLive::from(300);
        let ttl2 = ttl1; // Copy
        let ttl3 = ttl1; // Clone

        assert_eq!(ttl1, ttl2);
        assert_eq!(ttl1, ttl3);
        assert_eq!(ttl1.0, 300);
        assert_eq!(ttl2.0, 300);
        assert_eq!(ttl3.0, 300);
    }

    #[test]
    fn test_ttl_zero_deadline() {
        let ttl = TimeToLive::ZERO;
        let deadline = ttl.deadline();
        let now = Utc::now();

        // Zero TTL should have deadline very close to now
        let diff = deadline - now;
        assert!(diff.num_seconds() >= -10);
        assert!(diff.num_seconds() <= 10);
    }

    #[test]
    fn test_ttl_debug() {
        let ttl = TimeToLive::from(600);
        let debug_str = format!("{ttl:?}");
        assert!(debug_str.contains("TimeToLive"));
        assert!(debug_str.contains("600"));
    }
}
