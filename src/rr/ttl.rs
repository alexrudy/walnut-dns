use std::fmt;
use std::time::Duration;

use chrono::Utc;

use rusqlite::types::{FromSql, ToSql};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeToLive(u32);

impl TimeToLive {
    pub const MAX: TimeToLive = TimeToLive(u32::MAX);
    pub const MIN: TimeToLive = TimeToLive(u32::MIN);
    pub const ZERO: TimeToLive = TimeToLive(0u32);

    pub fn from_secs(secs: u32) -> Self {
        TimeToLive(secs)
    }

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
