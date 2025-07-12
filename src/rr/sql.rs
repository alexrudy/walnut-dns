use hickory_proto::{
    ProtoError,
    rr::{LowerName, Name},
};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, Value, ValueRef};
use std::{ops::Deref, str};

/// Wrapper type for Name to provide SQLite trait implementations
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SqlName(Name);

impl From<Name> for SqlName {
    fn from(name: Name) -> Self {
        SqlName(name)
    }
}

impl From<LowerName> for SqlName {
    fn from(name: LowerName) -> Self {
        SqlName(name.into())
    }
}

impl From<SqlName> for Name {
    fn from(wrapper: SqlName) -> Self {
        wrapper.0
    }
}

impl Deref for SqlName {
    type Target = Name;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToSql for SqlName {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'static>> {
        Ok(ToSqlOutput::Owned(Value::Text(self.0.to_utf8())))
    }
}

impl FromSql for SqlName {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Text(value) => {
                let name = Name::from_utf8(
                    str::from_utf8(value)
                        .map_err(FromSqlError::other)?,
                )
                .map_err(FromSqlError::other)?;
                Ok(SqlName(name))
            }
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

/// Extension trait to add utility methods for Name
pub trait NameExt {
    fn parse_soa_email(email: impl AsRef<str>) -> Result<Self, ProtoError>
    where
        Self: Sized;
}

impl NameExt for Name {
    fn parse_soa_email(email: impl AsRef<str>) -> Result<Self, ProtoError> {
        let (local_part, domain) =
            email
                .as_ref()
                .split_once('@')
                .ok_or(hickory_proto::ProtoErrorKind::Message(
                    "Email does not contain '@'",
                ))?;
        Name::from_utf8(format!("{}.{domain}", local_part.replace(".", r"\.")))
    }
}
