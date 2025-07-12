use std::{fmt, ops::Deref, str::FromStr};

use hickory_proto::ProtoError;
use rusqlite::types::{FromSql, ToSql};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(hickory_proto::rr::Name);

impl Deref for Name {
    type Target = hickory_proto::rr::Name;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Name {
    pub fn from_utf8(value: String) -> Result<Self, ProtoError> {
        Ok(Name(hickory_proto::rr::Name::from_utf8(value)?))
    }

    pub fn root() -> Self {
        Name(hickory_proto::rr::Name::root())
    }

    #[allow(dead_code)]
    pub(crate) fn parse_soa_email(
        email: impl AsRef<str>,
    ) -> Result<Self, hickory_proto::ProtoError> {
        let (local_part, domain) =
            email
                .as_ref()
                .split_once('@')
                .ok_or(hickory_proto::ProtoErrorKind::Message(
                    "Email does not contain '@'",
                ))?;
        Name::from_utf8(format!("{}.{domain}", local_part.replace(".", r"\.")))
    }

    pub fn as_lower_ref(&self) -> LowerRef<'_> {
        LowerRef(self)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Name {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Name)
    }
}

impl From<hickory_proto::rr::Name> for Name {
    fn from(value: hickory_proto::rr::Name) -> Self {
        Name(value)
    }
}

impl From<hickory_proto::rr::LowerName> for Name {
    fn from(value: hickory_proto::rr::LowerName) -> Self {
        Name(value.into())
    }
}

impl From<Name> for hickory_proto::rr::Name {
    fn from(value: Name) -> Self {
        value.0
    }
}

impl From<Name> for hickory_proto::rr::LowerName {
    fn from(value: Name) -> Self {
        hickory_proto::rr::LowerName::from(value.0)
    }
}

impl From<&Name> for hickory_proto::rr::LowerName {
    fn from(value: &Name) -> Self {
        hickory_proto::rr::LowerName::new(&value.0)
    }
}

impl ToSql for Name {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'static>> {
        Ok(rusqlite::types::ToSqlOutput::Owned(
            rusqlite::types::Value::Text(self.0.to_utf8()),
        ))
    }
}

impl FromSql for Name {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Text(value) => Name::from_utf8(
                str::from_utf8(value)
                    .map_err(rusqlite::types::FromSqlError::other)?
                    .to_string(),
            )
            .map_err(rusqlite::types::FromSqlError::other),
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialOrd, Ord)]
pub struct Lower(Name);

impl Lower {
    pub fn as_lower_ref(&'_ self) -> LowerRef<'_> {
        LowerRef(&self.0)
    }
}

impl Deref for Lower {
    type Target = hickory_proto::rr::Name;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for Lower {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl PartialEq<Name> for Lower {
    fn eq(&self, other: &Name) -> bool {
        self.0.to_lowercase() == other.to_lowercase()
    }
}

impl From<Name> for Lower {
    fn from(value: Name) -> Self {
        Lower(value)
    }
}

impl From<Lower> for Name {
    fn from(value: Lower) -> Self {
        value.0
    }
}

impl From<hickory_proto::rr::LowerName> for Lower {
    fn from(value: hickory_proto::rr::LowerName) -> Self {
        Lower(value.into())
    }
}

impl From<hickory_proto::rr::Name> for Lower {
    fn from(value: hickory_proto::rr::Name) -> Self {
        Lower(value.into())
    }
}

impl ToSql for Lower {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl AsRef<Name> for Lower {
    fn as_ref(&self) -> &Name {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialOrd, Ord)]
pub struct LowerRef<'n>(&'n Name);

impl fmt::Display for LowerRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'n> PartialEq for LowerRef<'n> {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl<'n> PartialEq<Name> for LowerRef<'n> {
    fn eq(&self, other: &Name) -> bool {
        self.0.to_lowercase() == other.to_lowercase()
    }
}

impl<'n> PartialEq<Lower> for LowerRef<'n> {
    fn eq(&self, other: &Lower) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl<'n> From<&'n Name> for LowerRef<'n> {
    fn from(value: &'n Name) -> Self {
        LowerRef(value)
    }
}

impl AsRef<Name> for LowerRef<'_> {
    fn as_ref(&self) -> &Name {
        self.0
    }
}

impl ToSql for LowerRef<'_> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}
