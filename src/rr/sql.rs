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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;

    #[test]
    fn test_sql_name_creation() {
        let name = Name::from_utf8("example.com").unwrap();
        let sql_name = SqlName::from(name.clone());
        
        assert_eq!(sql_name.to_utf8(), name.to_utf8());
    }

    #[test]
    fn test_sql_name_conversions() {
        let name = Name::from_utf8("test.example.com").unwrap();
        let sql_name = SqlName::from(name.clone());
        let back_to_name: Name = sql_name.into();
        
        assert_eq!(name, back_to_name);
    }

    #[test]
    fn test_sql_name_from_lower_name() {
        let name = Name::from_utf8("EXAMPLE.COM").unwrap();
        let lower_name = LowerName::from(name);
        let sql_name = SqlName::from(lower_name);
        
        assert!(sql_name.to_utf8().starts_with("example.com"));
    }

    #[test]
    fn test_sql_name_deref() {
        let name = Name::from_utf8("deref.test.com").unwrap();
        let sql_name = SqlName::from(name.clone());
        
        // Test that deref works
        assert_eq!(sql_name.to_utf8(), name.to_utf8());
        assert_eq!(&*sql_name, &name);
    }

    #[test]
    fn test_sql_name_debug() {
        let name = Name::from_utf8("debug.example.com").unwrap();
        let sql_name = SqlName::from(name);
        let debug_str = format!("{:?}", sql_name);
        
        assert!(debug_str.contains("SqlName"));
    }

    #[test]
    fn test_sql_name_ordering() {
        let name1 = Name::from_utf8("a.example.com").unwrap();
        let name2 = Name::from_utf8("b.example.com").unwrap();
        let sql_name1 = SqlName::from(name1);
        let sql_name2 = SqlName::from(name2.clone());
        let sql_name3 = SqlName::from(name2);
        
        assert!(sql_name1 < sql_name2);
        assert_eq!(sql_name2, sql_name3);
    }

    #[test]
    fn test_name_ext_parse_soa_email() {
        let result = Name::parse_soa_email("admin@example.com").unwrap();
        assert!(result.to_utf8().starts_with("admin.example.com"));
    }

    #[test]
    fn test_name_ext_parse_soa_email_with_dots() {
        let result = Name::parse_soa_email("admin.user@example.com").unwrap();
        assert!(result.to_utf8().starts_with("admin\\.user.example.com"));
    }

    #[test]
    fn test_name_ext_parse_soa_email_invalid() {
        let result = Name::parse_soa_email("not-an-email");
        assert!(result.is_err());
    }

    #[test]
    fn test_sql_name_root() {
        let root = Name::root();
        let sql_root = SqlName::from(root);
        assert_eq!(sql_root.to_utf8(), ".");
    }

    #[test]
    fn test_sql_name_clone() {
        let name = Name::from_utf8("clone.test.com").unwrap();
        let sql_name1 = SqlName::from(name);
        let sql_name2 = sql_name1.clone();
        
        assert_eq!(sql_name1, sql_name2);
        assert_eq!(sql_name1.to_utf8(), sql_name2.to_utf8());
    }

    // Note: SQL serialization/deserialization tests would require setting up
    // a test database, which is more complex and better suited for integration tests.
    // The functionality is tested indirectly through the database integration tests.
}
