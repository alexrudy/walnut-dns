//! SQLite Database Identifires
//!
//! For Walnut-DNS, all identifiers are UUID-v4 IDs stored as BASE64-url encoded strings
//! in the databse. (This makes them more readable than when they are stored as Blobs, as the rusqlite
//! UUID feature chooses to do).

macro_rules! impl_id {
    (
    $(#[$outer:meta])*
    pub struct $name:ident
   ) => {
       $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(::uuid::Uuid);

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Create a new unique identifier
            ///
            /// Generates a new UUID v4 for use as a unique identifier in the database.
            ///
            /// # Returns
            ///
            /// A new unique identifier instance
            pub fn new() -> $name {
                $name(::uuid::Uuid::new_v4())
            }
        }

        impl ::std::cmp::Ord for $name {
            fn cmp(&self, other: &$name) -> ::std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl ::std::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.0.as_hyphenated())
            }
        }

        impl ::rusqlite::types::FromSql for $name {
            fn column_result(
                value: ::rusqlite::types::ValueRef<'_>,
            ) -> ::rusqlite::types::FromSqlResult<Self> {
                use ::rusqlite::types::ValueRef::*;
                match value {
                    Text(buf) | Blob(buf) => data_encoding::BASE64URL_NOPAD
                        .decode(buf)
                        .map_err(::rusqlite::types::FromSqlError::other)
                        .and_then(|b| {
                            ::uuid::Uuid::from_slice(&b)
                                .map_err(::rusqlite::types::FromSqlError::other)
                        })
                        .map(|id| $name(id)),
                    _ => Err(::rusqlite::types::FromSqlError::InvalidType),
                }
            }
        }

        impl ::rusqlite::types::ToSql for $name {
            fn to_sql(&self) -> ::rusqlite::Result<::rusqlite::types::ToSqlOutput<'_>> {
                Ok(::rusqlite::types::ToSqlOutput::Owned(
                    ::rusqlite::types::Value::Text(
                        data_encoding::BASE64URL_NOPAD.encode(self.0.as_bytes()),
                    ),
                ))
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = ::uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                ::uuid::Uuid::parse_str(s).map($name)
            }
        }
    };
}

impl_id! {
    #[doc="DNS Zone ID for the SQLite Database"]
    pub struct ZoneID
}

impl_id! {
    #[doc="DNS Record ID for the SQLite Database"]
    pub struct RecordID
}

impl_id! {
    #[doc="DNS Query ID for the SQLite Database"]
    pub struct QueryID
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_zone_id_creation() {
        let id1 = ZoneID::new();
        let id2 = ZoneID::new();

        // Each ID should be unique
        assert_ne!(id1, id2);

        // Default should create a new ID
        let id3 = ZoneID::default();
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_record_id_creation() {
        let id1 = RecordID::new();
        let id2 = RecordID::new();

        // Each ID should be unique
        assert_ne!(id1, id2);

        // Default should create a new ID
        let id3 = RecordID::default();
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_zone_id_ordering() {
        let id1 = ZoneID::new();
        let id2 = ZoneID::new();

        // Should be orderable
        assert!(id1.cmp(&id2) != std::cmp::Ordering::Equal);
        assert_eq!(id1.partial_cmp(&id1), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn test_record_id_display() {
        let id = RecordID::new();
        let display_str = format!("{id}");

        // Should be a valid UUID string with hyphens
        assert!(display_str.len() == 36);
        assert!(display_str.contains('-'));
    }

    #[test]
    fn test_zone_id_from_str() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let id = ZoneID::from_str(uuid_str).unwrap();

        // Converting back to string should match
        assert_eq!(format!("{id}"), uuid_str);
    }

    #[test]
    fn test_record_id_from_str_invalid() {
        let invalid_uuid = "not-a-uuid";
        let result = RecordID::from_str(invalid_uuid);

        // Should fail for invalid UUID
        assert!(result.is_err());
    }

    #[test]
    fn test_zone_id_hash() {
        use std::collections::HashMap;

        let id1 = ZoneID::new();
        let id2 = ZoneID::new();

        let mut map = HashMap::new();
        map.insert(id1, "zone1");
        map.insert(id2, "zone2");

        // Should be able to use as hash keys
        assert_eq!(map.get(&id1), Some(&"zone1"));
        assert_eq!(map.get(&id2), Some(&"zone2"));
    }
}
