use std::{cmp::Ordering, ops::Add};

use rusqlite::{ToSql, types::FromSql};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SerialNumber(u32);

impl SerialNumber {
    pub const ZERO: SerialNumber = SerialNumber(0);

    pub fn get(&self) -> u32 {
        self.0
    }
}

impl From<u32> for SerialNumber {
    fn from(value: u32) -> Self {
        SerialNumber(value)
    }
}

/// Serial Number Addition, see RFC 1982, section 3.1
///
/// The result is a wrapping add.
impl Add for SerialNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Add<u32> for SerialNumber {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

/// Serial Number Comparison, see RFC 1982, section 3.2
impl PartialOrd for SerialNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        const SERIAL_BITS_HALF: u32 = 1 << (u32::BITS - 1);

        let i1 = self.0;
        let i2 = other.0;

        if i1 == i2 {
            Some(Ordering::Equal)
        } else if (i1 < i2 && (i2 - i1) < SERIAL_BITS_HALF)
            || (i1 > i2 && (i1 - i2) > SERIAL_BITS_HALF)
        {
            Some(Ordering::Less)
        } else if (i1 < i2 && (i2 - i1) > SERIAL_BITS_HALF)
            || (i1 > i2 && (i1 - i2) < SERIAL_BITS_HALF)
        {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl ToSql for SerialNumber {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for SerialNumber {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Integer(i) => Ok(SerialNumber(i as u32)),
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_number_creation() {
        let sn = SerialNumber::from(123);
        assert_eq!(sn.get(), 123);

        let zero = SerialNumber::ZERO;
        assert_eq!(zero.get(), 0);
    }

    #[test]
    fn test_serial_number_addition() {
        let sn1 = SerialNumber::from(10);
        let sn2 = SerialNumber::from(20);
        let result = sn1 + sn2;
        assert_eq!(result.get(), 30);
    }

    #[test]
    fn test_serial_number_wrapping_addition() {
        let sn1 = SerialNumber::from(u32::MAX);
        let sn2 = SerialNumber::from(1);
        let result = sn1 + sn2;
        assert_eq!(result.get(), 0); // Wrapping addition
    }

    #[test]
    fn test_serial_number_equality() {
        let sn1 = SerialNumber::from(42);
        let sn2 = SerialNumber::from(42);
        let sn3 = SerialNumber::from(43);

        assert_eq!(sn1, sn2);
        assert_ne!(sn1, sn3);
        assert_eq!(sn1.partial_cmp(&sn2), Some(Ordering::Equal));
    }

    #[test]
    fn test_serial_number_comparison_simple() {
        let sn1 = SerialNumber::from(10);
        let sn2 = SerialNumber::from(20);

        assert_eq!(sn1.partial_cmp(&sn2), Some(Ordering::Less));
        assert_eq!(sn2.partial_cmp(&sn1), Some(Ordering::Greater));
    }

    #[test]
    fn test_serial_number_comparison_wrap_around() {
        // Test RFC 1982 serial number arithmetic wrap-around behavior
        let sn1 = SerialNumber::from(100);
        let sn2 = SerialNumber::from(100 + 0x40000000); // Within valid comparison range

        // According to RFC 1982, comparison should be well-defined within valid range
        let result = sn1.partial_cmp(&sn2);
        assert_eq!(result, Some(std::cmp::Ordering::Less));

        // Test the boundary case that results in undefined comparison
        let sn3 = SerialNumber::from(0);
        let sn4 = SerialNumber::from(0x80000000); // Exactly half the range - undefined
        let result_undefined = sn3.partial_cmp(&sn4);
        assert_eq!(result_undefined, None); // Should be undefined
    }

    #[test]
    fn test_serial_number_comparison_undefined() {
        // Test case where comparison is undefined (exactly half the range apart)
        let sn1 = SerialNumber::from(0);
        let sn2 = SerialNumber::from(0x80000000); // Exactly half the range

        // Should return None for undefined comparison
        assert_eq!(sn1.partial_cmp(&sn2), None);
    }

    #[test]
    fn test_serial_number_rfc_examples() {
        // Examples from RFC 1982
        let s = SerialNumber::from(10);
        let s_plus_1 = SerialNumber::from(11);
        let s_plus_100 = SerialNumber::from(110);

        assert_eq!(s.partial_cmp(&s_plus_1), Some(Ordering::Less));
        assert_eq!(s.partial_cmp(&s_plus_100), Some(Ordering::Less));
        assert_eq!(s_plus_1.partial_cmp(&s_plus_100), Some(Ordering::Less));
    }

    #[test]
    fn test_serial_number_clone_and_copy() {
        let sn1 = SerialNumber::from(42);
        let sn2 = sn1; // Copy
        let sn3 = sn1; // Clone

        assert_eq!(sn1, sn2);
        assert_eq!(sn1, sn3);
        assert_eq!(sn1.get(), 42);
        assert_eq!(sn2.get(), 42);
        assert_eq!(sn3.get(), 42);
    }
}
