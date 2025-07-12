use std::{cmp::Ordering, ops::Add};

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
