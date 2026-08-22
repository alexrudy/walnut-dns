use crate::error::ProtocolError;

#[cfg(test)]
pub(crate) mod bin_tests;

pub mod decoder;
pub mod encoder;
pub mod restrict;

pub use self::decoder::{BinDecoder, DecodeError};
pub use self::encoder::{BinEncoder, EncodedSize, NameEncoding, RDataEncoding};
pub use self::restrict::{Restrict, RestrictedMath, Verified};

pub trait BinEncodable {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtocolError>;

    /// Returns the object in binary form
    fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            self.emit(&mut encoder)?;
        }

        Ok(bytes)
    }
}

pub trait BinDecodable<'r>: Sized {
    fn read(reader: &mut BinDecoder<'r>) -> Result<Self, DecodeError>;

    /// Returns the object in binary form
    fn from_bytes(bytes: &'r [u8]) -> Result<Self, DecodeError> {
        let mut decoder = BinDecoder::new(bytes);
        Self::read(&mut decoder)
    }
}

impl BinEncodable for u16 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtocolError> {
        encoder.emit_u16(*self)?;
        Ok(())
    }
}

impl BinDecodable<'_> for u16 {
    fn read(decoder: &mut BinDecoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_u16().map(Restrict::unverified)
    }
}

impl BinEncodable for i32 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtocolError> {
        encoder.emit_i32(*self)?;
        Ok(())
    }
}

impl<'r> BinDecodable<'r> for i32 {
    fn read(decoder: &mut BinDecoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_i32().map(Restrict::unverified)
    }
}

impl BinEncodable for u32 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtocolError> {
        encoder.emit_u32(*self)?;
        Ok(())
    }
}

impl BinDecodable<'_> for u32 {
    fn read(decoder: &mut BinDecoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_u32().map(Restrict::unverified)
    }
}

impl BinEncodable for Vec<u8> {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtocolError> {
        encoder.emit_vec(self.as_slice())?;
        Ok(())
    }
}
