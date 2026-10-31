//! The `codec` module contains traits that are used for serializing and deserializing
//! various structs.
//!
//! ### Compare To
//! [`s2n_codec`](https://crates.io/crates/s2n-codec) provides much richer functionality,
//! but that richer functionality comes at the cost of generic lifetimes, non-std
//! structs, and more generics. For example, s2n-codec requires a specialized
//! `DecoderBuffer<'a>`, but this codec just uses a plain byte slice `&[u8]`.
//!
//! [`binary_serde`](https://crates.io/crates/binary_serde) doesn't support dynamically
//! sized types like `Vec<T>`, which makes it a no-go for TLS use cases, because
//! TLS is _filled_ with lists of items.
//!
//! ### Future Development
//! Ideally all of the codec stuff would be moved to a different crate, and we'd
//! have proc macros to derive the `EncodeValue` and `DecodeValue` traits.
//!
//! ### &[u8] vs &mut [u8]
//! I tries making the codec generic over a DecodeByteSource, which was implemented
//! by &[u8] and &mut [u8], but that felt kinda icky. And made things much more
//! generic and nasty. I prefer the simple version: everything decodes from a plain `&[u8]`.

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, Cursor, ErrorKind, Read, Write};

pub trait CursorSplit<'a> {
    fn split(self) -> (&'a mut [u8], &'a mut [u8]);
}

impl<'a> CursorSplit<'a> for std::io::Cursor<&'a mut [u8]> {
    fn split(self) -> (&'a mut [u8], &'a mut [u8]) {
        let position = self.position() as usize;
        let inner = self.into_inner();
        inner.split_at_mut(position)
    }
}

/// This trait defines a source that values can be decoded from. It is only
/// implemented for `&[u8]`, and exists to make chained decoding ergonomic:
/// `let (value, remaining) = buffer.decode_value()?;`
pub trait DecodeByteSource<'a>: Sized {
    fn decode_value<T: DecodeValue<'a>>(&self) -> io::Result<(T, &'a [u8])>;
    fn decode_value_exact<T: DecodeValue<'a>>(&self) -> io::Result<T>;
    fn decode_value_context<T: DecodeValueWithContext<'a>>(
        &self,
        context: T::Context,
    ) -> io::Result<(T, &'a [u8])>;
    fn decode_value_context_exact<T: DecodeValueWithContext<'a>>(
        &self,
        context: T::Context,
    ) -> io::Result<T>;
}

/// This trait defines a sink that values can be encoded to. It is implemented
/// for `Cursor<&mut [u8]>`.
pub trait EncodeBytesSink<T: EncodeValue> {
    fn encode_value(&mut self, value: &T) -> io::Result<()>;
}

/// This trait defines a type that can be decoded from bytes.
///
/// The `'a` lifetime is the lifetime of the buffer being decoded. Types that
/// borrow from the buffer (e.g. `PrefixedBlob<'a, L>`) are tied to it.
pub trait DecodeValue<'a>: Sized {
    /// decode the value from a buffer of bytes, returning any remaining bytes.
    fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])>;

    /// decode the value from a buffer of bytes, consuming the entire buffer.
    ///
    /// If there is data remaining in the buffer after decoding the value, an
    /// error is returned.
    fn decode_from_exact(buffer: &'a [u8]) -> std::io::Result<Self> {
        let (value, remaining) = Self::decode_from(buffer)?;
        if remaining.is_empty() {
            Ok(value)
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "unexpected data remaining: {} bytes to be read",
                    remaining.len()
                ),
            ))
        }
    }
}

/// This trait defines a type that can only be decoded with external context.
///
/// This is necessary because TLS hates you, and thinks that parsing should be
/// difficult.
///
/// Example
/// - ServerKeyExchange: you need to know the selected cipher to parse this message,
///   because it branches on cipher auth methods, but the cipher auth method isn't
///   included in the actual message.
/// - Finished: the signature in the Finished message is _not_ length prefixed.
///   You need to know what hash the connection is using, and that isn't specified
///   as part of the Finished message.
pub trait DecodeValueWithContext<'a>: Sized {
    type Context;

    fn decode_from_with_context(
        buffer: &'a [u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &'a [u8])>;

    fn decode_from_with_context_exact(
        buffer: &'a [u8],
        context: Self::Context,
    ) -> std::io::Result<Self> {
        let (value, remaining) = Self::decode_from_with_context(buffer, context)?;
        if remaining.is_empty() {
            Ok(value)
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "unexpected data remaining: {} bytes to be read",
                    remaining.len()
                ),
            ))
        }
    }
}

/// This trait defines a type that can be encoded into bytes.
pub trait EncodeValue {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()>;

    fn encode_to_vec(&self) -> std::io::Result<Vec<u8>> {
        const AVERAGE_LENGTH_GUESS: usize = 100;

        let mut buffer = vec![0; AVERAGE_LENGTH_GUESS];
        let mut cursor = std::io::Cursor::new(buffer.as_mut_slice());
        loop {
            match self.encode_to(&mut cursor) {
                Ok(_) => break,
                Err(e) if e.kind() == ErrorKind::WriteZero => {
                    let new_len = buffer.len() * 2;
                    if new_len > 64_000 {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "buffer would be too big",
                        ));
                    }
                    buffer = vec![0; buffer.len() * 2];
                    cursor = std::io::Cursor::new(&mut buffer);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        let written = cursor.position();
        buffer.truncate(written as usize);
        Ok(buffer)
    }
}

//////////////////////////// Source + Sink Impls ///////////////////////////////

impl<'a> DecodeByteSource<'a> for &'a [u8] {
    fn decode_value<T: DecodeValue<'a>>(&self) -> io::Result<(T, &'a [u8])> {
        T::decode_from(*self)
    }

    fn decode_value_exact<T: DecodeValue<'a>>(&self) -> io::Result<T> {
        T::decode_from_exact(*self)
    }

    fn decode_value_context<T: DecodeValueWithContext<'a>>(
        &self,
        context: T::Context,
    ) -> io::Result<(T, &'a [u8])> {
        T::decode_from_with_context(*self, context)
    }

    fn decode_value_context_exact<T: DecodeValueWithContext<'a>>(
        &self,
        context: T::Context,
    ) -> io::Result<T> {
        T::decode_from_with_context_exact(*self, context)
    }
}

impl<T: EncodeValue> EncodeBytesSink<T> for Cursor<&mut [u8]> {
    fn encode_value(&mut self, value: &T) -> io::Result<()> {
        value.encode_to(self)
    }
}

/// Split `length` bytes off the front of `buffer`, returning `(taken, remaining)`.
///
/// Errors if fewer than `length` bytes are available.
pub fn take<'a>(buffer: &'a [u8], length: usize) -> io::Result<(&'a [u8], &'a [u8])> {
    if buffer.len() < length {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "no bytes remain"));
    }
    Ok(buffer.split_at(length))
}

//////////////////////////// Primitive Impls ///////////////////////////////////
impl<'a> DecodeValue<'a> for u8 {
    fn decode_from(mut buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let value = buffer.read_u8()?;
        Ok((value, buffer))
    }
}

impl<'a> DecodeValue<'a> for u16 {
    fn decode_from(mut buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let value = buffer.read_u16::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl<'a> DecodeValue<'a> for u32 {
    fn decode_from(mut buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let value = buffer.read_u32::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl<'a> DecodeValue<'a> for u64 {
    fn decode_from(mut buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let value = buffer.read_u64::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl EncodeValue for u8 {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(&[*self])?;
        Ok(())
    }
}

impl EncodeValue for u16 {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl EncodeValue for u32 {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl EncodeValue for u64 {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

// Implement Decode and Encode for byte arrays

impl<'a, const L: usize> DecodeValue<'a> for [u8; L] {
    fn decode_from(mut buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let mut value = [0; L];
        buffer.read_exact(&mut value)?;
        Ok((value, buffer))
    }
}

/// A byte slice encodes as exactly its bytes, with no length prefix.
impl EncodeValue for [u8] {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(self)?;
        Ok(())
    }
}

impl<const L: usize> EncodeValue for [u8; L] {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(self)?;
        Ok(())
    }
}

// Implement Decode and Encode for Option<T>

// Can't safely implement Decode for Option<T>, it requires domain logic to implement.

impl<T: EncodeValue> EncodeValue for Option<T> {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        if let Some(v) = self {
            v.encode_to(buffer)?
        }
        Ok(())
    }
}

impl<T: EncodeValue> EncodeValue for Vec<T> {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        for item in self {
            item.encode_to(buffer)?;
        }
        Ok(())
    }
}

/// Bytes with no length prefix. The length comes from somewhere else, so this is
/// only ever decoded with context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawBytes<'a>(pub &'a [u8]);

impl EncodeValue for RawBytes<'_> {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        buffer.write_all(self.0)
    }
}

/// u24 is not defined in the rust standard library but it is relatively common
/// in TLS messages. You can use `codec::U24` in TLS messages definitions to easily
/// encode or decode the correct value.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct U24(pub u32);

impl<'a> DecodeValue<'a> for U24 {
    fn decode_from(mut buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let u24 = buffer.read_u24::<BigEndian>()?;
        Ok((U24(u24), buffer))
    }
}

impl EncodeValue for U24 {
    fn encode_to(&self, buffer: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        let bytes = self.0.to_be_bytes();
        // nothing should be in the most significant byte
        assert_eq!(bytes[0], 0);
        buffer.write_all(&bytes[1..])?;
        Ok(())
    }
}

impl U24 {
    pub const MAX: usize = 0xFF_FFFF;
}

impl TryFrom<usize> for U24 {
    type Error = ();

    /// Fails, rather than truncating, if the value doesn't fit in 24 bits.
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > Self::MAX {
            Err(())
        } else {
            Ok(Self(value as u32))
        }
    }
}

impl From<U24> for usize {
    fn from(val: U24) -> Self {
        val.0 as _
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        codec::{DecodeByteSource, EncodeValue},
        protocol::RecordHeader,
    };

    fn record_header_then_123() -> Vec<u8> {
        let record_header = RecordHeader {
            content_type: crate::protocol::ContentType::ApplicationData,
            protocol_version: crate::iana::Protocol::TLSv1_2,
            record_length: 123,
        };
        let mut bytes = record_header.encode_to_vec().unwrap();
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes
    }

    #[test]
    fn immutable_decode() {
        let buffer = record_header_then_123();
        let buffer: &[u8] = buffer.as_slice();

        let (_, remaining): (RecordHeader, &[u8]) = buffer.decode_value().unwrap();
        assert_eq!(remaining, &[1, 2, 3]);
    }
}
