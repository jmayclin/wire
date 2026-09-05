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

use std::io::{self, Cursor, ErrorKind, Read, Write};

use anyhow::Error;

pub trait CursorSplit<'a> {
    fn split(self: Self) -> (&'a mut [u8], &'a mut [u8]);
}

impl<'a> CursorSplit<'a> for std::io::Cursor<&'a mut [u8]> {
    fn split(self) -> (&'a mut [u8], &'a mut [u8]) {
        let position = self.position() as usize;
        let inner = self.into_inner();
        inner.split_at_mut(position)
    }
}

/// This trait defines a source that values can be decoded from.
pub trait DecodeByteSource: Sized {
    fn decode_value<T: DecodeValue>(self) -> io::Result<(T, Self)>;
    fn decode_value_exact<T: DecodeValue>(self) -> io::Result<T>;
    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
    fn pull(self, length: usize) -> io::Result<(Self, Self)>;
    fn freeze(&self) -> &[u8];
}

/// This trait defines a sink that values can be encoded to. Currently this is
/// only implemented for `Vec<u8>`.
///
/// This is less efficient than relying on buffers, because encode calls might
/// result in allocations. But the benefit is that it's much more ergonomic.
pub trait EncodeBytesSink<T: EncodeValue>: Sized {
    fn encode_value(&mut self, value: &T) -> io::Result<()>;
}

/// This trait defines a type that can be decoded from bytes.
pub trait DecodeValue: Sized {
    /// decode the value from a buffer of bytes, returning any remaining bytes.
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)>;

    /// decode the value from a buffer of bytes, consuming the entire buffer.
    ///
    /// If there is data remaining in the buffer after decoding the value, an
    /// error is returned.
    fn decode_from_exact<S: DecodeByteSource>(buffer: S) -> std::io::Result<Self> {
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
pub trait DecodeValueWithContext: Sized {
    type Context;

    fn decode_from_with_context<S: DecodeByteSource>(
        buffer: S,
        context: Self::Context,
    ) -> std::io::Result<(Self, S)>;
}

/// This trait defines a type that can be encoded into bytes.
pub trait EncodeValue: Sized {
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
                        return Err(std::io::Error::new(ErrorKind::InvalidData, "buffer would be too big"));
                    }
                    buffer = vec![0; buffer.len() * 2];
                    cursor = std::io::Cursor::new(&mut buffer);
                },
                Err(e) => {
                    return Err(e);
                }
            }
        };
        let written = cursor.position();
        buffer.truncate(written as usize);
        Ok(buffer)
    }
}

//////////////////////////// Source + Sink Impls ///////////////////////////////

impl DecodeByteSource for &[u8] {
    fn decode_value<T: DecodeValue>(self) -> io::Result<(T, Self)> {
        T::decode_from(self)
    }

    fn decode_value_exact<T: DecodeValue>(self) -> io::Result<T> {
        T::decode_from_exact(self)
    }

    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn pull(self, length: usize) -> io::Result<(Self, Self)> {
        if self.len() < length {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "no bytes remain",
            ));
        }
        Ok(self.split_at(length))
    }

    fn freeze(&self) -> &[u8] {
        self
    }
}

impl DecodeByteSource for &mut [u8] {
    fn decode_value<T: DecodeValue>(self) -> io::Result<(T, Self)> {
        T::decode_from(self)
    }

    fn decode_value_exact<T: DecodeValue>(self) -> io::Result<T> {
        T::decode_from_exact(self)
    }

    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn pull(self, length: usize) -> io::Result<(Self, Self)> {
        if self.len() < length {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "no bytes remain",
            ));
        }
        Ok(self.split_at_mut(length))
    }

    fn freeze(&self) -> &[u8] {
        self
    }
}

impl<T: EncodeValue> EncodeBytesSink<T> for Cursor<&mut [u8]> {
    fn encode_value(&mut self, value: &T) -> io::Result<()> {
        value.encode_to(self)
    }
}

//////////////////////////// Primitive Impls ///////////////////////////////////
impl DecodeValue for u8 {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.pull(std::mem::size_of::<Self>())?;
        let value = value.freeze();
        let value: [u8; std::mem::size_of::<Self>()] = value.try_into().unwrap();
        let value = Self::from_be_bytes(value);
        Ok((value, remaining))
    }
}

impl DecodeValue for u16 {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.pull(std::mem::size_of::<Self>())?;
        let value = value.freeze();
        let value: [u8; std::mem::size_of::<Self>()] = value.try_into().unwrap();
        let value = Self::from_be_bytes(value);
        Ok((value, remaining))
    }
}

impl DecodeValue for u32 {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.pull(std::mem::size_of::<Self>())?;
        let value = value.freeze();
        let value: [u8; std::mem::size_of::<Self>()] = value.try_into().unwrap();
        let value = Self::from_be_bytes(value);
        Ok((value, remaining))
    }
}

impl DecodeValue for u64 {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.pull(std::mem::size_of::<Self>())?;
        let value = value.freeze();
        let value: [u8; std::mem::size_of::<Self>()] = value.try_into().unwrap();
        let value = Self::from_be_bytes(value);
        Ok((value, remaining))
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

impl<const L: usize> DecodeValue for [u8; L] {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.pull(L)?;
        let value = value.freeze().try_into().map_err(|e| {
            std::io::Error::new(ErrorKind::InvalidData, "unable to convert to array")
        })?;

        Ok((value, remaining))
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

/// u24 is not defined in the rust standard library but it is relatively common
/// in TLS messages. You can use `codec::U24` in TLS messages definitions to easily
/// encode or decode the correct value.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct U24(pub u32);

impl DecodeValue for U24 {
    fn decode_from<S: DecodeByteSource>(mut buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.pull(3)?;
        let value = value.freeze();
        let value: [u8; 3] = value.try_into().map_err(|e| {
            std::io::Error::new(ErrorKind::InvalidData, "unable to convert to array")
        })?;

        // TODO: check the ordering on this one
        let value = u32::from_be_bytes([0, value[0], value[1], value[2]]);
        Ok((U24(value), remaining))
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

impl TryFrom<usize> for U24 {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let u32 = value as u32;
        assert_eq!(u32.to_be_bytes()[0], 0);
        Ok(Self(u32))
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

        let (_, remaining): (RecordHeader, &[u8]) =
            buffer.decode_value::<RecordHeader>().unwrap();
        assert_eq!(remaining, &[1, 2, 3]);
    }

    #[test]
    fn mutable_decode() {
        let mut buffer = record_header_then_123();
        let buffer: &mut [u8] = buffer.as_mut_slice();

        let (_, remaining): (RecordHeader, &mut [u8]) = buffer.decode_value().unwrap();
        assert_eq!(remaining, &mut [1, 2, 3]);
    }
}
