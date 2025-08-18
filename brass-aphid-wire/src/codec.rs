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

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, ErrorKind, Read, Write};

/// This trait defines a source that values can be decoded from.
pub trait DecodeByteSource<T: DecodeValue>: Sized {
    fn decode_value(&self) -> io::Result<(T, Self)>;
    fn decode_value_exact(&self) -> io::Result<T>;
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
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])>;

    /// decode the value from a buffer of bytes, consuming the entire buffer.
    ///
    /// If there is data remaining in the buffer after decoding the value, an
    /// error is returned.
    fn decode_from_exact(buffer: &[u8]) -> std::io::Result<Self> {
        let (value, remaining) = Self::decode_from(buffer)?;
        if remaining.is_empty() {
            Ok(value)
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "unexpected data remaining",
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

    fn decode_from_with_context(
        buffer: &[u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &[u8])>;
}

/// This trait defines a type that can be encoded into bytes.
pub trait EncodeValue: Sized {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()>;

    fn encode_to_vec(&self) -> std::io::Result<Vec<u8>> {
        const AVERAGE_LENGTH_GUESS: usize = 100;

        let mut buffer = Vec::with_capacity(AVERAGE_LENGTH_GUESS);
        self.encode_to(&mut buffer)?;
        Ok(buffer)
    }
}

//////////////////////////// Source + Sink Impls ///////////////////////////////

impl<T: DecodeValue> DecodeByteSource<T> for &[u8] {
    fn decode_value(&self) -> io::Result<(T, Self)> {
        T::decode_from(self)
    }

    fn decode_value_exact(&self) -> io::Result<T> {
        T::decode_from_exact(self)
    }
}

impl<T: EncodeValue> EncodeBytesSink<T> for Vec<u8> {
    fn encode_value(&mut self, value: &T) -> io::Result<()> {
        value.encode_to(self)
    }
}

//////////////////////////// Primitive Impls ///////////////////////////////////

impl DecodeValue for u8 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u8()?;
        Ok((value, buffer))
    }
}

impl DecodeValue for u16 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u16::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl DecodeValue for u32 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u32::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl DecodeValue for u64 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u64::<BigEndian>()?;
        Ok((value, buffer))
    }
}


impl EncodeValue for u8 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&[*self])?;
        Ok(())
    }
}

impl EncodeValue for u16 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl EncodeValue for u32 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl EncodeValue for u64 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

// Implement Decode and Encode for byte arrays

impl<const L: usize> DecodeValue for [u8; L] {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let mut value = [0; L];
        buffer.read_exact(&mut value)?;
        Ok((value, buffer))
    }
}

impl<const L: usize> EncodeValue for [u8; L] {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(self)?;
        Ok(())
    }
}

// Implement Decode and Encode for Option<T>

// Can't safely implement Decode for Option<T>, it requires domain logic to implement.

impl<T: EncodeValue> EncodeValue for Option<T> {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        if let Some(v) = self {
            v.encode_to(buffer)?
        }
        Ok(())
    }
}

impl<T: EncodeValue> EncodeValue for Vec<T> {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
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
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let u24 = buffer.read_u24::<BigEndian>()?;
        Ok((U24(u24), buffer))
    }
}

impl EncodeValue for U24 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
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
