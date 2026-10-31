//! Type-directed writers.
//!
//! `Writer<T>` means "I can write myself out so that the bytes decode as a `T`".
//! A `&[Cipher]` can be written as a `PrefixedList<Cipher, u16>`, a `&[u8]` as a
//! `PrefixedBlob<u8>`, and anything already encodable can be written as itself.
//!
//! A type may implement `Writer<T>` for several `T`. Pick one explicitly with
//! `<W as Writer<T>>::encode_transform(..)`.
//!
//! The lifetime in a marker such as `PrefixedList<'b, ..>` is never used for
//! anything: the marker only names a type. Impls leave it free, so that a bound
//! written with `'static` is satisfied by a borrow of any lifetime.

use crate::codec::{EncodeValue, RawBytes};
use crate::prefixed_list::{
    encode_length_prefixed, PrefixedBlob, PrefixedBlobWriter, PrefixedList,
};

pub trait Writer<T> {
    fn encode_transform(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()>;
}

/// Any type which already implements `EncodeValue` is a writer for itself.
impl<T: EncodeValue> Writer<T> for T {
    fn encode_transform(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        self.encode_to(buffer)
    }
}

/// A slice of `Y` writes as a list of `X` whenever each `Y` writes as an `X`.
///
/// This covers a slice of plain values (`Y == X`, through the identity impl) and
/// a slice of writers (`&[KeyShareWriter]` as a list of `KeyShare`).
impl<'a, 'b, X, Y, L> Writer<PrefixedList<'b, X, L>> for &'a [Y]
where
    Y: Writer<X>,
    L: Default + EncodeValue + TryFrom<usize>,
{
    fn encode_transform(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        encode_length_prefixed::<L>(buffer, |buffer| {
            for item in self.iter() {
                <Y as Writer<X>>::encode_transform(item, buffer)?;
            }
            Ok(())
        })
    }
}

impl<'a, 'b, L> Writer<PrefixedBlob<'b, L>> for &'a [u8]
where
    L: Default + EncodeValue + TryFrom<usize>,
{
    fn encode_transform(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        PrefixedBlobWriter::<L>::new(*self).encode_to(buffer)
    }
}

/// Bytes write as unprefixed bytes.
impl<'a, 'b> Writer<RawBytes<'b>> for &'a [u8] {
    fn encode_transform(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        self.encode_to(buffer)
    }
}

/// Run `write`, then let `inspect` look at exactly the bytes that it wrote.
///
/// A derived writer only knows that a field *can* write itself as a `Protocol`,
/// not what the value is. Messages with rules that depend on a field's value
/// (extensions only for some versions, a fixed `random` for a HelloRetryRequest)
/// use this to read the value back from the bytes, and then carry on writing.
///
/// `inspect` can not return anything that borrows from the bytes, since the
/// buffer is written to again afterwards.
pub fn peek_written<R>(
    buffer: &mut std::io::Cursor<&mut [u8]>,
    write: impl FnOnce(&mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()>,
    inspect: impl FnOnce(&[u8]) -> std::io::Result<R>,
) -> std::io::Result<R> {
    let start = buffer.position() as usize;
    write(buffer)?;
    let end = buffer.position() as usize;
    inspect(&buffer.get_ref()[start..end])
}
