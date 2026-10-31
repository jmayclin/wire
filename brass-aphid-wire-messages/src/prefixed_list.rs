//! Length prefixed blobs and lists.
//!
//! Decoding never allocates: both types borrow from the buffer they were decoded
//! from. Lists are validated once during `decode_from`, and then decode their
//! items lazily as they are iterated.

use std::{
    any::type_name,
    fmt::Debug,
    io::{ErrorKind, Write},
    marker::PhantomData,
};

use crate::codec::{take, DecodeByteSource, DecodeValue, EncodeValue};

/// An opaque list of bytes, where the size of the list is prefixed on the wire as `L`.
#[derive(Clone, PartialEq, Eq)]
pub struct PrefixedBlob<'a, L>(pub PrefixedList<'a, u8, L>);

impl<'a, L> PrefixedBlob<'a, L> {
    pub fn blob(&self) -> &'a [u8] {
        self.0.buffer
    }
}

impl<L> Debug for PrefixedBlob<'_, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrefixedBlob")
            .field(&self.blob().len())
            .finish()
    }
}

impl<'a, L> DecodeValue<'a> for PrefixedBlob<'a, L>
where
    L: Copy + Into<usize> + DecodeValue<'a>,
{
    fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        // Every byte is a valid `u8`, so unlike `PrefixedList<T, L>` there is no
        // need to walk the contents to validate them.
        let (length, remaining): (L, &'a [u8]) = buffer.decode_value()?;
        let (contents, remaining) = take_list_contents::<u8, L>(remaining, length)?;
        let list = PrefixedList {
            length,
            buffer: contents,
            items: PhantomData,
        };
        Ok((Self(list), remaining))
    }
}

impl<L> EncodeValue for PrefixedBlob<'_, L>
where
    L: Copy + EncodeValue,
{
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        self.0.encode_to(buffer)
    }
}

/// A list of `T`, where the size of the list is prefixed on the wire as `L`.
///
/// Note that size != count. A list of 100 u16's, has count 100 and size 200.
pub struct PrefixedList<'a, T, L> {
    length: L,
    /// the contents of the list, excluding the length prefix
    buffer: &'a [u8],
    items: PhantomData<T>,
}

// Implemented by hand, because deriving would add `T: Clone`, `T: PartialEq`,
// etc. bounds that are meaningless for a `PhantomData<T>`.

impl<T, L: Clone> Clone for PrefixedList<'_, T, L> {
    fn clone(&self) -> Self {
        Self {
            length: self.length.clone(),
            buffer: self.buffer,
            items: PhantomData,
        }
    }
}

impl<T, L: PartialEq> PartialEq for PrefixedList<'_, T, L> {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length && self.buffer == other.buffer
    }
}

impl<T, L: Eq> Eq for PrefixedList<'_, T, L> {}

impl<'a, T, L> Debug for PrefixedList<'a, T, L>
where
    T: DecodeValue<'a> + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T, L> PrefixedList<'a, T, L> {
    /// The raw, undecoded bytes of the list, excluding the length prefix.
    pub fn raw(&self) -> &'a [u8] {
        self.buffer
    }
}

impl<'a, T: DecodeValue<'a>, L> PrefixedList<'a, T, L> {
    /// Iterate over the items in the list, decoding each one as it is yielded.
    ///
    /// The iterator borrows from the original buffer, not from `self`.
    pub fn iter(&self) -> PrefixedListIter<'a, T> {
        PrefixedListIter {
            buffer: self.buffer,
            items: PhantomData,
        }
    }
}

impl<'a, T: DecodeValue<'a>, L> IntoIterator for &PrefixedList<'a, T, L> {
    type Item = T;
    type IntoIter = PrefixedListIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the items of a [`PrefixedList`].
pub struct PrefixedListIter<'a, T> {
    buffer: &'a [u8],
    items: PhantomData<T>,
}

impl<'a, T: DecodeValue<'a>> Iterator for PrefixedListIter<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }
        // PrefixedList::decode_from walked every item before constructing the
        // list, and the buffer is immutable, so this can not fail.
        let (item, remaining) = T::decode_from(self.buffer)
            .expect("PrefixedList contents were validated when the list was decoded");
        self.buffer = remaining;
        Some(item)
    }
}

/// Split the `length` bytes of list contents off the front of `buffer`.
fn take_list_contents<T, L>(buffer: &[u8], length: L) -> std::io::Result<(&[u8], &[u8])>
where
    L: Copy + Into<usize>,
{
    let length: usize = length.into();
    take(buffer, length).map_err(|_| {
        std::io::Error::new(
            ErrorKind::UnexpectedEof,
            format!(
                "not enough data available for PrefixedList of {} with {} length",
                type_name::<T>(),
                type_name::<L>()
            ),
        )
    })
}

impl<'a, T, L> DecodeValue<'a> for PrefixedList<'a, T, L>
where
    L: Copy + Into<usize> + DecodeValue<'a>,
    T: DecodeValue<'a>,
{
    fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let (length, remaining): (L, &'a [u8]) = buffer.decode_value()?;
        let (contents, remaining) = take_list_contents::<T, L>(remaining, length)?;

        // Pre-validate the contents so that iterating over them is infallible.
        // This decodes every item once, but doesn't store any of them.
        let mut cursor = contents;
        while !cursor.is_empty() {
            let (_item, rest) = T::decode_from(cursor)?;
            // an item that consumes no bytes would loop forever
            if rest.len() == cursor.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "{} consumed no bytes while decoding PrefixedList",
                        type_name::<T>()
                    ),
                ));
            }
            cursor = rest;
        }

        let list = Self {
            length,
            buffer: contents,
            items: PhantomData,
        };
        Ok((list, remaining))
    }
}

impl<T, L> EncodeValue for PrefixedList<'_, T, L>
where
    L: Copy + EncodeValue,
{
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        // The contents are already in their wire format, so they are copied as is.
        self.length.encode_to(buffer)?;
        buffer.write_all(self.buffer)
    }
}

//////////////////////////////// Writers ///////////////////////////////////////

/// Write an `L` length prefix, then whatever `body` writes, then go back and
/// fill in the prefix with the number of bytes that `body` wrote.
///
/// This is the one place that does the "skip, write, backpatch" dance.
pub fn encode_length_prefixed<L>(
    buffer: &mut std::io::Cursor<&mut [u8]>,
    body: impl FnOnce(&mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()>,
) -> std::io::Result<()>
where
    L: Default + EncodeValue + TryFrom<usize>,
{
    // reserve space for the length with a placeholder
    let prefix_start = buffer.position();
    L::default().encode_to(buffer)?;
    let body_start = buffer.position();

    body(buffer)?;
    let body_end = buffer.position();

    let body_len = (body_end - body_start) as usize;
    let length: L = body_len.try_into().map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{body_len} bytes does not fit in a {} length prefix",
                type_name::<L>()
            ),
        )
    })?;

    buffer.set_position(prefix_start);
    length.encode_to(buffer)?;
    if buffer.position() != body_start {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "length prefix changed size after being filled in",
        ));
    }
    buffer.set_position(body_end);
    Ok(())
}

/// Encodes `blob` prefixed with its encoded length as `L`.
///
/// `E` is anything encodable. The default, `[u8]`, is a plain byte string.
pub struct PrefixedBlobWriter<'a, L, E: ?Sized = [u8]> {
    blob: &'a E,
    length: PhantomData<L>,
}

impl<'a, L, E: ?Sized> PrefixedBlobWriter<'a, L, E> {
    pub fn new(blob: &'a E) -> Self {
        Self {
            blob,
            length: PhantomData,
        }
    }
}

impl<L, E> EncodeValue for PrefixedBlobWriter<'_, L, E>
where
    L: Default + EncodeValue + TryFrom<usize>,
    E: EncodeValue + ?Sized,
{
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        encode_length_prefixed::<L>(buffer, |buffer| self.blob.encode_to(buffer))
    }
}

/// Encodes each of `items` back to back, prefixed with their total encoded
/// size as `L`.
pub struct PrefixedListWriter<'a, T, L> {
    items: &'a [T],
    length: PhantomData<L>,
}

impl<'a, T, L> PrefixedListWriter<'a, T, L> {
    pub fn new(items: &'a [T]) -> Self {
        Self {
            items,
            length: PhantomData,
        }
    }
}

impl<T, L> EncodeValue for PrefixedListWriter<'_, T, L>
where
    T: EncodeValue,
    L: Default + EncodeValue + TryFrom<usize>,
{
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        encode_length_prefixed::<L>(buffer, |buffer| {
            for item in self.items {
                item.encode_to(buffer)?;
            }
            Ok(())
        })
    }
}
