use std::{any::type_name, fmt::Debug, io::ErrorKind};

use anyhow::anyhow;

use crate::codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue};

/// An opaque list of bytes, where the size of the list is prefixed on the wire as `L`.
///
/// This is just a convenience wrapper for `PrefixedList<u8, L>`.
#[derive(Clone, PartialEq, Eq)]
pub struct PrefixedBlob<L>(pub PrefixedList<u8, L>);

impl<L: TryFrom<usize>> PrefixedBlob<L> {
    pub fn new(inner_blob: Vec<u8>) -> Self {
        let length: L = match inner_blob.len().try_into() {
            Ok(length) => length,
            _ => panic!("failed to convert"),
        };

        let list = PrefixedList::<u8, L> {
            length,
            items: inner_blob,
        };
        Self(list)
    }
}

impl<L> PrefixedBlob<L> {
    pub fn blob(&self) -> &[u8] {
        &self.0.items
    }
}

impl<L> Debug for PrefixedBlob<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrefixedBlob")
            .field(&self.blob().len())
            .finish()
    }
}

impl<L> DecodeValue for PrefixedBlob<L>
where
    L: Copy + Into<usize> + DecodeValue,
{
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (inner, remaining) = buffer.decode_value()?;
        Ok((Self(inner), remaining))
    }
}

impl<L> EncodeValue for PrefixedBlob<L>
where
    L: Copy + Into<usize> + TryFrom<usize> + EncodeValue,
{
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.0)?;
        Ok(())
    }
}

/// A list of `T`, where the size of the list is prefixed on the wire as `L`.
///
/// Note that size != count. A list of 100 u16's, has count 100 and size 200.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixedList<T, L> {
    // We could remove the length since it's implicit in the items and their
    // encode implementation, but it makes the writing much uglier because you need
    // to use a "skip write" pattern.
    length: L,
    items: Vec<T>,
}

impl<T, L> PrefixedList<T, L>
where
    L: Copy + Into<usize> + TryFrom<usize>,
{
    /// The size of the list in bytes.
    ///
    /// This is the number of bytes that will be written to the wire, excluding
    /// the length header.
    pub fn size(&self) -> usize {
        self.length.into()
    }

    pub fn list(&self) -> &[T] {
        &self.items
    }

    pub fn into_inner(self) -> Vec<T> {
        self.items
    }

    pub fn new(elements: Vec<T>) -> Self {
        Self {
            length: elements.len().try_into().unwrap_or_else(|_| panic!("bad")),
            items: elements,
        }
    }
}

impl<T, L> PrefixedList<T, L>
where
    L: Copy + TryFrom<usize>,
    T: EncodeValue,
{
    pub fn set_list(&mut self, list: Vec<T>) -> anyhow::Result<()> {
        if let Some(element) = list.first() {
            let encode_size = element.encode_to_vec()?.len();
            self.length = (encode_size * list.len())
                .try_into()
                .map_err(|_e| anyhow!("invalid length"))?;
            self.items = list;
        } else {
            // list is empty
            self.length = 0.try_into().ok().unwrap();
            self.items = Vec::new();
        }
        Ok(())
    }
}

impl<T, L> DecodeValue for PrefixedList<T, L>
where
    L: Copy + Into<usize> + DecodeValue,
    T: DecodeValue,
{
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (length, mut buffer): (L, S) = buffer.decode_value()?;
        let length_usize: usize = length.into();

        let current_buffer_size = buffer.len();
        // TODO: standardize the "not enough data" error
        if current_buffer_size < length_usize {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "not enough data available for PrefixedList of {} with {} length",
                    type_name::<T>(),
                    type_name::<L>()
                ),
            ));
        }
        let target_buffer_size = current_buffer_size - length_usize;

        // TODO: tracks size of self instead
        let mut list: Vec<T> = Vec::with_capacity(length_usize);
        while buffer.len() > target_buffer_size {
            let (item, remaining_buffer) = buffer.decode_value()?;
            list.push(item);
            buffer = remaining_buffer;
        }

        // We should never read more than the prefixed length
        if buffer.len() != target_buffer_size {
            // this means we override, e.g. target length of 21 bytes but we read 22
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "corrupted list length",
            ));
        }

        Ok((
            Self {
                length,
                items: list,
            },
            buffer,
        ))
    }
}

impl<T, L> EncodeValue for PrefixedList<T, L>
where
    T: EncodeValue,
    L: Copy + Into<usize> + TryFrom<usize> + EncodeValue,
{
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        let mut elements = Vec::new();
        for element in &self.items {
            element.encode_to(&mut elements)?;
        }
        let size = elements.len();
        let size: L = size
            .try_into()
            .map_err(|e| std::io::Error::new(ErrorKind::ArgumentListTooLong, "oops"))?;

        buffer.encode_value(&size)?;
        for item in &self.items {
            buffer.encode_value(item)?;
        }
        Ok(())
    }
}
