//! The `Writer` and `WriterStruct` derives, on small structs.

use brass_aphid_wire_macros::{DecodeStruct, EncodeStruct, Writer as WriterDerive, WriterStruct};
use brass_aphid_wire_messages::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::{PrefixedBlob, PrefixedList},
    writer::Writer,
};

#[derive(Debug, PartialEq, Eq, DecodeStruct, EncodeStruct, WriterDerive)]
struct Pair<'a> {
    id: u8,
    name: PrefixedBlob<'a, u8>,
}

/// no lifetime: the generated impls must not mention one
#[derive(Debug, PartialEq, Eq, DecodeStruct, EncodeStruct, WriterDerive)]
struct Plain {
    a: u16,
    b: u8,
}

/// nested: a field whose type is itself a derived struct
#[derive(Debug, PartialEq, Eq, DecodeStruct, EncodeStruct, WriterDerive)]
struct Outer<'a> {
    pair: Pair<'a>,
    tags: PrefixedList<'a, u8, u8>,
}

/// only the struct is derived, `EncodeValue` is written by hand
#[derive(Debug, PartialEq, Eq, DecodeStruct, EncodeStruct, WriterStruct)]
struct Hand<'a> {
    id: u8,
    name: PrefixedBlob<'a, u8>,
}

impl<T1, T2> EncodeValue for HandWriter<T1, T2>
where
    T1: Writer<u8>,
    T2: Writer<PrefixedBlob<'static, u8>>,
{
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        // custom logic: a marker byte in front
        0xFFu8.encode_to(buffer)?;
        self.id.encode_transform(buffer)?;
        self.name.encode_transform(buffer)
    }
}

#[test]
fn derived_writer_round_trips() {
    let writer = PairWriter {
        id: 7u8,
        name: &b"hello"[..],
    };
    let bytes = writer.encode_to_vec().unwrap();
    assert_eq!(bytes, [7, 5, b'h', b'e', b'l', b'l', b'o']);

    let pair = Pair::decode_from_exact(&bytes).unwrap();
    assert_eq!(pair.id, 7);
    assert_eq!(pair.name.blob(), b"hello");
}

#[test]
fn struct_without_a_lifetime() {
    let bytes = PlainWriter {
        a: 0x0102u16,
        b: 3u8,
    }
    .encode_to_vec()
    .unwrap();
    assert_eq!(bytes, [1, 2, 3]);
    assert_eq!(
        Plain::decode_from_exact(&bytes).unwrap(),
        Plain { a: 0x0102, b: 3 }
    );
}

#[test]
fn derived_writers_nest() {
    let writer = OuterWriter {
        pair: PairWriter {
            id: 1u8,
            name: &b"ab"[..],
        },
        tags: &[9u8, 8][..],
    };
    let bytes = writer.encode_to_vec().unwrap();
    assert_eq!(bytes, [1, 2, b'a', b'b', 2, 9, 8]);

    let outer = Outer::decode_from_exact(&bytes).unwrap();
    assert_eq!(outer.pair.name.blob(), b"ab");
    assert_eq!(outer.tags.iter().collect::<Vec<_>>(), [9, 8]);
}

#[test]
fn writer_struct_leaves_encode_to_the_caller() {
    let bytes = HandWriter {
        id: 5u8,
        name: &b"x"[..],
    }
    .encode_to_vec()
    .unwrap();
    assert_eq!(bytes, [0xFF, 5, 1, b'x']);
}
