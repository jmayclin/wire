//! The type-directed `Writer<T>` trait: one writer, several decodings.

use brass_aphid_wire_messages::{
    codec::{DecodeValue, EncodeValue},
    iana::{self, constants, Protocol},
    prefixed_list::{PrefixedBlob, PrefixedList},
    protocol::{extensions::*, *},
    writer::Writer,
};

fn write<W: Writer<T>, T>(w: &W) -> Vec<u8> {
    struct Adapter<'a, W, T>(&'a W, std::marker::PhantomData<T>);
    impl<W: Writer<T>, T> EncodeValue for Adapter<'_, W, T> {
        fn encode_to(&self, buf: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
            self.0.encode_transform(buf)
        }
    }
    Adapter(w, std::marker::PhantomData)
        .encode_to_vec()
        .unwrap()
}

#[test]
fn a_slice_writes_as_a_prefixed_list() {
    let groups = [constants::secp256r1, constants::x25519];
    let bytes = write::<_, PrefixedList<iana::Group, u16>>(&&groups[..]);
    assert_eq!(bytes, [0, 4, 0x00, 0x17, 0x00, 0x1d]);

    let list = PrefixedList::<iana::Group, u16>::decode_from_exact(&bytes).unwrap();
    assert_eq!(list.iter().collect::<Vec<_>>(), groups);
}

#[test]
fn the_same_slice_writes_with_a_different_prefix_width() {
    // Writer<T> is a trait parameter, so one input type has several outputs
    let groups = [iana::Group { value: 1 }];
    let wide = write::<_, PrefixedList<iana::Group, u16>>(&&groups[..]);
    let narrow = write::<_, PrefixedList<iana::Group, u8>>(&&groups[..]);
    assert_eq!(wide, [0, 2, 0, 1]);
    assert_eq!(narrow, [2, 0, 1]);
}

#[test]
fn bytes_write_as_a_prefixed_blob() {
    let id: &[u8] = &[1, 2, 3];
    let bytes = write::<_, PrefixedBlob<u8>>(&id);
    assert_eq!(bytes, [3, 1, 2, 3]);
    assert_eq!(
        PrefixedBlob::<u8>::decode_from_exact(&bytes)
            .unwrap()
            .blob(),
        &[1, 2, 3]
    );
}

#[test]
fn anything_encodable_is_a_writer_for_itself() {
    let bytes = write::<_, Protocol>(&Protocol::TLSv1_3);
    assert_eq!(bytes, [0x03, 0x04]);
    let bytes = write::<_, [u8; 4]>(&[1, 2, 3, 4]);
    assert_eq!(bytes, [1, 2, 3, 4]);
}

#[test]
fn an_empty_slice_is_an_empty_list() {
    let none: &[iana::Group] = &[];
    assert_eq!(write::<_, PrefixedList<iana::Group, u16>>(&none), [0, 0]);
}

#[test]
fn an_oversized_list_is_an_error_not_a_truncation() {
    let big = vec![0u8; 256];
    let big: &[u8] = &big;
    let adapter = {
        struct A<'a>(&'a [u8]);
        impl EncodeValue for A<'_> {
            fn encode_to(&self, b: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
                <&[u8] as Writer<PrefixedBlob<u8>>>::encode_transform(&self.0, b)
            }
        }
        A(big)
    };
    assert!(adapter.encode_to_vec().is_err());
}
