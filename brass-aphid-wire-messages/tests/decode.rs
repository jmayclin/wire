//! Zero-copy decoding: the decoded values must borrow from the input buffer.

use brass_aphid_wire_messages::{
    codec::{DecodeValue, EncodeValue},
    iana::{self, constants, Protocol},
    prefixed_list::{PrefixedBlob, PrefixedList},
    protocol::{extensions::*, *},
};

/// A TLS 1.2 hello with 2 ciphers, a session id, and 2 extensions
/// (supported groups, and a key share with 2 shares).
fn sample_client_hello() -> Vec<u8> {
    let mut b = vec![];
    b.extend([0x03, 0x03]); // TLS 1.2
    b.extend([7u8; 32]); // random
    b.extend([3, 0xAA, 0xBB, 0xCC]); // session id
    b.extend([0, 4, 0x13, 0x01, 0x13, 0x02]); // 2 ciphers
    b.extend([1, 0]); // compression: null

    let groups = [0, 4, 0x00, 0x17, 0x00, 0x1d]; // secp256r1, x25519
    let shares = [
        0, 11, // list length
        0x00, 0x17, 0, 2, 1, 2, // share 1
        0x00, 0x1d, 0, 1, 9, // share 2
    ];
    let mut exts = vec![];
    exts.extend([0, 10, 0, groups.len() as u8]);
    exts.extend(groups);
    exts.extend([0, 51, 0, shares.len() as u8]);
    exts.extend(shares);
    b.extend((exts.len() as u16).to_be_bytes());
    b.extend(exts);
    b
}

#[test]
fn client_hello_decodes() {
    let bytes = sample_client_hello();
    let hello = ClientHello::decode_from_exact(&bytes).unwrap();

    assert_eq!(hello.protocol_version, Protocol::TLSv1_2);
    assert_eq!(hello.session_id.blob(), &[0xAA, 0xBB, 0xCC]);
    assert_eq!(
        hello.offered_ciphers.iter().collect::<Vec<_>>(),
        [
            constants::TLS_AES_128_GCM_SHA256,
            constants::TLS_AES_256_GCM_SHA384
        ]
    );
    assert_eq!(hello.extensions.as_ref().unwrap().iter().count(), 2);
}

#[test]
fn blob_borrows_from_the_input() {
    let bytes = sample_client_hello();
    let hello = ClientHello::decode_from_exact(&bytes).unwrap();

    // the session id is a view into `bytes`, not a copy
    let blob = hello.session_id.blob();
    let input = bytes.as_ptr_range();
    assert!(input.contains(&blob.as_ptr()));
}

#[test]
fn typed_extension_is_parsed_on_demand() {
    let bytes = sample_client_hello();
    let hello = ClientHello::decode_from_exact(&bytes).unwrap();

    assert_eq!(
        hello.supported_groups().unwrap(),
        [constants::secp256r1, constants::x25519]
    );
    assert!(hello.extension(ExtensionType::ServerName).is_none());

    let ext = hello.extension(ExtensionType::KeyShare).unwrap();
    let shares = KeyShareClientHello::decode_from_exact(ext.extension_data.blob()).unwrap();
    let shares: Vec<_> = shares.client_shares.iter().collect();
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0].key_exchange.blob(), &[1, 2]);
    assert_eq!(shares[1].key_exchange.blob(), &[9]);
}

#[test]
fn decoded_values_outlive_a_scope_that_only_the_buffer_needs() {
    // the borrow is tied to `bytes`, so the hello can be returned alongside it
    fn parse(bytes: &[u8]) -> ClientHello<'_> {
        ClientHello::decode_from_exact(bytes).unwrap()
    }
    let bytes = sample_client_hello();
    let hello = parse(&bytes);
    assert_eq!(hello.protocol_version, Protocol::TLSv1_2);
}

#[test]
fn re_encoding_a_decoded_value_is_the_identity() {
    let bytes = sample_client_hello();
    let hello = ClientHello::decode_from_exact(&bytes).unwrap();
    assert_eq!(hello.encode_to_vec().unwrap(), bytes);
}

#[test]
fn legacy_versions_have_no_extensions() {
    let mut b = vec![];
    b.extend([0x03, 0x01]); // TLS 1.0
    b.extend([0u8; 32]);
    b.extend([0]); // no session id
    b.extend([0, 2, 0x13, 0x01]);
    b.extend([1, 0]);
    let hello = ClientHello::decode_from_exact(&b).unwrap();
    assert!(hello.extensions.is_none());
}

#[test]
fn truncated_input_is_an_error_not_a_panic() {
    let bytes = sample_client_hello();
    for len in 0..bytes.len() {
        assert!(
            ClientHello::decode_from_exact(&bytes[..len]).is_err(),
            "decoding {len} of {} bytes should fail",
            bytes.len()
        );
    }
}

#[test]
fn trailing_bytes_are_rejected_by_exact() {
    let mut bytes = sample_client_hello();
    bytes.push(0);
    assert!(ClientHello::decode_from_exact(&bytes).is_err());
    // but `decode_from` leaves them for the caller
    let (_, rest) = ClientHello::decode_from(&bytes).unwrap();
    assert_eq!(rest, &[0]);
}

#[test]
fn a_list_item_that_overruns_the_list_is_rejected() {
    // list says 3 bytes, but each Cipher is 2: the second item overruns
    let bytes = [0, 3, 0x13, 0x01, 0x13];
    assert!(PrefixedList::<iana::Cipher, u16>::decode_from_exact(&bytes).is_err());
}

#[test]
fn blob_length_longer_than_input_is_rejected() {
    assert!(PrefixedBlob::<u8>::decode_from_exact(&[5, 1, 2]).is_err());
}
