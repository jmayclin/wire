//! Write a client hello the way `Client::client_hello()` in the handshake crate
//! does, but with the generic `Writer<T>` structs, straight into a `Cursor`.

use brass_aphid_wire_messages::{
    codec::{DecodeValue, EncodeValue},
    iana::{self, constants, Protocol},
    protocol::{extensions::*, *},
};
use std::io::Cursor;

const RANDOM: [u8; 32] = *b"https://xkcd.com/221/-----------";

const SECP256R1: iana::Group = constants::secp256r1;
const ECDSA_SECP256R1_SHA256: iana::SignatureScheme = constants::ecdsa_secp256r1_sha256;
const RSA_PSS_RSAE_SHA256: iana::SignatureScheme = constants::rsa_pss_rsae_sha256;
const TLS_AES_256_GCM_SHA384: iana::Cipher = constants::TLS_AES_256_GCM_SHA384;

#[test]
fn write_client_hello_to_a_cursor() {
    let public_key = [4u8; 65];

    // extension bodies. These are bound to names before the extension list
    // because the list borrows them.
    let supported_groups = SupportedGroupsWriter {
        named_curve_list: [SECP256R1].as_slice(),
    };
    let supported_versions = SupportedVersionClientHelloWriter {
        versions: [Protocol::TLSv1_3].as_slice(),
    };
    let signature_algorithms = SignatureSchemeListWriter {
        supported_signature_algorithms: [ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256].as_slice(),
    };
    let key_shares = [KeyShareWriter {
        group: SECP256R1,
        key_exchange: public_key.as_slice(),
    }];
    let key_share = KeyShareClientHelloWriter {
        client_shares: key_shares.as_slice(),
    };

    // `of::<E>` takes the type code from `E`
    let extensions = [
        ExtensionWriter::of::<SupportedGroups>(&supported_groups),
        ExtensionWriter::of::<SupportedVersionClientHello>(&supported_versions),
        ExtensionWriter::of::<SignatureSchemeList>(&signature_algorithms),
        ExtensionWriter::of::<KeyShareClientHello>(&key_share),
    ];

    let client_hello = ClientHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id: [].as_slice(),
        offered_ciphers: [TLS_AES_256_GCM_SHA384].as_slice(),
        compression_methods: [0u8].as_slice(),
        extensions: Some(extensions.as_slice()),
    };

    // ... and now to a cursor
    let mut buffer = [0u8; 1024];
    let mut cursor = Cursor::new(buffer.as_mut_slice());
    client_hello.encode_to(&mut cursor).unwrap();
    let written = cursor.position() as usize;
    let bytes = &buffer[..written];

    // it decodes, and nothing is left over
    let hello = ClientHello::decode_from_exact(bytes).unwrap();
    assert_eq!(hello.protocol_version, Protocol::TLSv1_2);
    assert_eq!(hello.random, RANDOM);
    assert!(hello.session_id.blob().is_empty());
    assert_eq!(
        hello.offered_ciphers.iter().collect::<Vec<_>>(),
        [TLS_AES_256_GCM_SHA384]
    );
    assert_eq!(hello.compression_methods.blob(), &[0]);
    assert_eq!(hello.supported_groups().unwrap(), [SECP256R1]);

    let types: Vec<_> = hello
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .map(|e| e.extension_type)
        .collect();
    assert_eq!(
        types,
        [
            ExtensionType::SupportedGroups,
            ExtensionType::SupportedVersions,
            ExtensionType::SignatureAlgorithms,
            ExtensionType::KeyShare,
        ]
    );

    let ext = hello.extension(ExtensionType::KeyShare).unwrap();
    let shares = KeyShareClientHello::decode_from_exact(ext.extension_data.blob()).unwrap();
    let shares: Vec<_> = shares.client_shares.iter().collect();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].group, SECP256R1);
    assert_eq!(shares[0].key_exchange.blob(), &public_key);

    // and the decoded hello re-encodes to the bytes that were written
    assert_eq!(hello.encode_to_vec().unwrap(), bytes);
}

#[test]
fn a_too_small_cursor_is_an_error() {
    let client_hello = ClientHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id: &[][..],
        offered_ciphers: &[TLS_AES_256_GCM_SHA384][..],
        compression_methods: &[0u8][..],
        extensions: None::<&[ExtensionWriter]>,
    };
    let mut buffer = [0u8; 10];
    let mut cursor = Cursor::new(buffer.as_mut_slice());
    assert!(client_hello.encode_to(&mut cursor).is_err());
}

/// Optional pieces can be left out with the cheapest types: an array reference
/// for a literal list, `None` for the extensions.
#[test]
fn legacy_hello_without_extensions() {
    let client_hello = ClientHelloWriter {
        protocol_version: Protocol::TLSv1_0,
        random: RANDOM,
        session_id: &[1u8, 2, 3][..],
        offered_ciphers: &[TLS_AES_256_GCM_SHA384][..],
        compression_methods: &[0u8][..],
        extensions: None::<&[ExtensionWriter]>,
    };
    let bytes = client_hello.encode_to_vec().unwrap();
    let hello = ClientHello::decode_from_exact(&bytes).unwrap();
    assert!(hello.extensions.is_none());
    assert_eq!(hello.session_id.blob(), &[1, 2, 3]);
}

/// The version rule can't be derived, it is hand written on top of
/// `#[derive(WriterStruct)]`. Writing extensions for TLS 1.0 would produce bytes
/// that the decoder rejects, so it is an error.
#[test]
fn extensions_are_rejected_for_legacy_versions() {
    let groups = SupportedGroupsWriter {
        named_curve_list: &[SECP256R1][..],
    };
    let extensions = [ExtensionWriter::of::<SupportedGroups>(&groups)];
    let client_hello = ClientHelloWriter {
        protocol_version: Protocol::TLSv1_0,
        random: RANDOM,
        session_id: &[][..],
        offered_ciphers: &[TLS_AES_256_GCM_SHA384][..],
        compression_methods: &[0u8][..],
        extensions: Some(&extensions[..]),
    };
    let error = client_hello.encode_to_vec().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

/// TLS 1.2 with `None` writes no extensions block at all, which the decoder
/// then fails to read. The writer doesn't catch this one.
#[test]
fn missing_extensions_block_for_tls12_does_not_decode() {
    let client_hello = ClientHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id: &[][..],
        offered_ciphers: &[TLS_AES_256_GCM_SHA384][..],
        compression_methods: &[0u8][..],
        extensions: None::<&[ExtensionWriter]>,
    };
    let bytes = client_hello.encode_to_vec().unwrap();
    assert!(ClientHello::decode_from_exact(&bytes).is_err());
}
