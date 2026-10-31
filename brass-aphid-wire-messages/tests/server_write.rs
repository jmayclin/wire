//! Writing the server's side of the handshake: ServerHello, HelloRetryRequest,
//! and EncryptedExtensions.
//!
//! These exercise two things the ClientHello does not:
//! - one extension code (key_share) with a different body in each message
//! - a ServerHello and a HelloRetryRequest that are the same type, told apart by
//!   `ServerHello::is_hrr`

use brass_aphid_wire_messages::{
    codec::{DecodeValue, EncodeValue},
    iana::{self, constants, Protocol},
    protocol::{extensions::*, *},
};

const RANDOM: [u8; 32] = [0x11; 32];
const SECP256R1: iana::Group = constants::secp256r1;
const X25519: iana::Group = constants::x25519;
const TLS_AES_256_GCM_SHA384: iana::Cipher = constants::TLS_AES_256_GCM_SHA384;

#[test]
fn server_hello_with_a_server_key_share() {
    let public_key = [9u8; 32];
    let selected_version = SupportedVersionServerHelloWriter {
        selected_version: Protocol::TLSv1_3,
    };
    let key_share = KeyShareServerHelloWriter {
        server_share: KeyShareWriter {
            group: X25519,
            key_exchange: &public_key[..],
        },
    };
    let extensions = [
        ExtensionWriter::of::<SupportedVersionServerHello>(&selected_version),
        ExtensionWriter::of::<KeyShareServerHello>(&key_share),
    ];

    let server_hello = ServerHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id_echo: &[1u8, 2, 3][..],
        cipher_suite: TLS_AES_256_GCM_SHA384,
        legacy_compression_method: 0u8,
        extensions: &extensions[..],
    };
    let bytes = server_hello.encode_to_vec().unwrap();

    let hello = ServerHello::decode_from_exact(&bytes).unwrap();
    assert_eq!(hello.protocol_version, Protocol::TLSv1_2);
    assert_eq!(hello.session_id_echo.blob(), &[1, 2, 3]);
    assert_eq!(hello.cipher_suite, TLS_AES_256_GCM_SHA384);
    // the real version is in the extension, not the legacy field
    assert_eq!(hello.selected_version().unwrap(), Protocol::TLSv1_3);

    let share = hello.key_share().unwrap().unwrap();
    assert_eq!(share.group, X25519);
    assert_eq!(share.key_exchange.blob(), &public_key);

    assert!(!hello.is_hrr());
}

#[test]
fn hello_retry_request_uses_a_different_key_share_body() {
    // the same extension code (key_share) as above, but the body is a bare group
    let selected_version = SupportedVersionServerHelloWriter {
        selected_version: Protocol::TLSv1_3,
    };
    let key_share = KeyShareRetryRequestWriter {
        selected_group: SECP256R1,
    };
    let extensions = [
        ExtensionWriter::of::<SupportedVersionServerHello>(&selected_version),
        ExtensionWriter::of::<KeyShareRetryRequest>(&key_share),
    ];

    // a HelloRetryRequest is a ServerHello with the reserved random
    let retry = ServerHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: ServerHello::HELLO_RETRY_REQUEST_RANDOM,
        session_id_echo: &[][..],
        cipher_suite: TLS_AES_256_GCM_SHA384,
        legacy_compression_method: 0u8,
        extensions: &extensions[..],
    };
    let bytes = retry.encode_to_vec().unwrap();

    let hrr = ServerHello::decode_from_exact(&bytes).unwrap();
    assert!(hrr.is_hrr());
    assert_eq!(hrr.selected_group().unwrap(), Some(SECP256R1));

    // the key_share body is 2 bytes here, and 4+ in a regular ServerHello
    let ext = hrr.extension(ExtensionType::KeyShare).unwrap();
    assert_eq!(ext.extension_data.blob(), &[0x00, 0x17]);
}

/// The two key share accessors only make sense for one kind of message each, and
/// say so rather than misparsing the other kind's body.
#[test]
fn key_share_accessors_check_which_kind_of_message_it_is() {
    let key_share = KeyShareRetryRequestWriter {
        selected_group: SECP256R1,
    };
    let extensions = [ExtensionWriter::of::<KeyShareRetryRequest>(&key_share)];
    let retry = ServerHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: ServerHello::HELLO_RETRY_REQUEST_RANDOM,
        session_id_echo: &[][..],
        cipher_suite: TLS_AES_256_GCM_SHA384,
        legacy_compression_method: 0u8,
        extensions: &extensions[..],
    };
    let bytes = retry.encode_to_vec().unwrap();
    let hrr = ServerHello::decode_from_exact(&bytes).unwrap();
    assert!(hrr.key_share().is_err());
    assert!(hrr.selected_group().is_ok());

    let regular = ServerHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id_echo: &[][..],
        cipher_suite: TLS_AES_256_GCM_SHA384,
        legacy_compression_method: 0u8,
        extensions: &[][..] as &[ExtensionWriter],
    };
    let bytes = regular.encode_to_vec().unwrap();
    let hello = ServerHello::decode_from_exact(&bytes).unwrap();
    assert!(!hello.is_hrr());
    assert!(hello.selected_group().is_err());
    assert_eq!(hello.key_share().unwrap(), None);
}

/// The writer does not stop a ServerHello from carrying the reserved random: that
/// is a state machine concern, and `is_hrr` is how it finds out.
#[test]
fn the_reserved_random_is_just_a_value() {
    let bytes = ServerHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: ServerHello::HELLO_RETRY_REQUEST_RANDOM,
        session_id_echo: &[][..],
        cipher_suite: TLS_AES_256_GCM_SHA384,
        legacy_compression_method: 0u8,
        extensions: &[][..] as &[ExtensionWriter],
    }
    .encode_to_vec()
    .unwrap();
    assert!(ServerHello::decode_from_exact(&bytes).unwrap().is_hrr());
}

#[test]
fn encrypted_extensions() {
    let groups = SupportedGroupsWriter {
        named_curve_list: &[SECP256R1, X25519][..],
    };
    let extensions = [ExtensionWriter::of::<SupportedGroups>(&groups)];
    let encrypted_extensions = EncryptedExtensionsWriter {
        extensions: &extensions[..],
    };
    let bytes = encrypted_extensions.encode_to_vec().unwrap();

    let decoded = EncryptedExtensions::decode_from_exact(&bytes).unwrap();
    assert_eq!(decoded.extensions.iter().count(), 1);
    let ext = decoded.extensions.iter().next().unwrap();
    assert_eq!(ext.extension_type, ExtensionType::SupportedGroups);
}

#[test]
fn empty_encrypted_extensions() {
    let encrypted_extensions = EncryptedExtensionsWriter {
        extensions: &[][..] as &[ExtensionWriter],
    };
    let bytes = encrypted_extensions.encode_to_vec().unwrap();
    assert_eq!(bytes, [0, 0]);
    assert_eq!(
        EncryptedExtensions::decode_from_exact(&bytes)
            .unwrap()
            .extensions
            .iter()
            .count(),
        0
    );
}

/// The type system keeps the two key_share bodies apart: the retry request's body
/// is not accepted where a server hello's is expected.
#[test]
fn key_share_bodies_are_not_interchangeable() {
    let retry_body = KeyShareRetryRequestWriter {
        selected_group: SECP256R1,
    };
    // compiles: right body for the right type
    let _ = ExtensionWriter::of::<KeyShareRetryRequest>(&retry_body);
    // would not compile:
    // let _ = ExtensionWriter::of::<KeyShareServerHello>(&retry_body);
}
