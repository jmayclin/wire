//! Handshake framing: `HandshakeWriter::of::<M>` on the way out, and a checked
//! cast with `HandshakeMessage::parse` on the way in.

use brass_aphid_wire_messages::{
    codec::{DecodeValue, EncodeValue, RawBytes},
    protocol::handshake::*,
    iana::{self, constants, Protocol},
    protocol::{extensions::*, *},
};

const RANDOM: [u8; 32] = [0x11; 32];
const SECP256R1: iana::Group = constants::secp256r1;
const TLS_AES_128_GCM_SHA256: iana::Cipher = constants::TLS_AES_128_GCM_SHA256;
const TLS_AES_256_GCM_SHA384: iana::Cipher = constants::TLS_AES_256_GCM_SHA384;

fn client_hello_message() -> Vec<u8> {
    let groups = SupportedGroupsWriter {
        named_curve_list: &[SECP256R1][..],
    };
    let extensions = [ExtensionWriter::of::<SupportedGroups>(&groups)];
    let hello = ClientHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id: &[][..],
        offered_ciphers: &[TLS_AES_128_GCM_SHA256][..],
        compression_methods: &[0u8][..],
        extensions: Some(&extensions[..]),
    };
    HandshakeWriter::of::<ClientHello>(&hello)
        .encode_to_vec()
        .unwrap()
}

#[test]
fn write_and_cast_a_client_hello() {
    let bytes = client_hello_message();
    // type, then a u24 length that covers the rest
    assert_eq!(bytes[0], 1);
    let length = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
    assert_eq!(length, bytes.len() - 4);

    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    assert_eq!(message.handshake_type, HandshakeType::ClientHello);

    let hello: ClientHello = message.parse().unwrap();
    assert_eq!(hello.protocol_version, Protocol::TLSv1_2);
    assert_eq!(hello.supported_groups().unwrap(), [SECP256R1]);
}

#[test]
fn the_raw_bytes_are_the_whole_framed_message() {
    // this is what a running transcript hash is fed
    let bytes = client_hello_message();
    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    assert_eq!(message.raw, &bytes[..]);
    assert_eq!(message.body, &bytes[4..]);
}

#[test]
fn casting_to_the_wrong_message_is_an_error() {
    let bytes = client_hello_message();
    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    assert!(message.parse::<ServerHello>().is_err());
    assert!(message.parse::<EncryptedExtensions>().is_err());
}

#[test]
fn a_flight_of_messages_is_split_one_at_a_time() {
    // messages can be coalesced in one record
    let key_share = KeyShareServerHelloWriter {
        server_share: KeyShareWriter {
            group: SECP256R1,
            key_exchange: &[7u8; 32][..],
        },
    };
    let extensions = [ExtensionWriter::of::<KeyShareServerHello>(&key_share)];
    let server_hello = ServerHelloWriter {
        protocol_version: Protocol::TLSv1_2,
        random: RANDOM,
        session_id_echo: &[][..],
        cipher_suite: TLS_AES_128_GCM_SHA256,
        legacy_compression_method: 0u8,
        extensions: &extensions[..],
    };
    let encrypted_extensions = EncryptedExtensionsWriter {
        extensions: &[][..] as &[ExtensionWriter],
    };

    let mut flight = HandshakeWriter::of::<ServerHello>(&server_hello)
        .encode_to_vec()
        .unwrap();
    flight.extend(
        HandshakeWriter::of::<EncryptedExtensions>(&encrypted_extensions)
            .encode_to_vec()
            .unwrap(),
    );

    let (first, rest) = HandshakeMessage::decode_from(&flight).unwrap();
    assert_eq!(first.handshake_type, HandshakeType::ServerHello);
    let (second, rest) = HandshakeMessage::decode_from(rest).unwrap();
    assert_eq!(second.handshake_type, HandshakeType::EncryptedExtensions);
    assert!(rest.is_empty());

    let hello: ServerHello = first.parse().unwrap();
    assert_eq!(hello.key_share().unwrap().unwrap().group, SECP256R1);
    let ee: EncryptedExtensions = second.parse().unwrap();
    assert_eq!(ee.extensions.iter().count(), 0);

    // the raw slices tile the flight exactly
    assert_eq!(first.raw.len() + second.raw.len(), flight.len());
}

#[test]
fn finished_needs_the_cipher_to_know_its_length() {
    // the verify_data has no length prefix: SHA-256 is 32 bytes, SHA-384 is 48
    let sha256 = [0xAAu8; 32];
    let finished = FinishedWriter {
        verify_data: &sha256[..],
    };
    let bytes = HandshakeWriter::of::<Finished>(&finished)
        .encode_to_vec()
        .unwrap();
    assert_eq!(bytes.len(), 4 + 32);

    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    let parsed: Finished = message.parse_with_context(TLS_AES_128_GCM_SHA256).unwrap();
    assert_eq!(parsed.verify_data, RawBytes(&sha256));

    // the same bytes with the wrong cipher: 48 are expected, only 32 are there
    assert!(message
        .parse_with_context::<Finished>(TLS_AES_256_GCM_SHA384)
        .is_err());
}

#[test]
fn finished_with_extra_bytes_is_an_error() {
    let long = [0u8; 40];
    let finished = FinishedWriter {
        verify_data: &long[..],
    };
    let bytes = HandshakeWriter::of::<Finished>(&finished)
        .encode_to_vec()
        .unwrap();
    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    // 32 bytes expected, 40 present: `parse` uses the _exact variant
    assert!(message
        .parse_with_context::<Finished>(TLS_AES_128_GCM_SHA256)
        .is_err());
}

#[test]
fn unknown_cipher_has_no_hash_length() {
    let bytes = HandshakeWriter::of::<Finished>(&FinishedWriter {
        verify_data: &[0u8; 32][..],
    })
    .encode_to_vec()
    .unwrap();
    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    assert!(message
        .parse_with_context::<Finished>(iana::Cipher { value: [0x00, 0xff] })
        .is_err());
}

#[test]
fn truncated_framing_is_an_error_not_a_panic() {
    let bytes = client_hello_message();
    for len in 0..bytes.len() {
        assert!(
            HandshakeMessage::decode_from(&bytes[..len]).is_err(),
            "{len} of {} bytes should not frame",
            bytes.len()
        );
    }
}

#[test]
fn an_unknown_handshake_type_still_frames() {
    // the framing is generic: type 99 with a 2 byte body
    let bytes = [99, 0, 0, 2, 0xAB, 0xCD];
    let message = HandshakeMessage::decode_from_exact(&bytes).unwrap();
    assert_eq!(message.handshake_type, HandshakeType::Unknown(99));
    assert_eq!(message.body, &[0xAB, 0xCD]);
}
