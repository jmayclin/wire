//! Basic client/server handshake using s2n-tls's `TestPair`.
//!
//! This is the starting point for the integration suite. It stands up an
//! s2n-tls client and server backed by in-memory IO and drives a TLS 1.3
//! handshake to completion. Add your own protocol scenarios on top of this.

use std::{
    io::{Cursor, Write},
    task::Poll,
};

use brass_aphid_wire_messages::{
    codec::{DecodeValue, DecodeValueWithContext, EncodeValue},
    iana::Protocol,
    protocol::{content_value::HandshakeMessageValue, ContentType},
};
use brass_aphid_wire_record::{Plaintext, RecordProtocol, RecordProtocolBehavior};
use s2n_tls::{config::Config, security::Policy, testing::TestPair};

/// Signature/certificate type available under the workspace `certs/` directory.
#[derive(Clone, Copy)]
#[allow(dead_code)] // variants kept for convenience as scenarios are added
enum SigType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Rsapss2048,
    Ecdsa256,
    Ecdsa384,
    Ecdsa521,
}

impl SigType {
    fn dir_name(&self) -> &'static str {
        match self {
            SigType::Rsa2048 => "rsa2048",
            SigType::Rsa3072 => "rsa3072",
            SigType::Rsa4096 => "rsa4096",
            SigType::Rsapss2048 => "rsapss2048",
            SigType::Ecdsa256 => "ecdsa256",
            SigType::Ecdsa384 => "ecdsa384",
            SigType::Ecdsa521 => "ecdsa521",
        }
    }
}

/// Read one of the shared workspace certs. Tests execute with the crate root as
/// the working directory, so the `../certs` relative path resolves correctly.
fn read_cert(sig_type: SigType, file: &str) -> Vec<u8> {
    let path = format!("../certs/{}/{}", sig_type.dir_name(), file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Build a config usable by both the client and server sides of a `TestPair`.
///
/// Loads the server chain/key and trusts the matching CA. x509 verification is
/// disabled so the stock certs handshake without hostname wiring.
fn test_config(security_policy: &str, sig_type: SigType) -> Config {
    let policy = Policy::from_version(security_policy).unwrap();

    let mut builder = Config::builder();
    builder.with_system_certs(false).unwrap();
    builder.set_security_policy(&policy).unwrap();
    // Avoid long delays on handshake failure in tests.
    builder.set_max_blinding_delay(0).unwrap();

    // SAFETY: test-only; the stock certs aren't issued for a real hostname.
    unsafe { builder.disable_x509_verification().unwrap() };

    builder
        .trust_pem(&read_cert(sig_type, "ca-cert.pem"))
        .unwrap();
    let chain = read_cert(sig_type, "server-chain.pem");
    let key = read_cert(sig_type, "server-key.pem");
    builder.load_pem(&chain, &key).unwrap();

    builder.build().unwrap()
}

/// I wrote this test taking into account s2n-tls's silly goose one-message-per-record
/// behaviors
#[test]
fn basic_handshake() {
    let config = test_config("default_tls13", SigType::Rsa3072);
    let mut pair = TestPair::from_config(&config);

    let mut buffer = [0_u8; 9_000];
    let mut cursor = Cursor::new(buffer.as_mut_slice());
    // let mut bar = brass_aphid_wire_record::Plaintext::default();
    let mut record_protocol = RecordProtocol::<Plaintext>::new();
    let mut client = brass_aphid_wire_handshake::Client::new();

    let ch = client.make_message().unwrap();
    let ch = ch.encode_to_vec().unwrap();
    record_protocol.encapsulate_bytes(ContentType::Handshake, &ch, &mut cursor);
    // transfer
    {
        let written = cursor.position() as usize;
        let slice = &cursor.get_mut()[0..written];
        pair.io
            .client_tx_stream
            .borrow_mut()
            .write_all(slice)
            .unwrap();
        cursor.set_position(0);
    }

    println!("client buffer: {}", pair.io.client_tx_stream.borrow().len());

    assert!(matches!(pair.server.poll_negotiate(), Poll::Pending));
    println!("client buffer: {}", pair.io.client_tx_stream.borrow().len());

    let mut server_flight = pair.io.server_tx_stream.borrow_mut();
    let remaining = server_flight.make_contiguous();

    // record 1
    {
        let (mut record, remaining) = record_protocol
            .decapsulate_bytes(remaining, &mut cursor)
            .unwrap();
        let handshake = record.assert_handshake();

        let hsm = HandshakeMessageValue::decode_from_exact(handshake).unwrap();
        client.consume_message(hsm).unwrap();
        cursor.set_position(0);

        // record 2
        let (mut record, remaining) = record_protocol
            .decapsulate_bytes(remaining, &mut cursor)
            .unwrap();
        let ccs = record.assert_ccs();
        cursor.set_position(0);

        let mut record_protocol = record_protocol.select_tls13(
            client.negotiated_cipher().unwrap(),
            &client.handshake_secrets().unwrap().1,
        );

        let cipher = record_protocol.cipher();
        let protocol = Protocol::TLSv1_3;
        let decode_context = (protocol, cipher);

        // record 3 - EE
        let (mut record, remaining) = record_protocol
            .decapsulate_bytes(remaining, &mut cursor)
            .unwrap();
        let handshake = record.assert_handshake();
        let hsm = HandshakeMessageValue::decode_from_exact(handshake).unwrap();
        client.consume_message(hsm).unwrap();

        // record 4 - Certificate
        let (mut record, remaining) = record_protocol
            .decapsulate_bytes(remaining, &mut cursor)
            .unwrap();
        let handshake = record.assert_handshake();
        let hsm =
            HandshakeMessageValue::decode_from_with_context_exact(handshake, decode_context).unwrap();
        client.consume_message(hsm).unwrap();

        // record 5 - Cert Verify
        let (mut record, remaining) = record_protocol
            .decapsulate_bytes(remaining, &mut cursor)
            .unwrap();
        let handshake = record.assert_handshake();
        let hsm = HandshakeMessageValue::decode_from_with_context_exact(handshake, decode_context).unwrap();
        client.consume_message(hsm).unwrap();

        // record 6 - Finished
        let (mut record, remaining) = record_protocol
            .decapsulate_bytes(remaining, &mut cursor)
            .unwrap();
        let handshake = record.assert_handshake();
        let hsm = HandshakeMessageValue::decode_from_with_context_exact(handshake, decode_context).unwrap();
        client.consume_message(hsm).unwrap();
    }

    // pair.handshake().expect("handshake should complete");

    // // Exchange a round of application data to confirm the connection works
    // // past the handshake.
    // let client_msg = b"hello from the client";
    // let server_msg = b"hello from the server";

    // let mut buf = [0u8; 32];

    // assert!(pair.client.poll_send(client_msg).is_ready());
    // assert!(pair.server.poll_recv(&mut buf[..client_msg.len()]).is_ready());
    // assert_eq!(&buf[..client_msg.len()], client_msg);

    // assert!(pair.server.poll_send(server_msg).is_ready());
    // assert!(pair.client.poll_recv(&mut buf[..server_msg.len()]).is_ready());
    // assert_eq!(&buf[..server_msg.len()], server_msg);
}
