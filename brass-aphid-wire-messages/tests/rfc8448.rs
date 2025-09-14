use brass_aphid_wire_messages::{
    codec::DecodeValue,
    iana::{self, Protocol},
    protocol::{
        extensions::{
            ExtensionType, KeyShareClientHello, ServerNameClientHello, SupportedVersionServerHello,
        },
        messages::{
            CertVerifyTls13, CertificateTls13, ClientHello, EncryptedExtensions,
            HandshakeMessageHeader, ServerHello,
        },
        HandshakeType,
    },
};

/// Helper function to convert a hex string to a byte vector
fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    let hex_str: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(hex_str).unwrap()
}

/// Test the ClientHello message from the Simple 1-RTT Handshake in RFC8448
#[test]
fn test_client_hello_1rtt() -> std::io::Result<()> {
    // ClientHello from RFC8448 section 3
    let client_hello_hex = "
        01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38
        c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef
        62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01
        00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76
        65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
        17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
        23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
        e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e
        51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00
        03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
        02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
        04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
        00 02 40 01
    ";
    let client_hello_bytes = hex_to_bytes(client_hello_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&client_hello_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(handshake_header.handshake_type, HandshakeType::ClientHello);

    // Parse the ClientHello message from the remaining bytes
    let (client_hello, _) = ClientHello::decode_from(remaining).unwrap();

    // Verify the parsed values
    assert_eq!(client_hello.protocol_version, Protocol::TLSv1_2);

    // Check random bytes
    let expected_random = hex_to_bytes(
        "
        cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d
        ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7
    ",
    );
    assert_eq!(client_hello.random.to_vec(), expected_random);

    // Check cipher suites
    assert_eq!(
        client_hello.offered_ciphers.list(),
        &[
            iana::constants::TLS_AES_128_GCM_SHA256,
            iana::constants::TLS_CHACHA20_POLY1305_SHA256,
            iana::constants::TLS_AES_256_GCM_SHA384,
        ]
    );

    // Check extensions
    assert_eq!(client_hello.extensions()?.len(), 9);

    // Find and check the server name extension
    let sni = client_hello
        .extensions()?
        .iter()
        .find(|ext| ext.extension_type == ExtensionType::ServerName)
        .map(|ext| ServerNameClientHello::decode_from_exact(ext.extension_data.blob()).unwrap())
        .unwrap();

    assert_eq!(sni.server_name_list.list().len(), 1);
    assert_eq!(
        String::from_utf8_lossy(sni.server_name_list.list()[0].host_name.blob()),
        "server"
    );
    Ok(())
}

/// Test the ServerHello message from the Simple 1-RTT Handshake in RFC8448
#[test]
fn test_server_hello_1rtt() {
    // ServerHello from RFC8448 section 3
    let server_hello_hex = "
        02 00 00 76 03 03 a6 af 06 a4 12 18 60 dc 5e 6e
        60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55
        77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24
        00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db
        f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0
        4e 75 1f 0f 00 2b 00 02 03 04
    ";
    let server_hello_bytes = hex_to_bytes(server_hello_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&server_hello_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(handshake_header.handshake_type, HandshakeType::ServerHello);

    // Parse the ServerHello message from the remaining bytes
    let (server_hello, _) = ServerHello::decode_from(remaining).unwrap();

    // Verify the parsed values
    assert_eq!(server_hello.protocol_version, Protocol::TLSv1_2);
    assert_eq!(server_hello.selected_version().unwrap(), Protocol::TLSv1_3);

    // Check random bytes
    let expected_random = hex_to_bytes(
        "
        a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95
        93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28
    ",
    );
    assert_eq!(server_hello.random.to_vec(), expected_random);

    // Check cipher suite
    assert_eq!(
        server_hello.cipher_suite,
        iana::constants::TLS_AES_128_GCM_SHA256
    );

    // Check extensions
    assert_eq!(server_hello.extensions.list().len(), 2);

    // Find and check the key share extension
    let key_share = server_hello
        .extensions
        .list()
        .iter()
        .find(|ext| ext.extension_type == ExtensionType::KeyShare)
        .unwrap();

    // Find and check the supported versions extension
    let supported_versions = server_hello
        .extensions
        .list()
        .iter()
        .find(|ext| ext.extension_type == ExtensionType::SupportedVersions)
        .map(|ext| {
            SupportedVersionServerHello::decode_from_exact(ext.extension_data.blob()).unwrap()
        })
        .unwrap();

    assert_eq!(supported_versions.selected_version, Protocol::TLSv1_3);
}

/// Test the EncryptedExtensions message from the Simple 1-RTT Handshake in RFC8448
#[test]
fn test_encrypted_extensions_1rtt() {
    // EncryptedExtensions from RFC8448 section 3
    let encrypted_extensions_hex = "
        08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17
        00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
        00 02 40 01 00 00 00 00
    ";
    let encrypted_extensions_bytes = hex_to_bytes(encrypted_extensions_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&encrypted_extensions_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(
        handshake_header.handshake_type,
        HandshakeType::EncryptedExtensions
    );

    // Parse the EncryptedExtensions message from the remaining bytes
    let (encrypted_extensions, _) = EncryptedExtensions::decode_from(remaining).unwrap();

    // Verify the extensions blob is present
    assert!(!encrypted_extensions.extensions.blob().is_empty());
}

/// Test the Certificate message from the Simple 1-RTT Handshake in RFC8448
#[test]
fn test_certificate_1rtt() {
    // Certificate from RFC8448 section 3
    let certificate_hex = "
        0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
        82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a
        86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a
        06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36
        30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30
        37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a
        06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06
        09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d 00
        30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98
        08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
        d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a
        95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12
        09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b
        63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80
        30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
        3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a
        8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18
        30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55
        1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86
        f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5
        b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f
        8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
        8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a
        03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02
        70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e
        b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0
        a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8
        f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00
    ";
    let certificate_bytes = hex_to_bytes(certificate_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&certificate_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(handshake_header.handshake_type, HandshakeType::Certificate);

    // Parse the Certificate message from the remaining bytes
    let (certificate, _) = CertificateTls13::decode_from(remaining).unwrap();

    // Verify the certificate request context is empty
    assert_eq!(certificate.certificate_request_context.blob().len(), 0);

    // Verify the certificate list has one entry
    assert_eq!(certificate.certificate_list.list().len(), 1);

    // Verify the certificate data is present
    assert!(!certificate.certificate_list.list()[0]
        .cert_data
        .blob()
        .is_empty());
}

/// Test the CertificateVerify message from the Simple 1-RTT Handshake in RFC8448
#[test]
fn test_certificate_verify_1rtt() {
    // CertificateVerify from RFC8448 section 3
    let certificate_verify_hex = "
        0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2
        e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
        b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3
        3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee
        aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51
        1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
        9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09
        d3 be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2
        0d 53 df ac d4 2f 74 f3
    ";
    let certificate_verify_bytes = hex_to_bytes(certificate_verify_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&certificate_verify_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(
        handshake_header.handshake_type,
        HandshakeType::CertificateVerify
    );

    // Parse the CertificateVerify message from the remaining bytes
    let (cert_verify, _) = CertVerifyTls13::decode_from(remaining).unwrap();

    // Verify the signature algorithm (0x0804 = rsa_pss_rsae_sha256)
    assert_eq!(cert_verify.algorithm.value, 0x0804);
    assert_eq!(cert_verify.algorithm.description, "rsa_pss_rsae_sha256");

    // Verify the signature is present
    assert!(!cert_verify.signature.blob().is_empty());
}

/// Test the ClientHello message from the Resumed 0-RTT Handshake in RFC8448
#[test]
fn test_client_hello_0rtt() -> std::io::Result<()> {
    // ClientHello from RFC8448 section 4
    let client_hello_hex = "01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff
         93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76
         48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00
         09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00
         26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
         6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00
         00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
         00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
         ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
         82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
         1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
         37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
         90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
         ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
         e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
         cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
         ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d";
    let client_hello_bytes = hex_to_bytes(client_hello_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&client_hello_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(handshake_header.handshake_type, HandshakeType::ClientHello);

    // Parse the ClientHello message from the remaining bytes
    let client_hello = ClientHello::decode_from_exact(remaining).unwrap();

    // Verify the parsed values
    assert_eq!(client_hello.protocol_version, Protocol::TLSv1_2);

    // Check random bytes
    let expected_random = hex_to_bytes(
        "
        1b c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d
        b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76 48 7d 95
    ",
    );
    assert_eq!(client_hello.random.to_vec(), expected_random);

    // Check cipher suites
    assert_eq!(
        client_hello.offered_ciphers.list(),
        &[
            iana::constants::TLS_AES_128_GCM_SHA256,
            iana::constants::TLS_CHACHA20_POLY1305_SHA256,
            iana::constants::TLS_AES_256_GCM_SHA384,
        ]
    );

    // Check extensions
    assert!(!client_hello.extensions()?.is_empty());

    // Check for the presence of the pre_shared_key extension (for 0-RTT)
    let has_psk = client_hello
        .extensions()?
        .iter()
        .any(|ext| ext.extension_type == ExtensionType::PreSharedKey);

    assert!(
        has_psk,
        "Pre-shared key extension should be present for 0-RTT"
    );

    // Check for the presence of the early_data extension (for 0-RTT)
    let has_early_data = client_hello
        .extensions()?
        .iter()
        .any(|ext| ext.extension_type == ExtensionType::EarlyData);

    assert!(
        has_early_data,
        "Early data extension should be present for 0-RTT"
    );
    Ok(())
}

/// Test the ClientHello message from the HelloRetryRequest handshake in RFC8448
#[test]
fn test_client_hello_hello_retry_request() -> std::io::Result<()> {
    // ClientHello from RFC8448 section 5
    let client_hello_hex = "
        01 00 00 b0 03 03 b0 b1 c5 a5 aa 37 c5 91 9f 2e
        d1 d5 c6 ff f7 fc b7 84 97 16 94 5a 2b 8c ee 92
        58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01
        00 00 81 00 00 00 0b 00 09 00 00 06 73 65 72 76
        65 72 ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00
        17 00 18 00 33 00 26 00 24 00 1d 00 20 e8 e8 e3
        f3 b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27 2c 62 88
        e5 85 c6 48 4d 05 26 2f ca d0 62 ad 1f 00 2b 00
        03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
        02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
        04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
        00 02 40 01
    ";
    let client_hello_bytes = hex_to_bytes(client_hello_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&client_hello_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(handshake_header.handshake_type, HandshakeType::ClientHello);

    // Parse the ClientHello message from the remaining bytes
    let (client_hello, _) = ClientHello::decode_from(remaining).unwrap();

    // Verify the parsed values
    assert_eq!(client_hello.protocol_version, Protocol::TLSv1_2);

    // Check random bytes
    let expected_random = hex_to_bytes(
        "
        b0 b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc
        b7 84 97 16 94 5a 2b 8c ee 92 58 a3 46 67 7b 6f
    ",
    );
    assert_eq!(client_hello.random.to_vec(), expected_random);

    // Check cipher suites
    assert_eq!(
        client_hello.offered_ciphers.list(),
        &[
            iana::constants::TLS_AES_128_GCM_SHA256,
            iana::constants::TLS_CHACHA20_POLY1305_SHA256,
            iana::constants::TLS_AES_256_GCM_SHA384,
        ]
    );

    // Check for key share extension
    let key_share = client_hello
        .extensions()?
        .iter()
        .find(|ext| ext.extension_type == ExtensionType::KeyShare)
        .map(|ext| KeyShareClientHello::decode_from_exact(ext.extension_data.blob()).unwrap())
        .unwrap();

    // Verify key share contains x25519 key
    assert_eq!(key_share.client_shares.list().len(), 1);
    Ok(())
}

/// Test the HelloRetryRequest message from RFC8448
#[test]
fn test_hello_retry_request() {
    // HelloRetryRequest from RFC8448 section 5
    let hello_retry_request_hex = "
        02 00 00 ac 03 03 cf 21 ad 74 e5 9a 61 11 be 1d
        8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07 9e
        09 e2 c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02
        00 17 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18
        91 19 39 8a 00 00 00 00 ee fa fc 76 c1 46 b8 23
        b0 96 f8 aa ca d3 65 dd 00 30 95 3f 4e df 62 56
        36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10
        d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d
        6e 50 78 1b 5e da 4a a1 5b 0c 8b e7 78 25 7d 16
        aa 30 30 e9 e7 84 1d d9 e4 c0 34 22 67 e8 ca 0c
        af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03 04
    ";
    let hello_retry_request_bytes = hex_to_bytes(hello_retry_request_hex);

    // First parse the handshake message header
    let (handshake_header, remaining) =
        HandshakeMessageHeader::decode_from(&hello_retry_request_bytes).unwrap();

    // Verify the handshake header
    assert_eq!(handshake_header.handshake_type, HandshakeType::ServerHello);

    // Parse the ServerHello message from the remaining bytes
    let (server_hello, _) = ServerHello::decode_from(remaining).unwrap();

    // Verify the parsed values
    assert_eq!(server_hello.protocol_version, Protocol::TLSv1_2);

    // Check for supported_versions extension
    let supported_versions = server_hello
        .extensions
        .list()
        .iter()
        .find(|ext| ext.extension_type == ExtensionType::SupportedVersions)
        .map(|ext| {
            SupportedVersionServerHello::decode_from_exact(ext.extension_data.blob()).unwrap()
        })
        .unwrap();

    assert_eq!(supported_versions.selected_version, Protocol::TLSv1_3);

    // Check for key_share extension with selected group
    let has_key_share = server_hello
        .extensions
        .list()
        .iter()
        .any(|ext| ext.extension_type == ExtensionType::KeyShare);

    assert!(
        has_key_share,
        "Key share extension should be present in HelloRetryRequest"
    );
}
