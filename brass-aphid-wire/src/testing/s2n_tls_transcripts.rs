use crate::{
    codec::{DecodeValue, DecodeValueWithContext},
    decryption::transcript::TestPairExtension,
    iana::{self, HashAlgorithm, Protocol, SignatureAlgorithm, SignatureScheme},
    protocol::{
        extensions::{ClientHelloExtensionData, EcPointFormat, EcPointFormatList, ExtendedMasterSecret, ExtensionType},
        server_key_exchange::{ECCurveType, EcCurveValue},
        CertificateTls12ish, ChangeCipherSpec, ClientHello, ContentType, HandshakeMessageHeader,
        HandshakeType, RecordHeader, ServerHello, ServerKeyExchange, SigHashOrScheme,
        SignatureAndHashAlgorithm,
    },
};
use s2n_tls::{config::Config, enums::Mode, error::Error, security::Policy, testing::TestPair};

const SERVER_CHAIN: &[u8] = include_bytes!("../../certs/rsa2048/server-chain.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../certs/rsa2048/server-key.pem");
const CA_CERT: &[u8] = include_bytes!("../../certs/rsa2048/ca-cert.pem");

/// Helper function to create a server config for testing
fn create_config(security_policy: &str) -> Result<Config, Error> {
    let mut builder = Config::builder();
    builder
        .set_security_policy(&Policy::from_version(security_policy)?)?
        .load_pem(SERVER_CHAIN, SERVER_KEY)?
        .trust_pem(CA_CERT)?;

    builder.build()
}

fn tls13_transcript() -> Result<Vec<(Mode, Vec<u8>)>, Error> {
    // Create client and server configs
    let config = create_config("default_tls13")?;

    // Create TestPair
    let mut test_pair = TestPair::from_config(&config);
    let transcript = test_pair.enable_transcript();

    test_pair.client.set_server_name("localhost")?;

    test_pair.handshake()?;
    test_pair.client.poll_send(b"Hello from client!")?;

    // Receive and verify data on server
    let mut server_buffer = [0u8; 1024];
    let server_received = test_pair.server.poll_recv(&mut server_buffer)?;

    // Gracefully close the connection
    test_pair.client.poll_shutdown_send()?;
    test_pair.server.poll_shutdown_send()?;
    test_pair.client.poll_recv(&mut [0]);
    test_pair.server.poll_recv(&mut [0]);

    // Verify transcript
    let records = transcript.get_all_records();

    for (sender, record) in &records {
        println!("{sender:?}, {}", record.len());
    }

    Ok(records)
}

fn tls12_transcript() -> Result<Vec<(Mode, Vec<u8>)>, Error> {
    // Create client and server configs
    let config = create_config("default")?;

    // Create TestPair
    let mut test_pair = TestPair::from_config(&config);
    let transcript = test_pair.enable_transcript();

    test_pair.client.set_server_name("localhost")?;

    test_pair.handshake()?;
    test_pair.client.poll_send(b"Hello from client!")?;

    // Receive and verify data on server
    let mut server_buffer = [0u8; 1024];
    let server_received = test_pair.server.poll_recv(&mut server_buffer)?;

    // Gracefully close the connection
    test_pair.client.poll_shutdown_send()?;
    test_pair.server.poll_shutdown_send()?;
    test_pair.client.poll_recv(&mut [0]);
    test_pair.server.poll_recv(&mut [0]);

    // Verify transcript
    let records = transcript.get_all_records();

    for (sender, record) in &records {
        println!("{sender:?}, {}", record.len());
    }

    Ok(records)
}

#[test]
fn weird_group() {
    let weird: u16 = 2057;
    let s = SigHashOrScheme::decode_from_exact(&weird.to_be_bytes()).unwrap();
}

/// Test a complete TLS 1.3 handshake with application data exchange
#[test]
fn tls13() -> std::io::Result<()> {
    let mut writes = tls13_transcript().unwrap().into_iter();

    // client hello
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(handshake_header.handshake_type, HandshakeType::ClientHello);

        let client_hello = ClientHello::decode_from_exact(buffer)?;

        assert_eq!(client_hello.protocol_version, Protocol::TLSv1_2);
        assert_eq!(client_hello.session_id.blob().len(), 32);
        assert_eq!(
            client_hello.offered_ciphers.list(),
            &[
                iana::constants::TLS_AES_128_GCM_SHA256,
                iana::constants::TLS_AES_256_GCM_SHA384,
                iana::constants::TLS_CHACHA20_POLY1305_SHA256,
                iana::constants::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                iana::constants::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                iana::constants::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                iana::constants::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                iana::constants::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                iana::constants::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                iana::constants::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                iana::constants::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                iana::constants::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                iana::constants::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                iana::constants::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ]
        );
        assert_eq!(client_hello.compression_methods.blob().len(), 1);
        let mut extensions = client_hello.extensions.unwrap().list().to_vec();
        let mut extensions = extensions.drain(..);

        // extension: supported versions
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::SupportedVersions);
            if let ClientHelloExtensionData::SupportedVersions(s) = ext.extension_data {
                assert_eq!(s.versions.list(), &[Protocol::TLSv1_3, Protocol::TLSv1_2]);
            } else {
                panic!("unexpected enum");
            }
        }

        // extension: supported groups
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::SupportedGroups);
            if let ClientHelloExtensionData::SupportedGroups(s) = ext.extension_data {
                assert_eq!(
                    s.named_curve_list.list(),
                    &[
                        iana::constants::secp256r1,
                        iana::constants::x25519,
                        iana::constants::secp384r1,
                        iana::constants::secp521r1,
                    ]
                );
            } else {
                panic!("unexpected enum");
            }
        }

        // extension: key share
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::KeyShare);
            if let ClientHelloExtensionData::KeyShare(s) = ext.extension_data {
                let shares: Vec<iana::Group> = s
                    .client_shares
                    .list()
                    .iter()
                    .map(|share| share.group)
                    .collect();
                assert_eq!(shares, vec![iana::constants::secp256r1]);
            } else {
                panic!("unexpected enum");
            }
        }

        // extension: signature algorithm
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::SignatureAlgorithms);
            if let ClientHelloExtensionData::SignatureScheme(s) = ext.extension_data {
                assert_eq!(
                    s.supported_signature_algorithms.list(),
                    &[
                        SigHashOrScheme::SignatureHash(SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha256,
                            signature: SignatureAlgorithm::Ecdsa
                        }),
                        SigHashOrScheme::SignatureHash(SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha384,
                            signature: SignatureAlgorithm::Ecdsa
                        }),
                        SigHashOrScheme::SignatureHash(SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha512,
                            signature: SignatureAlgorithm::Ecdsa
                        }),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_pss_sha256),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_pss_sha384),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_pss_sha512),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_rsae_sha256),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_rsae_sha384),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_rsae_sha512),
                        SigHashOrScheme::SignatureHash(SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha256,
                            signature: SignatureAlgorithm::Rsa
                        }),
                        SigHashOrScheme::SignatureHash(SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha384,
                            signature: SignatureAlgorithm::Rsa
                        }),
                        SigHashOrScheme::SignatureHash(SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha512,
                            signature: SignatureAlgorithm::Rsa
                        })
                    ]
                );
            } else {
                panic!("unexpected enum");
            }
        }

        // extension: server name
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::ServerName);
            if let ClientHelloExtensionData::ServerName(s) = ext.extension_data {
                let list =  s.server_name_list.list();
                assert_eq!(list.len(), 1);
                assert_eq!(String::from_utf8(list[0].host_name.blob().to_vec()).unwrap(), "localhost".to_string());
            } else {
                panic!("unexpected enum");
            }
        }

        // extension: ec point formats
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::EcPointFormats);
            if let ClientHelloExtensionData::EcPointFormat(s) = ext.extension_data {
                assert_eq!(s.ec_point_format_list.list(), &[EcPointFormat::Uncompressed]);
            } else {
                panic!("unexpected enum");
            }
        }

        // extension: extended master secret
        {
            let ext = extensions.next().unwrap();
            assert_eq!(ext.extension_type, ExtensionType::ExtendedMasterSecret);
            if let ClientHelloExtensionData::ExtendedMasterSecret(s) = ext.extension_data {
                assert_eq!(s, ExtendedMasterSecret {});
            } else {
                panic!("unexpected enum");
            }
        }
    }

    // server hello
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(handshake_header.handshake_type, HandshakeType::ServerHello);

        let server_hello = ServerHello::decode_from_exact(buffer)?;
        assert_eq!(server_hello.selected_version()?, Protocol::TLSv1_3);
    }

    // CCS
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::ChangeCipherSpec);

        let ccs = ChangeCipherSpec::decode_from_exact(buffer)?;
        assert_eq!(ccs, ChangeCipherSpec::ChangeCipherSpec)
    }

    // everything else is encrypted

    Ok(())
}

#[test]
fn tls12() -> std::io::Result<()> {
    let mut writes = tls12_transcript().unwrap().into_iter();

    // client hello
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(handshake_header.handshake_type, HandshakeType::ClientHello);

        let client_hello = ClientHello::decode_from_exact(buffer)?;
    }

    // server hello
    let selected_cipher = {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(handshake_header.handshake_type, HandshakeType::ServerHello);

        let server_hello = ServerHello::decode_from_exact(buffer)?;
        assert_eq!(server_hello.selected_version()?, Protocol::TLSv1_2);
        server_hello.cipher_suite
    };

    // certificate
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(handshake_header.handshake_type, HandshakeType::Certificate);

        let certificate = CertificateTls12ish::decode_from_exact(buffer)?;
    }

    // server key exchange
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(
            handshake_header.handshake_type,
            HandshakeType::ServerKeyExchange
        );
        assert_eq!(handshake_header.handshake_message_length.0, 329);

        let (key_exchange, buffer) =
            ServerKeyExchange::decode_from_with_context(buffer, selected_cipher).unwrap();
        if let ServerKeyExchange::Ecdhe { params, signature } = key_exchange {
            assert_eq!(params.curve_params.curve_type, ECCurveType::NamedCurve);
            if let EcCurveValue::NamedCurve(group) = params.curve_params.curve_value {
                assert_eq!(group.description, "secp256r1");
            } else {
                panic!("expected named curve");
            }
        } else {
            panic!("expected ecdhe kx")
        }
        assert!(buffer.is_empty());
    }

    // ServerHelloDone
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let handshake_header = HandshakeMessageHeader::decode_from_exact(buffer)?;
        assert_eq!(
            handshake_header.handshake_type,
            HandshakeType::ServerHelloDone
        );

        // Server Done is zero sized
    }

    // ClientKeyExchange
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        assert_eq!(
            handshake_header.handshake_type,
            HandshakeType::ClientKeyExchange
        );

        // TODO: not defined
    }

    // CCS - client
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::ChangeCipherSpec);

        let ccs = ChangeCipherSpec::decode_from_exact(buffer)?;
        assert_eq!(ccs, ChangeCipherSpec::ChangeCipherSpec)
    }

    // Finished - client
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        // encrypted
    }

    // CCS - server
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::ChangeCipherSpec);

        let ccs = ChangeCipherSpec::decode_from_exact(buffer)?;
        assert_eq!(ccs, ChangeCipherSpec::ChangeCipherSpec)
    }

    // Finished - server
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Handshake);

        // encrypted
    }

    // Application Data
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::ApplicationData);
    }

    // Alert from client
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Client);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Alert);
    }

    // Alert from server
    {
        let (sender, record) = writes.next().unwrap();

        assert_eq!(sender, Mode::Server);
        let buffer = record.as_slice();

        let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
        assert_eq!(record_header.content_type, ContentType::Alert);
    }

    Ok(())
}
