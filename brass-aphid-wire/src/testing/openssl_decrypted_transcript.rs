use std::io::{Read, Write};

use openssl::ssl::{ShutdownResult, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode};
use s2n_tls::testing::TestPair;

use crate::{
    decryption::{
        key_manager::KeyManager, s2n_tls_intercept::{intercept_recv_callback, intercept_send_callback, ArchaicCPipe}, DecryptingPipe
    },
    protocol::content_value::{ContentValue, HandshakeMessageValue},
    stream_decrypter::Mode,
    testing::utilities::{get_cert_path, s2n_server_config, PemType, SigType},
};

#[test]
fn openssl_server_test() -> anyhow::Result<()> {
    let key_manager = KeyManager::new();
    let key_manager_handle = key_manager.clone();

    let client_config = {
        let mut builder = SslContext::builder(SslMethod::tls_client())?;
        builder.set_ca_file(get_cert_path(PemType::CACert, SigType::Rsa2048))?;
        builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
        builder.set_keylog_callback(move |sslref, key_log| {
            key_manager_handle.parse_key_log_line(key_log.as_bytes());
        });
        builder.build()
    };

    let server_config = {
        let mut builder = SslContext::builder(SslMethod::tls_server())?;
        builder.set_certificate_chain_file(get_cert_path(
            PemType::ServerCertChain,
            SigType::Rsa2048,
        ))?;
        builder.set_private_key_file(
            get_cert_path(PemType::ServerKey, SigType::Rsa2048),
            SslFiletype::PEM,
        )?;
        builder.build()
    };

    let client =  Ssl::new(&client_config)?;
    let server = Ssl::new(&server_config)?;

    let server_tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let server_addr = server_tcp.local_addr()?;

    const MESSAGE: &[u8] = b"hello from the openssl client";

    let mut transcript = std::thread::scope(|s| {
        s.spawn(|| {
            let (server_stream, client_addr) = server_tcp.accept().unwrap();
            let mut stream = SslStream::new(server, server_stream).unwrap();
            stream.accept().unwrap();
            stream.do_handshake().unwrap();
            let mut buffer = [0; MESSAGE.len()];
            stream.read_exact(&mut buffer);
            let shutdown_state = stream.shutdown().unwrap();
            if shutdown_state != ShutdownResult::Received {
                let state = stream.shutdown().unwrap();
                assert_eq!(state, ShutdownResult::Received);
            }
        });
        let decrypter = s.spawn(move || {
            let client_stream = std::net::TcpStream::connect(server_addr).unwrap();
            let decrypting_pipe = DecryptingPipe::new(key_manager, client_stream);
            let decrypter = decrypting_pipe.decrypter.clone();
            let mut stream = SslStream::new(client, decrypting_pipe).unwrap();
            stream.connect().unwrap();
            stream.write_all(MESSAGE);
            let shutdown_state = stream.shutdown().unwrap();
            if shutdown_state != ShutdownResult::Received {
                let state = stream.shutdown().unwrap();
                assert_eq!(state, ShutdownResult::Received);
            }
            decrypter
        }).join().unwrap();
        let decrypter = decrypter.lock().unwrap();
        decrypter.transcript.clone()
    });

    let mut messages = transcript.drain(..);

    // handshake starts
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::ClientHello(_))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::ServerHello(_))
    ));

    // encrypted data
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::EncryptedExtensions(_))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::CertificateTls13(_))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::CertVerifyTls13(_))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::Finished(_))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::Finished(_))
    ));

    // handshake finished -> application data

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    if let ContentValue::ApplicationData(data) = message {
        assert_eq!(&data, MESSAGE);
    } else {
        panic!("unexpected message");
    }

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(message, ContentValue::Alert(_)));

    // client's first read since finishing the handshake

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(message, ContentValue::Handshake(HandshakeMessageValue::NewSessionTicketTls13(_))));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(message, ContentValue::Handshake(HandshakeMessageValue::NewSessionTicketTls13(_))));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(message, ContentValue::Alert(_)));

    assert!(messages.next().is_none());

    Ok(())
}
