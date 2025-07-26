use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use openssl::ssl::{
    ShutdownResult, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode,
};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server, RootCertStore,
};

use crate::{
    decryption::{key_manager::KeyManager, DecryptingPipe},
    protocol::content_value::{ContentValue, HandshakeMessageValue},
    stream_decrypter::Mode,
    testing::utilities::{get_cert_path, PemType, SigType},
};

struct NoVerify {}

#[test]
fn rustls_client_test() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let key_manager = KeyManager::new();
    let key_manager_handle = key_manager.clone();

    let client_config = {
        let mut roots = RootCertStore::empty();
        let ca = CertificateDer::from_pem_file(get_cert_path(PemType::CACert, SigType::Rsa2048))
            .unwrap();
        roots.add(ca).unwrap();

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.key_log = Arc::new(key_manager_handle);
        config
    };

    // server config

    let server_config = {
        let cert_file = get_cert_path(PemType::ServerCertChain, SigType::Rsa2048);
        let private_key_file = get_cert_path(PemType::ServerKey, SigType::Rsa2048);

        let certs = CertificateDer::pem_file_iter(cert_file)
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect();
        let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;
        config
    };
    let mut server = rustls::ServerConnection::new(Arc::new(server_config))?;

    let server_tcp = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let server_addr = server_tcp.local_addr().unwrap();

    const MESSAGE: &[u8] = b"Hello from the server";

    let mut transcript = std::thread::scope(|s| {
        s.spawn(|| {
            let (mut server_stream, client_addr) = server_tcp.accept().unwrap();
            // let mut stream = SslStream::new(server, server_stream).unwrap();
            let mut tls_stream = rustls::Stream::new(&mut server, &mut server_stream);
            tls_stream.write_all(MESSAGE).unwrap();
            tls_stream.flush().unwrap();
            tls_stream.conn.send_close_notify();
            tls_stream.write(&[]);
            let closed = tls_stream.read(&mut []);
        });
        let transcript = s
            .spawn(move || {
                let mut client_stream = std::net::TcpStream::connect(server_addr).unwrap();

                let server_name = "localhost".try_into().unwrap();
                let mut conn =
                    rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();

                //let mut decrypting_pipe = DecryptingPipe::new(key_manager, std::io::Cursor::new(Vec::new()));
                //let mut tls = rustls::Stream::new(&mut conn, &mut client_stream);
                let mut decrypting_pipe = DecryptingPipe::new(key_manager, client_stream);
                let mut tls = rustls::Stream::new(&mut conn, &mut decrypting_pipe);
                let mut buffer = [0; MESSAGE.len()];
                tls.read_exact(&mut buffer);
                let shutdown = tls.read(&mut []);
                tls.conn.send_close_notify();
                tls.write(&[]);

                decrypting_pipe.decrypter.transcript.clone()
            })
            .join()
            .unwrap();
        let transcript = transcript.lock().unwrap();
        transcript.clone()
    });

    // std::fs::write("resources/traces/broken-rustls.log", format!("{transcript:#?}"));

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

    // MISSING ENCRYPTED EXTENSION, CERTIFICATE, CERTIFICATE VERIFY?
    // let (sender, message) = messages.next().unwrap();
    // assert_eq!(sender, Mode::Server);
    // assert!(matches!(
    //     message,
    //     ContentValue::Handshake(HandshakeMessageValue::EncryptedExtensions(_))
    // ));

    // encrypted data
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::Finished(_))
    ));

    // encrypted data
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::Handshake(HandshakeMessageValue::NewSessionTicketTls13(_))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(message, ContentValue::ApplicationData(_)));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(message, ContentValue::Alert(_)));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(message, ContentValue::Alert(_)));

    assert!(messages.next().is_none());
    // assert!(false);

    Ok(())
}
