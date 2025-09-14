use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
};

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use brass_aphid_wire_messages::protocol::{ContentType, HandshakeType};
use crate::{
    decryption::{key_manager::KeyManager, DecryptingPipe, Mode},
    testing::utilities::{get_cert_path, PemType, SigType},
};

struct NoVerify {}

#[test]
fn rustls_client_test() -> anyhow::Result<()> {
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

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?
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
                let client_stream = std::net::TcpStream::connect(server_addr).unwrap();

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

    // std::fs::write("resources/traces/rustls_0_23.log", format!("{transcript:#?}"));

    let mut messages = transcript.drain(..);

    // handshake starts
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::ClientHello
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::ServerHello
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert_eq!(message.content_type(), ContentType::ChangeCipherSpec);

    // encrypted data
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::Finished
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(message.content_type(), ContentType::ChangeCipherSpec);

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::EncryptedExtensions
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::Certificate
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::CertificateVerify
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::Finished
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::NewSessionTicket
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::NewSessionTicket
    );

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(message.content_type(), ContentType::ApplicationData);

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(message.content_type(), ContentType::Alert);

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert_eq!(message.content_type(), ContentType::Alert);

    assert!(messages.next().is_none());
    // assert!(false);

    Ok(())
}
