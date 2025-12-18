use std::io::{Read, Write};

use crate::{
    decryption::{DecryptingPipe, Mode, key_manager::KeyManager},
    testing::utilities::{ContentValueTestEquality, PemType, SigType, get_cert_path},
};
use brass_aphid_wire_messages::protocol::{
    content_value::ContentValue, ContentType, HandshakeType,
};
use openssl::ssl::{
    ShutdownResult, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode,
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

    let client = Ssl::new(&client_config)?;
    let server = Ssl::new(&server_config)?;

    let server_tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let server_addr = server_tcp.local_addr()?;

    const MESSAGE: &[u8] = b"hello from the openssl client";

    let mut transcript = std::thread::scope(|s| {
        s.spawn(|| {
            let (server_stream, _client_addr) = server_tcp.accept().unwrap();
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
        let transcript = s
            .spawn(move || {
                let client_stream = std::net::TcpStream::connect(server_addr).unwrap();
                let decrypting_pipe = DecryptingPipe::new(key_manager, client_stream);
                let decrypter = decrypting_pipe.decrypter.transcript.clone();
                let mut stream = SslStream::new(client, decrypting_pipe).unwrap();
                stream.connect().unwrap();
                stream.write_all(MESSAGE);
                let shutdown_state = stream.shutdown().unwrap();
                if shutdown_state != ShutdownResult::Received {
                    let state = stream.shutdown().unwrap();
                    assert_eq!(state, ShutdownResult::Received);
                }
                decrypter
            })
            .join()
            .unwrap();
        let transcript = transcript.lock().unwrap();
        transcript.clone()
    });

    // std::fs::write("resources/traces/openssl_3_5.log", format!("{transcript:#?}"));

    // validate transcript
    {
        let expected_app_data = ContentValue::ApplicationData(MESSAGE.to_vec());
        let expected_transcript: Vec<(Mode, &dyn ContentValueTestEquality)> = vec![
            // handshake starts
            (Mode::Client, &HandshakeType::ClientHello),
            (Mode::Server, &HandshakeType::ServerHello),
            (Mode::Server, &ContentType::ChangeCipherSpec),
            (Mode::Server, &HandshakeType::EncryptedExtensions),
            (Mode::Server, &HandshakeType::Certificate),
            (Mode::Server, &HandshakeType::CertificateVerify),
            (Mode::Server, &HandshakeType::Finished),
            (Mode::Client, &ContentType::ChangeCipherSpec),
            (Mode::Client, &HandshakeType::Finished),
            // handshake finished, now application data
            (Mode::Client, &expected_app_data),
            (Mode::Client, &ContentType::Alert),
            // client's first read since finishing the handshake
            (Mode::Server, &HandshakeType::NewSessionTicket),
            (Mode::Server, &HandshakeType::NewSessionTicket),
            (Mode::Server, &ContentType::Alert),
        ];

        let mut messages = transcript.drain(..);
        for (i, (sender, content)) in expected_transcript.into_iter().enumerate() {
            let (actual_sender, actual_content) = messages.next().unwrap();
            assert_eq!(actual_sender, sender);
            assert!(content.same_as(actual_content));
        }
        assert!(messages.next().is_none());
    }

    Ok(())
}
