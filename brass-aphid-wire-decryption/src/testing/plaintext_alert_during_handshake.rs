use std::{
    io::{Read, Write},
    net::TcpStream,
    task::Poll,
};

use crate::{
    decryption::{
        key_manager::KeyManager,
        s2n_tls_intercept::{generic_recv_cb, generic_send_cb},
        DecryptingPipe, Mode,
    },
    testing::utilities::{get_cert_path, s2n_server_config, PemType, SigType},
};
use brass_aphid_wire_messages::protocol::{
    content_value::ContentValue, Alert, AlertDescription, AlertLevel, ContentType, HandshakeType,
};
use openssl::ssl::{
    ShutdownResult, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode,
};

#[test]
fn openssl_server_test() -> anyhow::Result<()> {
    // tracing_subscriber::fmt()
    //     .with_max_level(tracing::Level::TRACE)
    //     .init();

    let key_manager = KeyManager::new();
    let key_manager_handle = key_manager.clone();

    let client_config = {
        let mut builder = SslContext::builder(SslMethod::tls_client())?;
        builder.set_ca_file(get_cert_path(PemType::CACert, SigType::Rsa2048))?;
        builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
        builder.set_sigalgs_list("rsa_pss_pss_sha256").unwrap();
        builder.build()
    };

    let server_config = {
        let mut config = s2n_server_config("20250211", &[SigType::Rsa3072]).unwrap();
        key_manager.enable_s2n_logging(&mut config);
        config.build().unwrap()
    };

    let mut server = s2n_tls::connection::Connection::new_server();
    server.set_config(server_config).unwrap();

    let client = Ssl::new(&client_config)?;

    let server_tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let server_addr = server_tcp.local_addr()?;

    let transcript = std::thread::scope(|s| {
        let transcript = s.spawn(|| {
            let (server_stream, _client_addr) = server_tcp.accept().unwrap();
            // setup IO
            let boxed_stream = Box::new(server_stream);
            {
                server
                    .set_receive_callback(Some(generic_recv_cb::<TcpStream>))
                    .unwrap();
                server
                    .set_send_callback(Some(generic_send_cb::<TcpStream>))
                    .unwrap();
                unsafe {
                    server.set_receive_context(boxed_stream.as_ref() as *const TcpStream as *mut _)
                }
                .unwrap();
                unsafe {
                    server.set_send_context(boxed_stream.as_ref() as *const TcpStream as *mut _)
                }
                .unwrap();
            }

            // setup decryption
            let stream_decrypter = {
                let decrypting_stream = DecryptingPipe::s2n_tls_decrypter(key_manager, &mut server);
                decrypting_stream
            };

            loop {
                if let Poll::Ready(Err(e)) = server.poll_negotiate() {
                    println!("hit an error: {e:?}");
                    break;
                }
            }

            stream_decrypter.decrypter.transcript()
        });

        // spawn the client, and wait for it to finish
        s.spawn(move || {
            let client_stream = std::net::TcpStream::connect(server_addr).unwrap();
            let mut stream = SslStream::new(client, client_stream).unwrap();
            let connect_err = stream.connect().unwrap_err();
            println!("connect error: {connect_err:?}");
        })
        .join()
        .unwrap();

        // get the transcript from the server thread
        transcript.join().unwrap()
    });

    let mut transcript = transcript.content_transcript.lock().unwrap().clone();
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

    // encrypted data
    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert_eq!(message.content_type(), ContentType::ChangeCipherSpec);

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert_eq!(message.content_type(), ContentType::ChangeCipherSpec);

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

    // encrypted data
    let (sender, message) = messages.next().unwrap();
    println!("{sender:?}, {message:?}");
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

    // because we're sending over a TCP stream/multiple threads, this is not deterministic
    // Sometimes the alert is received from the client before the server finished,
    // sometimes afterwards.

    let alert = messages
        .inspect(|(sender, message)| {
            if let ContentValue::Alert(alert) = message {
                println!("alert was {alert:?}");
            }
        })
        .find(|(sender, message)| {
            let client_sender = *sender == Mode::Client;
            let correct_alert = matches!(
                message,
                ContentValue::Alert(Alert {
                    level: AlertLevel::Fatal,
                    description: AlertDescription::UnknownCA
                })
            );
            client_sender && correct_alert
        });
    assert!(alert.is_some());

    Ok(())
}
