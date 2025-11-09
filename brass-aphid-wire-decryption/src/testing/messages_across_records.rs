use core::ffi;
use std::io::{Read, Write};

use crate::{
    decryption::{key_manager::KeyManager, DecryptingPipe, Mode},
    testing::utilities::{get_cert_path, PemType, SigType},
};
use brass_aphid_wire_messages::protocol::{
    content_value::ContentValue, ContentType, HandshakeType,
};
use openssl::ssl::{
    ShutdownResult, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslStream,
    SslVerifyMode,
};
use openssl_sys::{SSL_CTX_ctrl, SSL_CTX};

// # define SSL_CTX_set_max_send_fragment(ctx,m) \
//        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)
fn SSL_CTX_set_max_send_fragment(ctx: *mut SSL_CTX, length: std::ffi::c_long) -> std::ffi::c_long {
    // https://github.com/openssl/openssl/blob/49f8db53274191987b57d8e5542218690a983e35/include/openssl/ssl.h.in#L1260
    const SSL_CTRL_SET_MAX_SEND_FRAGMENT: ffi::c_int = 52;
    unsafe {
        SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MAX_SEND_FRAGMENT,
            length,
            std::ptr::null_mut(),
        )
    }
}

trait SslContextExtension {
    fn set_max_send_fragment(&mut self, length: u64);
}

impl SslContextExtension for SslContextBuilder {
    fn set_max_send_fragment(&mut self, length: u64) {
        let ptr = self.as_ptr();
        let res = SSL_CTX_set_max_send_fragment(ptr, length as _);
        assert_eq!(res, 1);
    }
}

#[test]
fn single_message_many_records() -> anyhow::Result<()> {
    let key_manager = KeyManager::new();
    let key_manager_handle = key_manager.clone();

    let client_config = {
        let mut builder = SslContext::builder(SslMethod::tls_client())?;
        builder.set_max_send_fragment(512);
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
            stream.read_exact(&mut buffer).unwrap();
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
                stream.write_all(MESSAGE).unwrap();
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

    // std::fs::write("resources/traces/openssl.log", format!("{transcript:#?}"));

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

    // encrypted data
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
    assert_eq!(sender, Mode::Client);
    assert_eq!(message.content_type(), ContentType::ChangeCipherSpec);

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert_eq!(
        message.as_handshake().handshake_type(),
        HandshakeType::Finished
    );

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
    assert_eq!(message.content_type(), ContentType::Alert);

    // client's first read since finishing the handshake

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
    assert_eq!(message.content_type(), ContentType::Alert);

    assert!(messages.next().is_none());

    Ok(())
}
