use s2n_tls::testing::TestPair;

use crate::{
    decryption::{key_manager::KeyManager, DecryptingPipe},
    protocol::content_value::{ContentValue, HandshakeMessageValue},
    stream_decrypter::Mode,
    testing::utilities::{s2n_server_config, SigType},
};

#[test]
fn s2n_server_test() -> anyhow::Result<()> {
    let key_manager = KeyManager::new();

    let client_config = s2n_server_config("default_tls13", &[SigType::Rsa3072]).unwrap();
    let mut server_config = s2n_server_config("default_tls13", &[SigType::Rsa3072]).unwrap();
    key_manager.enable_s2n_logging(&mut server_config);
    let mut test_pair = TestPair::from_configs(&client_config.build()?, &server_config.build()?);

    test_pair
        .client
        .set_server_name("omg💅heyyy✨bestie💖lets👪do💌tls🔒")
        .unwrap();

    let decrypting_stream = DecryptingPipe::s2n_tls_decrypter(key_manager, &mut test_pair.server);

    let stream_decrypter = Box::new(decrypting_stream);
    DecryptingPipe::enable_s2n_tls_decryption(&stream_decrypter, &mut test_pair.server);

    test_pair.handshake().unwrap();

    let mut message_buffer = [0; b"i am the client".len()];

    test_pair.client.poll_send(b"i am the client");
    test_pair.server.poll_recv(&mut message_buffer);

    test_pair.server.poll_send(b"i am the server");
    test_pair.client.poll_recv(&mut message_buffer);

    // the complicated shutdown dance is required so that the client and server
    // are always reading the CloseNotify in the same order. While this normally
    // doesn't matter, we want to reuse these assertions for both client and
    // server decryption.
    test_pair.client.poll_shutdown_send();
    test_pair.server.poll_recv(&mut [0]);

    test_pair.server.poll_shutdown_send();
    test_pair.client.poll_recv(&mut [0]);

    let messages = stream_decrypter.decrypter.transcript.clone();
    assert_s2n_decryption_correct(messages.lock().unwrap().clone());

    Ok(())
}

#[test]
fn s2n_client_test() -> anyhow::Result<()> {
    let key_manager = KeyManager::new();

    let mut client_config = s2n_server_config("default_tls13", &[SigType::Rsa3072]).unwrap();
    let server_config = s2n_server_config("default_tls13", &[SigType::Rsa3072]).unwrap();
    key_manager.enable_s2n_logging(&mut client_config);
    let mut test_pair = TestPair::from_configs(&client_config.build()?, &server_config.build()?);

    test_pair
        .client
        .set_server_name("omg💅heyyy✨bestie💖lets👪do💌tls🔒")
        .unwrap();

    let decrypting_stream = DecryptingPipe::s2n_tls_decrypter(key_manager, &mut test_pair.client);

    let stream_decrypter = Box::new(decrypting_stream);
    DecryptingPipe::enable_s2n_tls_decryption(&stream_decrypter, &mut test_pair.client);

    test_pair.handshake().unwrap();

    let mut message_buffer = [0; b"i am the client".len()];

    test_pair.client.poll_send(b"i am the client");
    test_pair.server.poll_recv(&mut message_buffer);

    test_pair.server.poll_send(b"i am the server");
    test_pair.client.poll_recv(&mut message_buffer);

    // the complicated shutdown dance is required so that the client and server
    // are always reading the CloseNotify in the same order. While this normally
    // doesn't matter, we want to reuse these assertions for both client and
    // server decryption.
    test_pair.client.poll_shutdown_send();
    test_pair.server.poll_recv(&mut [0]);

    test_pair.server.poll_shutdown_send();
    test_pair.client.poll_recv(&mut [0]);

    let messages = stream_decrypter
        .decrypter
        .transcript
        .lock()
        .unwrap()
        .clone();
    assert_s2n_decryption_correct(messages);

    Ok(())
}

fn assert_s2n_decryption_correct(mut messages: Vec<(Mode, ContentValue)>) {
    let mut messages = messages.drain(..);

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
        assert_eq!(&data, b"i am the client");
    } else {
        panic!("unexpected message");
    }

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    if let ContentValue::ApplicationData(data) = message {
        assert_eq!(&data, b"i am the server");
    } else {
        panic!("unexpected message");
    }

    // application finished -> alerts

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(message, ContentValue::Alert(_)));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(message, ContentValue::Alert(_)));

    assert!(messages.next().is_none());
}
