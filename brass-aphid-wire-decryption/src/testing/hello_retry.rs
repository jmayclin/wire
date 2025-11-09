use crate::{
    decryption::{key_manager::KeyManager, DecryptingPipe, Mode},
    testing::utilities::{s2n_server_config, SigType},
};
use brass_aphid_wire_messages::protocol::{
    content_value::{ContentValue, HandshakeMessageValue},
    ChangeCipherSpec, ServerHelloConfusionMode,
};
use s2n_tls::testing::TestPair;

#[test]
fn key_update_request() -> anyhow::Result<()> {
    let key_manager = KeyManager::new();

    let client_config = s2n_server_config("default_tls13", &[SigType::Rsa3072]).unwrap();
    /// RFC9151 will only accept secp384
    let mut server_config = s2n_server_config("rfc9151", &[SigType::Rsa3072]).unwrap();
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

    assert!(test_pair
        .client
        .poll_send(b"omg, let's be besties")
        .is_ready());
    assert!(test_pair.server.poll_recv(&mut [0; 100]).is_ready());

    // the complicated shutdown dance is required so that the client and server
    // are always reading the CloseNotify in the same order. While this normally
    // doesn't matter, we want to reuse these assertions for both client and
    // server decryption.
    assert!(test_pair.client.poll_shutdown_send().is_ready());
    assert!(test_pair.server.poll_recv(&mut [0]).is_ready());

    assert!(test_pair.server.poll_shutdown_send().is_ready());
    assert!(test_pair.client.poll_recv(&mut [0]).is_ready());

    let mut messages = stream_decrypter
        .decrypter
        .transcript
        .lock()
        .unwrap()
        .clone();
    let application_data: Vec<String> = messages
        .iter()
        .filter_map(|(sender, content)| {
            if let ContentValue::ApplicationData(d) = content {
                Some(String::from_utf8(d.clone()).unwrap())
            } else {
                None
            }
        })
        .collect();
    let mut messages = messages.drain(..);

    let (sender, content) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(
        content.as_handshake(),
        HandshakeMessageValue::ClientHello(_)
    ));

    let (sender, content) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        content,
        ContentValue::Handshake(HandshakeMessageValue::ServerHelloConfusion(
            ServerHelloConfusionMode::HelloRetryRequest(_)
        ))
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Server);
    assert!(matches!(
        message,
        ContentValue::ChangeCipherSpec(ChangeCipherSpec::ChangeCipherSpec)
    ));

    let (sender, message) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(
        message,
        ContentValue::ChangeCipherSpec(ChangeCipherSpec::ChangeCipherSpec)
    ));

    let (sender, content) = messages.next().unwrap();
    assert_eq!(sender, Mode::Client);
    assert!(matches!(
        content,
        ContentValue::Handshake(HandshakeMessageValue::ClientHello(_))
    ));

    let (sender, content) = messages.next().unwrap();
    assert!(matches!(
        content,
        ContentValue::Handshake(HandshakeMessageValue::ServerHelloConfusion(
            ServerHelloConfusionMode::ServerHello(_)
        ))
    ));

    assert_eq!(application_data, vec!["omg, let's be besties".to_string(),]);

    Ok(())
}
