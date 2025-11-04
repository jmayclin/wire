use crate::{
    decryption::{key_manager::KeyManager, DecryptingPipe, Mode},
    testing::utilities::{s2n_server_config, SigType},
};
use brass_aphid_wire_messages::protocol::{
    content_value::{ContentValue, HandshakeMessageValue},
    ChangeCipherSpec,
};
use s2n_tls::testing::TestPair;

#[test]
fn key_update_request() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

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

    test_pair.client.poll_send(b"before key update");
    test_pair
        .client
        .request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested);
    test_pair.client.poll_send(b"after client key update 1");

    test_pair.server.poll_recv(&mut [0; 100]);

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
    let application_data: Vec<String> = messages
        .into_iter()
        .filter_map(|(sender, content)| {
            if let ContentValue::ApplicationData(d) = content {
                Some(String::from_utf8(d).unwrap())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        application_data,
        vec![
            "before key update".to_string(),
            "after client key update 1".to_string()
        ]
    );

    Ok(())
}
