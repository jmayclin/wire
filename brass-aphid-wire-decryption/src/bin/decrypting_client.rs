use std::{io::Read, time::Duration};

use brass_aphid_wire_decryption::decryption::{key_manager::KeyManager, DecryptingPipe};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream};

const DOMAIN: &str = "postman-echo.com";
const PORT: u16 = 443;

fn main() -> anyhow::Result<()> {
    // first we create a KeyManager. Most TLS implementation will set the key-logging
    // callback per-config. The KeyManager provides that callback.
    let key_manager = KeyManager::new();

    let client_config = {
        let key_manager_handle = key_manager.clone();
        let mut builder = SslContext::builder(SslMethod::tls_client())?;
        builder.set_keylog_callback(move |sslref, key_log| {
            // move, so the config stores its own copy of the KeyManager, which is
            // internally reference counted.
            key_manager_handle.parse_key_log_line(key_log.as_bytes());
        });
        builder.build()
    };

    let client = Ssl::new(&client_config)?;

    // configure the "normal" transport stream.
    let client_stream = std::net::TcpStream::connect(format!("{DOMAIN}:{PORT}")).unwrap();
    client_stream.set_read_timeout(Some(Duration::from_secs(1)));

    // wrap the transport stream in the "decrypting pipe", associating the key manager
    // from before with the decrypting pipe.
    let decrypting_pipe = DecryptingPipe::new(key_manager, client_stream);

    // hold a reference to the transcript, which we can look at after the handshake
    // (or during the handshake)
    let transcript = decrypting_pipe.decrypter.transcript.clone();

    // construct the actual SslStream.
    let mut stream = SslStream::new(client, decrypting_pipe).unwrap();
    stream.connect().unwrap();
    // this read is necessary to make the client read in the "secret" data that the server
    // sends after the handshake (which is the NST).
    // We set the read_timeout earlier so that this doesn't just hand forever.
    stream.read(&mut []);
    stream.shutdown().unwrap();

    let transcript_trace = format!("{:#?}", *transcript.lock().unwrap());
    std::fs::write(DOMAIN, transcript_trace).unwrap();

    Ok(())
}
