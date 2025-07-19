use std::{io::Read, time::Duration};

use brass_aphid_wire::decryption::{key_manager::KeyManager, DecryptingPipe};
use openssl::ssl::{ShutdownResult, Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};

const DOMAIN: &str = "www.amazon.com";
const PORT: u16 = 443;

fn main() -> anyhow::Result<()> {
    let key_manager = KeyManager::new();
    let key_manager_handle = key_manager.clone();

    let client_config = {
        let mut builder = SslContext::builder(SslMethod::tls_client())?;
        builder.set_keylog_callback(move |sslref, key_log| {
            key_manager_handle.parse_key_log_line(key_log.as_bytes());
        });
        builder.build()
    };

    let client = Ssl::new(&client_config)?;

    let client_stream = std::net::TcpStream::connect(format!("{DOMAIN}:{PORT}")).unwrap();
    client_stream.set_read_timeout(Some(Duration::from_secs(1)));
    let decrypting_pipe = DecryptingPipe::new(key_manager, client_stream);
    let decrypter = decrypting_pipe.decrypter.clone();
    let mut stream = SslStream::new(client, decrypting_pipe).unwrap();
    stream.connect().unwrap();
    stream.read(&mut []);
    let shutdown_state = stream.shutdown().unwrap();


    decrypter.lock().unwrap().dump_transcript(DOMAIN);

    // disable cert validation because we don't actually care if an endpoint is good

    println!("hello world");
    Ok(())
}
