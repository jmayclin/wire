//! Test fixtures for the record protocol.
//!
//! This test performs a fully in-memory TLS 1.3 handshake between an OpenSSL
//! client and an OpenSSL server, once for each of the three mandatory TLS 1.3
//! cipher suites:
//!   - TLS_AES_128_GCM_SHA256
//!   - TLS_AES_256_GCM_SHA384
//!   - TLS_CHACHA20_POLY1305_SHA256
//!
//! For each handshake we capture:
//!   - every raw byte the *server* reads off the wire (client -> server), and
//!   - every raw byte the *server* writes to the wire (server -> client), and
//!   - every NSS key-log line emitted (all traffic secrets for the connection).
//!
//! The result is three `Conversation` fixtures which are written to
//! `tests/resources/` for use when testing the record protocol.
//!
//! NOTE: The `openssl` crate is built with the `vendored` feature. We build and
//! link our own copy of OpenSSL rather than using whatever is on the system.

use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{self, Read, Write},
    rc::Rc,
    sync::{Arc, Mutex},
};

use openssl::ssl::{
    ErrorCode, Ssl, SslContext, SslFiletype, SslMethod, SslVerifyMode, SslVersion,
};
use serde::{Deserialize, Serialize};

const CERT_DIR: &str = "../certs/rsa2048";
const APP_DATA: &[u8] = b"hello from the openssl client";

/// The three mandatory-to-implement TLS 1.3 cipher suites. The string is the
/// OpenSSL cipher-suite name passed to `set_ciphersuites`, which also doubles
/// as the fixture file stem.
const TLS13_CIPHERS: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

/// Which side of the connection the server was doing when the bytes crossed the
/// wire, from the *server's* point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Direction {
    /// Bytes the server read off the wire (sent by the client).
    ServerRead,
    /// Bytes the server wrote to the wire (destined for the client).
    ServerWrite,
}

/// A single chunk of raw bytes that crossed the server's transport, recorded in
/// the order it happened. Bytes are stored hex-encoded so the fixture is a
/// human-readable, diff-friendly JSON document.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEvent {
    direction: Direction,
    #[serde(rename = "data_hex")]
    data: String,
}

impl WireEvent {
    fn new(direction: Direction, bytes: &[u8]) -> Self {
        Self {
            direction,
            data: hex::encode(bytes),
        }
    }
}

/// A complete recorded TLS 1.3 conversation for a single cipher suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Conversation {
    /// OpenSSL cipher-suite name, e.g. "TLS_AES_128_GCM_SHA256".
    cipher: String,
    /// The raw bytes the server read and wrote, in wire order.
    events: Vec<WireEvent>,
    /// The NSS key-log lines produced during the handshake (one secret each).
    nss_key_log: Vec<String>,
}

/// A one-directional, in-memory byte queue shared between the two endpoints.
type Wire = Rc<RefCell<VecDeque<u8>>>;

/// A non-blocking, in-memory, bidirectional transport for one endpoint.
///
/// Reads pull from `inbound`; writes push into `outbound`. When there is nothing
/// to read we return `WouldBlock` so the caller (an OpenSSL handshake) can make
/// progress on the other endpoint instead. This lets us drive both the client
/// and the server on a single thread with no real sockets.
struct MemoryTransport {
    inbound: Wire,
    outbound: Wire,
}

impl Read for MemoryTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut queue = self.inbound.borrow_mut();
        if queue.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no data available"));
        }
        let n = queue.len().min(buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = queue.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for MemoryTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.borrow_mut().extend(buf.iter().copied());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wraps another transport and records every byte read and written. This is
/// installed on the *server* so we capture exactly what the OpenSSL server saw
/// on the wire and what it emitted.
struct RecordingTransport {
    inner: MemoryTransport,
    events: Rc<RefCell<Vec<WireEvent>>>,
}

impl Read for RecordingTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.events
                .borrow_mut()
                .push(WireEvent::new(Direction::ServerRead, &buf[..n]));
        }
        Ok(n)
    }
}

impl Write for RecordingTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.events
                .borrow_mut()
                .push(WireEvent::new(Direction::ServerWrite, &buf[..n]));
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn is_would_block(err: &openssl::ssl::Error) -> bool {
    matches!(err.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE)
}

fn cert_path(file: &str) -> String {
    format!("{CERT_DIR}/{file}")
}

/// Run a single in-memory OpenSSL <-> OpenSSL TLS 1.3 handshake pinned to
/// `cipher`, returning the recorded conversation.
fn record_conversation(cipher: &str) -> Conversation {
    // ----- server context: certificate + NSS key logging + pinned cipher -----
    let key_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let server_ctx = {
        let mut b = SslContext::builder(SslMethod::tls_server()).unwrap();
        b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        b.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        b.set_ciphersuites(cipher).unwrap();
        b.set_certificate_chain_file(cert_path("server-chain.pem"))
            .unwrap();
        b.set_private_key_file(cert_path("server-key.pem"), SslFiletype::PEM)
            .unwrap();

        // Capture every NSS key-log line. A single TLS 1.3 endpoint logs all of
        // the traffic secrets (client + server, handshake + application) plus
        // the exporter secret, which is everything needed to decrypt the record
        // stream in either direction.
        let sink = key_log.clone();
        b.set_keylog_callback(move |_ssl, line| {
            sink.lock().unwrap().push(line.to_string());
        });
        b.build()
    };

    // ----- client context: trust the CA, pin the same cipher ------------------
    let client_ctx = {
        let mut b = SslContext::builder(SslMethod::tls_client()).unwrap();
        b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        b.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        b.set_ciphersuites(cipher).unwrap();
        b.set_ca_file(cert_path("ca-cert.pem")).unwrap();
        b.set_verify(SslVerifyMode::PEER);
        b.build()
    };

    // ----- wire up two in-memory pipes ----------------------------------------
    // client_to_server: written by the client, read by the server.
    // server_to_client: written by the server, read by the client.
    let client_to_server: Wire = Rc::new(RefCell::new(VecDeque::new()));
    let server_to_client: Wire = Rc::new(RefCell::new(VecDeque::new()));

    let events: Rc<RefCell<Vec<WireEvent>>> = Rc::new(RefCell::new(Vec::new()));

    let server_transport = RecordingTransport {
        inner: MemoryTransport {
            inbound: client_to_server.clone(),
            outbound: server_to_client.clone(),
        },
        events: events.clone(),
    };
    let client_transport = MemoryTransport {
        inbound: server_to_client.clone(),
        outbound: client_to_server.clone(),
    };

    let mut server = openssl::ssl::SslStream::new(
        Ssl::new(&server_ctx).unwrap(),
        server_transport,
    )
    .unwrap();
    let mut client = openssl::ssl::SslStream::new(
        Ssl::new(&client_ctx).unwrap(),
        client_transport,
    )
    .unwrap();

    // ----- drive the handshake on a single thread -----------------------------
    let mut client_done = false;
    let mut server_done = false;
    for _ in 0..100 {
        if !client_done {
            match client.connect() {
                Ok(()) => client_done = true,
                Err(e) if is_would_block(&e) => {}
                Err(e) => panic!("client handshake failed for {cipher}: {e:?}"),
            }
        }
        if !server_done {
            match server.accept() {
                Ok(()) => server_done = true,
                Err(e) if is_would_block(&e) => {}
                Err(e) => panic!("server handshake failed for {cipher}: {e:?}"),
            }
        }
        if client_done && server_done {
            break;
        }
    }
    assert!(
        client_done && server_done,
        "handshake did not complete for {cipher}"
    );

    // ----- exchange a little application data ---------------------------------
    // The client sends a message; the server reads it. This exercises the
    // application-data records (and lets the server flush its TLS 1.3
    // NewSessionTicket messages onto the wire, which we also capture).
    client.write_all(APP_DATA).unwrap();
    client.flush().unwrap();

    let mut received = vec![0u8; APP_DATA.len()];
    let mut filled = 0;
    for _ in 0..100 {
        // Give the server a chance to emit session tickets, etc.
        match server.read(&mut received[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if filled == received.len() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("server read failed for {cipher}: {e:?}"),
        }
    }
    assert_eq!(&received[..filled], APP_DATA, "app data mismatch for {cipher}");

    // ----- shut down, capturing the close_notify alerts -----------------------
    // Best-effort: pump both directions so the close_notify records land in the
    // recorded transcript. We don't require a fully clean bilateral shutdown.
    for _ in 0..10 {
        let _ = client.shutdown();
        let _ = server.shutdown();
    }

    let events = events.borrow().clone();
    let nss_key_log = key_log.lock().unwrap().clone();

    Conversation {
        cipher: cipher.to_string(),
        events,
        nss_key_log,
    }
}

#[test]
fn generate_tls13_record_fixtures() {
    let out_dir = std::path::Path::new("tests/resources");
    std::fs::create_dir_all(out_dir).unwrap();

    for cipher in TLS13_CIPHERS {
        let conversation = record_conversation(cipher);

        // Sanity checks: we should have captured wire traffic in both
        // directions and a full set of NSS secrets.
        assert!(
            conversation
                .events
                .iter()
                .any(|e| e.direction == Direction::ServerRead),
            "{cipher}: no bytes read by server"
        );
        assert!(
            conversation
                .events
                .iter()
                .any(|e| e.direction == Direction::ServerWrite),
            "{cipher}: no bytes written by server"
        );
        // A TLS 1.3 endpoint logs 5 secrets: client/server handshake,
        // client/server application (traffic secret 0), and the exporter.
        assert_eq!(
            conversation.nss_key_log.len(),
            5,
            "{cipher}: unexpected key-log line count: {:#?}",
            conversation.nss_key_log
        );

        let path = out_dir.join(format!("{cipher}.json"));
        let json = serde_json::to_string_pretty(&conversation).unwrap();
        std::fs::write(&path, json).unwrap();
        println!(
            "wrote {} ({} wire events, {} key-log lines)",
            path.display(),
            conversation.events.len(),
            conversation.nss_key_log.len()
        );
    }
}


#[test]
fn tls13_ciphers() {
    for cipher in TLS13_CIPHERS {
        let conversation = record_conversation(cipher);

        
    }
}