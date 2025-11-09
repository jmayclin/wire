use crate::decryption::{
    key_manager::KeyManager, tls_stream::TlsStream, transcript::Transcript, Mode,
};
use brass_aphid_wire_messages::{
    iana::{self, Protocol},
    protocol::{
        content_value::{ContentValue, HandshakeMessageValue},
        ServerHelloConfusionMode,
    },
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// The conversation state tracks the context necessary to decrypt the connection.
///
/// For example, we need to know the cipher to know how to decrypt encrypted records.
#[derive(Debug, Default, Clone)]
pub struct ConversationState {
    pub client_random: Option<Vec<u8>>,
    pub selected_protocol: Option<Protocol>,
    pub selected_cipher: Option<iana::Cipher>,
}

#[derive(Debug)]
pub struct StreamDecrypter {
    pub state: ConversationState,
    /// The key_manager which holds all of the key log entries from the connection.
    ///
    /// The Key Manager is associated with a single config, so secrets must be retrieved
    /// with the connection ID (client hello random).
    key_manager: KeyManager,
    pub transcript: Arc<Mutex<Vec<(Mode, ContentValue)>>>,
    pub client_stream: TlsStream,
    pub server_stream: TlsStream,
}

impl StreamDecrypter {
    pub fn new(key_manager: KeyManager) -> Self {
        Self {
            state: ConversationState::default(),
            key_manager,
            transcript: Default::default(),
            client_stream: TlsStream::new(Mode::Client),
            server_stream: TlsStream::new(Mode::Server),
        }
    }

    /// Record a transmitted bytes.
    ///
    /// Received bytes should be recorded as transmissions of the peer.
    ///
    ///
    pub fn record_tx(&mut self, data: &[u8], sender: Mode) {
        match sender {
            Mode::Client => self.client_stream.feed_bytes(data),
            Mode::Server => self.server_stream.feed_bytes(data),
        };
    }

    pub fn transcript(&self) -> Transcript {
        Transcript {
            record_transcript: Default::default(),
            content_transcript: Mutex::new(self.transcript.lock().unwrap().clone()),
        }
    }

    pub fn dump_transcript(&self, file: &PathBuf) {
        let transcript = format!("{:#?}", self.transcript);
        std::fs::write(file, transcript).unwrap();
    }

    pub fn assemble_records(&mut self, mode: Mode) -> std::io::Result<()> {
        // TODO: error handling. We currently assume that all errors are just because
        // there isn't enough data. Which will not be true into the future. Also
        // should think more about the "not enough data" error.

        /* no op */

        Ok(())
    }

    /// decrypt the records sent by `mode`.
    pub fn decrypt_records(&mut self, mode: Mode) -> std::io::Result<()> {
        let content = match mode {
            Mode::Client => self
                .client_stream
                .digest_bytes(&mut self.state, &self.key_manager),
            Mode::Server => self
                .server_stream
                .digest_bytes(&mut self.state, &self.key_manager),
        }?;

        // if the server sent a hello retry, we need to let the client stream know
        // that it should move the key space forwards
        // TODO: could we remove the context from this, and just peek at the records
        // in the client
        let hello_retry = content.iter().any(|content| {
            matches!(
                content,
                ContentValue::Handshake(HandshakeMessageValue::ServerHelloConfusion(
                    ServerHelloConfusionMode::HelloRetryRequest(_)
                ))
            )
        });

        if hello_retry {
            // hello retry is indicated by the server hello
            debug_assert_eq!(mode, Mode::Server);
            self.client_stream.suppress_next_key_state();
        }

        self.transcript
            .lock()
            .unwrap()
            .extend(content.into_iter().map(|content| (mode, content)));
        Ok(())
    }
}
