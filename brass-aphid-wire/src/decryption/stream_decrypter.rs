use std::sync::{Arc, Mutex};

use crate::{
    decryption::{key_manager::KeyManager, tls_stream::TlsStream, Mode},
    iana::{self, Protocol},
    protocol::content_value::{ContentValue, HandshakeMessageValue},
};

#[derive(Debug, Default, Clone)]
pub struct ConversationState {
    pub client_random: Option<Vec<u8>>,
    pub selected_protocol: Option<Protocol>,
    pub selected_cipher: Option<iana::Cipher>,
}

pub struct StreamDecrypter {
    pub state: ConversationState,
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
    /// To record received bytes, this method can just be called with a swapped
    /// mode. E.g. Receiving bytes from the client can be recorded as a client
    /// transmissions.
    pub fn record_tx(&mut self, data: &[u8], sender: Mode) {
        match sender {
            Mode::Client => self.client_stream.feed_bytes(data),
            Mode::Server => self.server_stream.feed_bytes(data),
        };
    }

    pub fn dump_transcript(&self, file: &str) {
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

        // if the sever sent a hello retry, we need to let the client stream know
        // that it should move the key space forwards
        let hello_retry = content.iter().any(|content| {
            if let ContentValue::Handshake(HandshakeMessageValue::ServerHello(sh)) = content {
                sh.is_hello_retry_tls13()
            } else {
                false
            }
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
