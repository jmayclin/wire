use crate::{
    codec::{DecodeValue, DecodeValueWithContext, EncodeValue},
    decryption::key_manager::KeyManager,
    iana::{self, Protocol},
    protocol::{
        content_value::{ContentValue, HandshakeMessageValue},
        Alert, ChangeCipherSpec, ContentType, RecordHeader,
    },
};
use aws_lc_rs::{
    aead,
    hkdf::{self},
};
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    pub fn peer(&self) -> Mode {
        match self {
            Mode::Client => Mode::Server,
            Mode::Server => Mode::Client,
        }
    }
}

impl iana::Cipher {
    fn aead(&self) -> &'static aws_lc_rs::aead::Algorithm {
        match self.description {
            "TLS_AES_128_GCM_SHA256" => &aead::AES_128_GCM,
            "TLS_AES_256_GCM_SHA384" => &aead::AES_256_GCM,
            "TLS_CHACHA20_POLY1305_SHA256" => &aead::CHACHA20_POLY1305,
            _ => panic!("one of us did something stupid. Probably me."),
        }
    }

    fn hkdf(&self) -> aws_lc_rs::hkdf::Algorithm {
        match self.description {
            "TLS_AES_128_GCM_SHA256" => hkdf::HKDF_SHA256,
            "TLS_AES_256_GCM_SHA384" => hkdf::HKDF_SHA384,
            "TLS_CHACHA20_POLY1305_SHA256" => hkdf::HKDF_SHA256,
            _ => panic!("one of us did something stupid. Probably me."),
        }
    }
}

struct UsizeContainer(usize);

impl UsizeContainer {
    fn new(num: usize) -> Self {
        UsizeContainer(num)
    }
}

// they have unfortunately made me too angry to put up with their API
// I am done asking nicely, and will simply transmute it into the shape
// I wish for, and deal with the consequences later.
impl hkdf::KeyType for UsizeContainer {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label<T: hkdf::KeyType>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    key_type: T,
    hkdf: hkdf::Algorithm,
) -> Vec<u8> {
    let prk = hkdf::Prk::new_less_safe(hkdf, secret);

    let output_length_bytes = (key_type.len() as u16).to_be_bytes();
    let label = {
        let mut label_builder = Vec::new();
        label_builder.extend_from_slice(b"tls13 ");
        label_builder.extend_from_slice(label);
        label_builder
    };
    let label_bytes = label.len() as u8;

    let context_bytes = context.len() as u8;
    let label = [
        output_length_bytes.as_slice(),
        &[label_bytes],
        &label,
        &[context_bytes],
        context,
    ];

    let mut key = vec![0; key_type.len()];
    let out = prk.expand(&label, key_type).unwrap();
    out.fill(&mut key).unwrap();
    key
}

/// KeySpace represents the decryption context of some keys.
///
/// E.g. Handshake Space or Traffic Space.
#[derive(Debug)]
pub struct KeySpace {
    pub cipher: iana::Cipher,
    pub secret: Vec<u8>,
    pub record_count: u64,
}

impl KeySpace {
    pub fn new(secret: Vec<u8>, cipher: iana::Cipher) -> Self {
        // https://www.rfc-editor.org/rfc/rfc8446#section-7.3
        // [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)

        Self {
            cipher,
            secret,
            record_count: 0,
        }
    }

    fn traffic_key(&self) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let secret = &self.secret;
        // Determine the hash algorithm, key length, and IV length based on the cipher suite
        let aead = self.cipher.aead();

        let key = hkdf_expand_label(
            secret,
            b"key",
            b"",
            UsizeContainer::new(aead.key_len()),
            self.cipher.hkdf(),
        );
        let iv = hkdf_expand_label(
            secret,
            b"iv",
            b"",
            UsizeContainer::new(aead.nonce_len()),
            self.cipher.hkdf(),
        );

        Ok((key, iv))
    }

    /// * `record`: the encrypted record, exclusive of the header
    /// * `sender`: the party who transmitted the record
    fn decrypt_record(&mut self, header: &RecordHeader, record: &[u8]) -> Vec<u8> {
        let (key, iv) = self.traffic_key().unwrap();

        let nonce = Self::calculate_nonce(iv, self.record_count);
        self.record_count += 1;

        let unbound_key = aws_lc_rs::aead::UnboundKey::new(self.cipher.aead(), &key).unwrap();
        let less_safe_key = aws_lc_rs::aead::LessSafeKey::new(unbound_key);

        // Create a buffer that contains ciphertext + tag for in-place decryption
        let mut output = record.to_vec();

        // Decrypt the record
        let nonce_obj = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce).unwrap();

        let aad = header.encode_to_vec().unwrap();

        let plaintext = less_safe_key
            .open_in_place(nonce_obj, aws_lc_rs::aead::Aad::from(aad), &mut output)
            .unwrap();
        plaintext.to_vec()
    }

    /// XOR the IV with the record count
    fn calculate_nonce(iv: Vec<u8>, record_count: u64) -> Vec<u8> {
        let mut nonce = iv.clone();
        let record_count = record_count.to_be_bytes();
        let mut bytes = vec![0; nonce.len() - record_count.len()];
        bytes.extend_from_slice(&record_count);

        for i in 0..nonce.len() {
            nonce[i] ^= bytes[i];
        }

        nonce
    }
}

/// The StreamDecrypter is responsible for actually decrypting the TLS traffic
///
/// The decrypt pipeline goes
/// 1. tx_byte_buffer: data is buffered here until a complete record has been gathered
/// 2. tx_record_buffer: records are buffered here until a complete message can be read
///
/// TODO: This representation is a poor one for the eldritch nightmare that is technically
/// allowed by TLS record framing
/// ```text
/// |   message 1 |  message 2  | message 3  |
/// |  r1   |   r2      |     r3    |   r4   |
/// ```
/// I affectionately refer to this as "polyrhythm records".
///
/// We currently just assume that messages fit in a record which is very not right.
/// We probably want to adapt the tx_record_buffer to be a stream of the concatenated
/// plaintexts from the decrypted records that we receive
/// stream[space][content_type]
pub struct StreamDecrypter {
    /// The identity of this decrypter, either "client" or "server".
    ///
    /// We need to track this because we need to map send/recv data onto client/server
    /// specific keys.
    ///
    /// This is deduced from first IO. If the first IO is receiving, then we are
    /// a server. If the first IO is sending, then we are a client.
    pub identity: Option<Mode>,
    pub client_random: Option<Vec<u8>>,

    selected_cipher: Option<iana::Cipher>,
    selected_protocol: Option<Protocol>,

    /// all tx calls are buffered here until there is enough to read a message
    server_tx_byte_buffer: Vec<u8>,
    client_tx_byte_buffer: Vec<u8>,

    /// records, populated from tx
    server_tx_record_buffer: Vec<Vec<u8>>,
    client_tx_record_buffer: Vec<Vec<u8>>,

    key_manager: KeyManager,

    // These _have_ to be different spaces, because the openssl key logging callback
    // is kinda lazy. The ClientHandshake won't be given until after EncryptedExtensions
    // has already been received
    current_server_space: Option<KeySpace>,
    current_client_space: Option<KeySpace>,

    client_need: Option<KeySchedule>,

    server_need: Option<KeySchedule>,

    // client_wants: Option<KeySchedule>,
    // server_wants: Option<KeySchedule>,
    pub transcript: Arc<Mutex<Vec<(Mode, ContentValue)>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeySchedule {
    Plain,
    Handshake,
    Traffic,
}

impl StreamDecrypter {
    pub fn new(
        // send: Box<dyn std::io::Write>,
        // read: Box<dyn std::io::Read>,
        key_manager: KeyManager,
    ) -> Self {
        Self {
            identity: None,
            client_random: None,
            selected_cipher: None,
            selected_protocol: None,
            server_tx_byte_buffer: Vec::new(),
            client_tx_byte_buffer: Vec::new(),
            server_tx_record_buffer: Vec::new(),
            client_tx_record_buffer: Vec::new(),
            // intercepted_send: send,
            // intercepted_read: read,
            key_manager,
            current_server_space: None,
            current_client_space: None,
            client_need: None,
            server_need: None,
            transcript: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a transmitted bytes.
    ///
    /// To record received bytes, this method can just be called with a swapped
    /// mode. E.g. Receiving bytes from the client can be recorded as a client
    /// transmissions.
    pub fn record_tx(&mut self, bytes: &[u8], sender: Mode) {
        match sender {
            Mode::Client => self.client_tx_byte_buffer.extend_from_slice(bytes),
            Mode::Server => self.server_tx_byte_buffer.extend_from_slice(bytes),
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

        let (raw, records) = match mode {
            Mode::Client => (
                &mut self.client_tx_byte_buffer,
                &mut self.client_tx_record_buffer,
            ),
            Mode::Server => (
                &mut self.server_tx_byte_buffer,
                &mut self.server_tx_record_buffer,
            ),
        };
        println!("raw length: {:?}", raw.len());

        // multiple records may have been sent, so loop
        loop {
            let buffer = raw.as_slice();
            let (record_header, buffer) = RecordHeader::decode_from(buffer)?;
            println!("record header {record_header:?}");
            if buffer.len() >= record_header.record_length as usize {
                // TODO: use split off for better performance
                let (record_contents, remaining) =
                    raw.split_at(5 + record_header.record_length as usize);
                records.push(record_contents.to_vec());
                *raw = remaining.to_vec();
            } else {
                // there wasn't enough to get the full record
                break;
            }
        }

        Ok(())
    }

    /// decrypt the records sent by `mode`.
    pub fn decrypt_records(&mut self, mode: Mode) -> std::io::Result<()> {
        // for each record
        println!("------------ {mode:?} ------------");
        let records = match mode {
            Mode::Client => &mut self.client_tx_record_buffer,
            Mode::Server => &mut self.server_tx_record_buffer,
        };

        for record in records.drain(..) {
            let record_buffer = record.as_slice();
            let (record_header, mut record_buffer) = RecordHeader::decode_from(record_buffer)?;
            println!("{record_header:#?}");

            // read all of the messages in the buffer
            while !record_buffer.is_empty() {
                record_buffer = match record_header.content_type {
                    ContentType::Invalid => panic!("invalid content"),
                    ContentType::ChangeCipherSpec => {
                        let (ccs, record_buffer) = ChangeCipherSpec::decode_from(record_buffer)?;
                        println!("{ccs:?}");
                        record_buffer
                    }
                    ContentType::Alert => {
                        let (alert, record_buffer) = Alert::decode_from(record_buffer)?;
                        println!("{alert:?}");
                        self.transcript
                            .lock()
                            .unwrap()
                            .push((mode, ContentValue::Alert(alert)));
                        record_buffer
                    }
                    ContentType::Handshake => {
                        println!("decrypting plaintext handshake");
                        let (handshake_message, record_buffer) =
                            match (self.selected_protocol, self.selected_cipher) {
                                (Some(protocol), Some(cipher)) => {
                                    HandshakeMessageValue::decode_from_with_context(
                                        record_buffer,
                                        (protocol, cipher),
                                    )?
                                }
                                _ => HandshakeMessageValue::decode_from(record_buffer)?,
                            };

                        // extra the client random from the client hello
                        if let HandshakeMessageValue::ClientHello(ch) = &handshake_message {
                            self.client_random = Some(ch.random.to_vec())
                        }

                        // the server hello sets most of the relevant cryptographic state
                        if let HandshakeMessageValue::ServerHello(sh) = &handshake_message {
                            self.selected_cipher = Some(sh.cipher_suite);
                            self.selected_protocol = Some(sh.selected_version()?);
                        }

                        println!("{handshake_message:?}");
                        self.transcript
                            .lock()
                            .unwrap()
                            .push((mode, ContentValue::Handshake(handshake_message)));

                        record_buffer
                    }
                    ContentType::ApplicationData => {
                        // TODO: this is absolutely awful and makes me cry inside
                        match mode {
                            Mode::Client => {
                                if self.client_need == Some(KeySchedule::Traffic) {
                                    self.current_client_space = self
                                        .key_manager
                                        .application_space(
                                            Mode::Client,
                                            self.client_random.as_ref().unwrap(),
                                            self.selected_cipher.unwrap(),
                                        )
                                        .unwrap()
                                        .into();
                                    self.client_need = None;
                                }
                                if self.current_client_space.is_none() {
                                    self.current_client_space = self.key_manager.handshake_space(
                                        Mode::Client,
                                        self.client_random.as_ref().unwrap(),
                                        self.selected_cipher.unwrap(),
                                    );
                                }
                            }
                            Mode::Server => {
                                if self.server_need == Some(KeySchedule::Traffic) {
                                    self.current_server_space = self.key_manager.application_space(
                                        Mode::Server,
                                        self.client_random.as_ref().unwrap(),
                                        self.selected_cipher.unwrap(),
                                    );
                                    self.server_need = None;
                                }
                                if self.current_server_space.is_none() {
                                    self.current_server_space = self.key_manager.handshake_space(
                                        Mode::Server,
                                        self.client_random.as_ref().unwrap(),
                                        self.selected_cipher.unwrap(),
                                    );
                                }
                            }
                        }

                        println!("{} bytes of ApplicationData", record_buffer.len());
                        let space = match mode {
                            Mode::Client => self.current_client_space.as_mut().unwrap(),
                            Mode::Server => self.current_server_space.as_mut().unwrap(),
                        };
                        // let space = self.current_space.as_mut().unwrap();
                        let mut plaintext = space.decrypt_record(&record_header, record_buffer);

                        // TODO explain wth is happening here.
                        let mut padding = 0;
                        while plaintext.ends_with(&[0]) {
                            padding += 1;
                            plaintext.remove(plaintext.len() - 1);
                        }

                        let (content_type, _buffer) =
                            ContentType::decode_from(&plaintext[plaintext.len() - 1..])?;

                        // drop the content byte from the end
                        let plaintext = &plaintext[..(plaintext.len() - 1)];

                        println!("InnerRecordHeader {{");
                        println!("    content_type: {content_type:?}");
                        println!("    inner_length: {}", plaintext.len());
                        println!("    padding: {padding}");
                        println!("}}");
                        let inner_plaintext = plaintext;

                        let (value, buffer) = match content_type {
                            ContentType::Invalid => panic!("invalid"),
                            ContentType::ChangeCipherSpec => panic!("invalid inner CCS"),
                            ContentType::Alert => {
                                let (alert, buffer) = Alert::decode_from(inner_plaintext)?;
                                println!("{alert:?}");
                                (ContentValue::Alert(alert), buffer)
                            }
                            ContentType::Handshake => {
                                let (handshake_message, inner_buffer) =
                                    match (self.selected_protocol, self.selected_cipher) {
                                        (Some(protocol), Some(cipher)) => {
                                            HandshakeMessageValue::decode_from_with_context(
                                                inner_plaintext,
                                                (protocol, cipher),
                                            )?
                                        }
                                        _ => HandshakeMessageValue::decode_from(inner_plaintext)?,
                                    };
                                // if it was the client finished, time for application secrets
                                if matches!(handshake_message, HandshakeMessageValue::Finished(_))
                                    && mode == Mode::Client
                                {
                                    println!("seting both traffic spaces");
                                    self.client_need = Some(KeySchedule::Traffic);
                                    self.server_need = Some(KeySchedule::Traffic);

                                    // openssl will only make the client traffic secret available
                                    // _after_ the client finished message has been
                                    // handled.
                                    // both should be available at this point
                                    // self.current_client_space = self.key_manager.application_space(
                                    //     Mode::Client,
                                    //     self.client_random.as_ref().unwrap(),
                                    //     self.selected_cipher.unwrap(),
                                    // );
                                    // self.current_server_space = self.key_manager.application_space(
                                    //     Mode::Client,
                                    //     self.client_random.as_ref().unwrap(),
                                    //     self.selected_cipher.unwrap(),
                                    // );
                                }
                                (ContentValue::Handshake(handshake_message), inner_buffer)
                            }
                            ContentType::ApplicationData => (
                                ContentValue::ApplicationData(inner_plaintext.to_vec()),
                                [].as_slice(),
                            ),
                        };
                        println!("content value: {value:#?}");
                        self.transcript.lock().unwrap().push((mode, value));

                        &[]
                    }
                };
            }
        }

        Ok(())
    }
}

impl Debug for StreamDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamDecrypter")
            .field("raw_client_tx", &self.client_tx_byte_buffer.len())
            .field("raw_server_tx", &self.server_tx_byte_buffer.len())
            .field("client_record_tx", &self.client_tx_record_buffer.len())
            .field("server_record_tx", &self.server_tx_record_buffer.len())
            .finish()
    }
}

#[cfg(test)]
mod s2n_tls_decryption {
    use crate::protocol::HandshakeMessageHeader;

    use super::*;

    #[test]
    /// Make sure that the correct traffic key is derived
    fn traffic_key_derivation() {
        let server_secret =
            hex::decode("4182e4b0b6565a8f7b8586cc35d2ca23f22fa47764a16eaee9e1b21038efd2a4")
                .unwrap();
        let client_secret =
            hex::decode("8bf4b07633e7de6b46e2a680713d8b0b8b9bcc9592163b8fa32222d650b005f3")
                .unwrap();

        let space = KeySpace::new(
            server_secret,
            iana::Cipher::from_description("TLS_AES_128_GCM_SHA256").unwrap(),
        );

        let (key, iv) = space.traffic_key().unwrap();
        assert_eq!(hex::encode(key), "d4af18cdaa11d3943b4d8bb0f9d6c6ca");
        assert_eq!(hex::encode(iv), "32bd8d44d91fb6e913c3349b");
    }

    #[test]
    /// Make sure that a record is successfully decrypted
    fn handshake_record_decrypt() {
        let server_secret =
            hex::decode("64d7b60c7f0d3ca90e47411c575f7eaa8b24d754f3e68ac2d3f060e28395553d")
                .unwrap();
        let client_secret =
            hex::decode("8bf4b07633e7de6b46e2a680713d8b0b8b9bcc9592163b8fa32222d650b005f3")
                .unwrap();

        let aes_128 = iana::Cipher::from_description("TLS_AES_128_GCM_SHA256").unwrap();

        let mut space = KeySpace::new(server_secret, aes_128);

        let record =
            hex::decode("1703030017c89a8a469e34ecee23cd8fbe8e978763ac2e498ddebcc5").unwrap();
        let record_buffer = record.as_slice();
        let (record_header, record_buffer) = RecordHeader::decode_from(record_buffer).unwrap();

        let decrypted = space.decrypt_record(&record_header, record_buffer);
        assert_eq!(hex::encode(decrypted), "08000002000016");
    }

    #[test]
    fn maybe_app_data() {
        let data = hex::decode("08000002000016").unwrap();

        let (header, buffer) = HandshakeMessageHeader::decode_from(data.as_slice()).unwrap();
        println!("header : {header:#?}");
    }
}
