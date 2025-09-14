use aws_lc_rs::{aead, hkdf};

use brass_aphid_wire_messages::{
    iana, protocol::{ContentType, RecordHeader}
};
use brass_aphid_wire_messages::{
    codec::{DecodeValue, EncodeValue}
};

trait DecryptionCipherExtension {
    fn aead(&self) -> &'static aws_lc_rs::aead::Algorithm ;

    fn hkdf(&self) -> aws_lc_rs::hkdf::Algorithm;
}

impl DecryptionCipherExtension for iana::Cipher {
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
    /// Defined for application traffic
    pub key_epoch: Option<usize>,
}

impl KeySpace {
    /// Construct a new key space from a handshake secret
    pub fn handshake_traffic_secret(secret: Vec<u8>, cipher: iana::Cipher) -> Self {
        // https://www.rfc-editor.org/rfc/rfc8446#section-7.3
        // [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)

        Self {
            cipher,
            secret,
            record_count: 0,
            key_epoch: None,
        }
    }

    /// Construct a new key space from the first traffic secret
    pub fn first_traffic_secret(secret: Vec<u8>, cipher: iana::Cipher) -> Self {
        // https://www.rfc-editor.org/rfc/rfc8446#section-7.3
        // [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)

        Self {
            cipher,
            secret,
            record_count: 0,
            key_epoch: Some(0),
        }
    }

    /// Construct a new key space following a key update
    ///
    /// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-7.2
    pub fn key_update(&self) -> Self {
        let new_secret = hkdf_expand_label(
            &self.secret,
            b"traffic upd",
            b"",
            UsizeContainer::new(
                self.cipher
                    .hkdf()
                    .hmac_algorithm()
                    .digest_algorithm()
                    .output_len(),
            ),
            self.cipher.hkdf(),
        );
        Self {
            cipher: self.cipher,
            secret: new_secret,
            record_count: 0,
            key_epoch: self.key_epoch.map(|epoch| epoch + 1),
        }
    }

    /// Return the actual key and IV which will be used the the symmetric cipher
    pub fn traffic_key(&self) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
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
    pub fn decrypt_record(&mut self, header: &RecordHeader, record: &[u8]) -> Vec<u8> {
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

#[derive(Debug)]
pub enum SecretSpace {
    Plaintext,
    Handshake(KeySpace),
    // TODO: handle key updates
    Application(KeySpace, usize),
}

impl SecretSpace {
    /// Deframe (possibly decrypt) a record, returning it's true content type.
    ///
    /// E.g. A TLS 1.3 obfuscated record may have an obfuscated content type of "ApplicationData",
    /// but an internal type of Handshake. This method would return `Handshake`.
    ///
    /// This method will also strip off all record padding
    pub fn deframe_record(&mut self, record: &[u8]) -> std::io::Result<(ContentType, Vec<u8>)> {
        let remaining = record;
        let (outer_record_header, remaining) = RecordHeader::decode_from(remaining)?;
        tracing::debug!("Deframing {outer_record_header:?}");
        if outer_record_header.content_type == ContentType::ChangeCipherSpec {
            // don't attempt to decrypt, this is it's own weird little thing
            return Ok((outer_record_header.content_type, remaining.to_vec()));
        }

        match self {
            SecretSpace::Plaintext => Ok((outer_record_header.content_type, remaining.to_vec())),
            SecretSpace::Handshake(key_space) | SecretSpace::Application(key_space, _) => {
                assert!(outer_record_header.content_type == ContentType::ApplicationData);
                let mut plaintext = key_space.decrypt_record(&outer_record_header, remaining);

                // TODO explain wth is happening here.
                let mut padding = 0;
                while plaintext.ends_with(&[0]) {
                    padding += 1;
                    plaintext.pop();
                }

                // TODO: is it possible to send a record which is entirely padding?

                let (content_type, _buffer) =
                    ContentType::decode_from(&plaintext[plaintext.len() - 1..])?;
                // drop the content byte from the end
                plaintext.pop();

                println!("InnerRecordHeader {{");
                println!("    content_type: {content_type:?}");
                println!("    inner_length: {}", plaintext.len());
                println!("    padding: {padding}");
                println!("}}");
                Ok((content_type, plaintext))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use brass_aphid_wire_messages::protocol::HandshakeMessageHeader;

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

        let space = KeySpace::handshake_traffic_secret(
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

        let mut space = KeySpace::handshake_traffic_secret(server_secret, aes_128);

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
