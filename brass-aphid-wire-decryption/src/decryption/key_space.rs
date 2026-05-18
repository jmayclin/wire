use ::hkdf::{GenericHkdf, HmacImpl};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use brass_aphid_wire_messages::codec::{DecodeValue, EncodeValue};
use brass_aphid_wire_messages::prefixed_list::PrefixedBlob;
use brass_aphid_wire_messages::{
    iana,
    protocol::{ContentType, RecordHeader},
};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{EagerHash, SimpleHmac};
use sha2::{Sha256, Sha384};

//    The key derivation process makes use of the HKDF-Extract and
//    HKDF-Expand functions as defined for HKDF [RFC5869], as well as the
//    functions defined below:
//
//        HKDF-Expand-Label(Secret, Label, Context, Length) =
//             HKDF-Expand(Secret, HkdfLabel, Length)
//
//        Where HkdfLabel is specified as:
//
//        struct {
//            uint16 length = Length;
//            opaque label<7..255> = "tls13 " + Label;
//            opaque context<0..255> = Context;
//        } HkdfLabel;
//
//        Derive-Secret(Secret, Label, Messages) =
//             HKDF-Expand-Label(Secret, Label,
//                               Transcript-Hash(Messages), Hash.length)
// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
pub fn hkdf_expand_label<H>(secret: &[u8], label: &[u8], context: &[u8], length: u16) -> Vec<u8>
where
    SimpleHmac<H>: HmacImpl,
    H: digest::Digest + EagerHash,
{
    let hkdf_label = {
        let length = u16::to_be_bytes(length).as_slice().to_vec();
        let label: PrefixedBlob<u8> = PrefixedBlob::new([b"tls13 ", label].concat());
        let context: PrefixedBlob<u8> = PrefixedBlob::new(context.to_vec());
        [
            length,
            label.encode_to_vec().unwrap(),
            context.encode_to_vec().unwrap(),
        ]
        .concat()
    };

    let mut output = vec![0; length as usize];

    let hkdf = GenericHkdf::<SimpleHmac<H>>::from_prk(secret).unwrap();
    hkdf.expand(&hkdf_label, &mut output).unwrap();

    output
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
        let hash_len = self.cipher.hash().digest_size() as u16;
        let new_secret = match self.cipher {
            iana::constants::TLS_AES_128_GCM_SHA256
            | iana::constants::TLS_CHACHA20_POLY1305_SHA256 => {
                hkdf_expand_label::<Sha256>(&self.secret, b"traffic upd", b"", hash_len)
            }
            iana::constants::TLS_AES_256_GCM_SHA384 => {
                hkdf_expand_label::<Sha384>(&self.secret, b"traffic upd", b"", hash_len)
            }
            _ => panic!("unsupported cipher for key update: {:?}", self.cipher),
        };
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

        let (key_len, nonce_len) = match self.cipher {
            iana::constants::TLS_AES_128_GCM_SHA256 => (16, 12),
            iana::constants::TLS_AES_256_GCM_SHA384 => (32, 12),
            iana::constants::TLS_CHACHA20_POLY1305_SHA256 => (32, 12),
            _ => unimplemented!("cipher {:?} is not supported", self.cipher),
        };

        let (key, iv) = match self.cipher {
            iana::constants::TLS_AES_128_GCM_SHA256
            | iana::constants::TLS_CHACHA20_POLY1305_SHA256 => {
                let key = hkdf_expand_label::<Sha256>(secret, b"key", b"", key_len);
                let iv = hkdf_expand_label::<Sha256>(secret, b"iv", b"", nonce_len);
                (key, iv)
            }
            iana::constants::TLS_AES_256_GCM_SHA384 => {
                let key = hkdf_expand_label::<Sha384>(secret, b"key", b"", key_len);
                let iv = hkdf_expand_label::<Sha384>(secret, b"iv", b"", nonce_len);
                (key, iv)
            }
            _ => unimplemented!("cipher {:?} is not supported", self.cipher),
        };

        Ok((key, iv))
    }

    /// * `record`: the encrypted record, exclusive of the header
    /// * `sender`: the party who transmitted the record
    pub fn decrypt_record(&mut self, header: &RecordHeader, record: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{generic_array::GenericArray, Aead, Payload};

        let (key, iv) = self.traffic_key().unwrap();

        let nonce = Self::calculate_nonce(iv, self.record_count);
        self.record_count += 1;

        let nonce = GenericArray::from_slice(&nonce);
        let aad = header.encode_to_vec().unwrap();
        let payload = Payload {
            msg: record,
            aad: &aad,
        };

        match self.cipher {
            iana::constants::TLS_AES_128_GCM_SHA256 => Aes128Gcm::new_from_slice(&key)
                .unwrap()
                .decrypt(nonce, payload)
                .unwrap(),
            iana::constants::TLS_AES_256_GCM_SHA384 => Aes256Gcm::new_from_slice(&key)
                .unwrap()
                .decrypt(nonce, payload)
                .unwrap(),
            iana::constants::TLS_CHACHA20_POLY1305_SHA256 => ChaCha20Poly1305::new_from_slice(&key)
                .unwrap()
                .decrypt(nonce, payload)
                .unwrap(),
            _ => panic!("unsupported cipher: {:?}", self.cipher),
        }
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
        // handle plaintext items which might occur in different places
        // CCS -> TLS adores complexity, so this is included to make my parsing
        //        more complicated.
        // Alert -> we might receive a TLS alert in plaintext even during an
        //          encrypted space.
        if matches!(
            outer_record_header.content_type,
            ContentType::ChangeCipherSpec | ContentType::Alert
        ) {
            return Ok((outer_record_header.content_type, remaining.to_vec()));
        }

        match self {
            SecretSpace::Plaintext => Ok((outer_record_header.content_type, remaining.to_vec())),
            SecretSpace::Handshake(key_space) | SecretSpace::Application(key_space, _) => {
                let mut plaintext = key_space.decrypt_record(&outer_record_header, remaining);

                // In TLS 1.3, records are "obfuscated". The plaintext record header
                // contains a fake content type set to "Application Data". To determine
                // the real content type you must
                // 1. decrypt the record
                // 2. remove all padding (0's) from the end of the record
                // 3. the non-zero byte at the end of the decrypted record content
                //    is the "real" content type.
                // "But James!" you say. "That's so complicated. Why wouldn't they
                // just add another header inside the plaintext? That way you
                // don't have to try and parse backwards."
                //
                // well dear reader, I completely agree, but you are forgetting
                // the primary point that "TLS Adores Complexity"

                // remove the padding
                let mut padding = 0;
                while plaintext.ends_with(&[0]) {
                    padding += 1;
                    plaintext.pop();
                }

                // TODO: is it possible to send a record which is entirely padding?

                // parse the content type from the last byte
                let content_type =
                    ContentType::decode_from_exact(&plaintext[plaintext.len() - 1..])?;
                plaintext.pop();

                tracing::trace!("InnerRecordHeader {{");
                tracing::trace!("    content_type: {content_type:?}");
                tracing::trace!("    inner_length: {}", plaintext.len());
                tracing::trace!("    padding: {padding}");
                tracing::trace!("}}");
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

        let (header, _) = HandshakeMessageHeader::decode_from(data.as_slice()).unwrap();
        println!("header : {header:#?}");
    }
}
