use std::io::{BufRead, Cursor, Write};

use aes_gcm::aead::{Aead, AeadInPlace};
use aes_gcm::aes::cipher::{InOut, InOutBuf};
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit};
use brass_aphid_wire_messages::codec::EncodeValue;
use brass_aphid_wire_messages::{
    codec::{DecodeByteSource, DecodeValue},
    iana::{self, Cipher, Protocol},
    prefixed_list::PrefixedBlob,
    protocol::{ContentType, RecordHeader},
};

use chacha20poly1305::ChaCha20Poly1305;
use hkdf::{GenericHkdf, HmacImpl};
use hmac::{EagerHash, SimpleHmac};
use sha2::{Sha256, Sha384};

use crate::{Payload, Record, RecordError, RecordProtocol, RecordProtocolBehavior};

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

        // TODO: make PrefixedBlob zero-copy
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

/// This is used to define the protocol specific traits
///
// We allow non_camel_case_types so that we can directly match the TLS RFC spelling
#[allow(non_camel_case_types)]
enum Tls13Cipher {
    TLS_AES_128_GCM_SHA256 {
        key: aes_gcm::Aes128Gcm,
        iv: [u8; Self::IV_SIZE],
    },
    TLS_AES_256_GCM_SHA384 {
        key: aes_gcm::Aes256Gcm,
        iv: [u8; Self::IV_SIZE],
    },
    TLS_CHACHA20_POLY1305_SHA256 {
        key: chacha20poly1305::ChaCha20Poly1305,
        iv: [u8; Self::IV_SIZE],
    },
}

impl Tls13Cipher {
    const KEY_LABEL: &[u8] = b"key";
    const IV_LABEL: &[u8] = b"iv";

    const IV_SIZE: usize = 12;

    fn from_iana(cipher: iana::Cipher, secret: &[u8]) -> Option<Self> {
        match cipher {
            iana::constants::TLS_AES_128_GCM_SHA256 => {
                let key =
                    hkdf_expand_label::<Sha256>(secret, Self::KEY_LABEL, b"", cipher.key_len()?);
                let iv =
                    hkdf_expand_label::<Sha256>(secret, Self::IV_LABEL, b"", Self::IV_SIZE as u16);
                let key = Aes128Gcm::new_from_slice(&key).unwrap();
                Some(Self::TLS_AES_128_GCM_SHA256 {
                    key,
                    iv: iv.try_into().unwrap(),
                })
            }
            iana::constants::TLS_AES_256_GCM_SHA384 => {
                let key =
                    hkdf_expand_label::<Sha384>(secret, Self::KEY_LABEL, b"", cipher.key_len()?);
                let iv =
                    hkdf_expand_label::<Sha384>(secret, Self::IV_LABEL, b"", Self::IV_SIZE as u16);
                let key = Aes256Gcm::new_from_slice(&key).unwrap();
                Some(Self::TLS_AES_256_GCM_SHA384 {
                    key,
                    iv: iv.try_into().unwrap(),
                })
            }
            iana::constants::TLS_CHACHA20_POLY1305_SHA256 => {
                let key =
                    hkdf_expand_label::<Sha256>(secret, Self::KEY_LABEL, b"", cipher.key_len()?);
                let iv =
                    hkdf_expand_label::<Sha256>(secret, Self::IV_LABEL, b"", Self::IV_SIZE as u16);
                let key = ChaCha20Poly1305::new_from_slice(&key).unwrap();
                Some(Self::TLS_CHACHA20_POLY1305_SHA256 {
                    key,
                    iv: iv.try_into().unwrap(),
                })
            }
            _ => None,
        }
    }

    fn iv(&self) -> [u8; Self::IV_SIZE] {
        match self {
            Tls13Cipher::TLS_AES_128_GCM_SHA256 { key, iv } => iv.clone(),
            Tls13Cipher::TLS_AES_256_GCM_SHA384 { key, iv } => iv.clone(),
            Tls13Cipher::TLS_CHACHA20_POLY1305_SHA256 { key, iv } => iv.clone(),
        }
    }

    fn encrypt_ciphertext(
        &self,
        inout_buffer: &mut [u8],
        nonce: &[u8; Self::IV_SIZE],
        aad: &[u8; 5],
    ) {
        let (plaintext, mut tag_buffer) = inout_buffer.split_at_mut(inout_buffer.len() - 16);
        let inout = InOutBuf::from(plaintext);

        match self {
            Tls13Cipher::TLS_AES_128_GCM_SHA256 { key, iv } => {
                let tag = key
                    .encrypt_inout_detached(nonce.into(), aad, inout)
                    .unwrap();
                tag_buffer.write_all(&tag).unwrap();
            }
            Tls13Cipher::TLS_AES_256_GCM_SHA384 { key, iv } => {
                let tag = key
                    .encrypt_inout_detached(nonce.into(), aad, inout)
                    .unwrap();
                tag_buffer.write_all(&tag).unwrap();
            }
            Tls13Cipher::TLS_CHACHA20_POLY1305_SHA256 { key, iv } => {
                let tag = key
                    .encrypt_inout_detached(nonce.into(), aad, inout)
                    .unwrap();
                tag_buffer.write_all(&tag).unwrap();
            }
        }
    }

    // TODO: have this operate on raw &mut slices
    fn decrypt_ciphertext(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; Self::IV_SIZE],
        aad: &[u8; 5],
        output: &mut Cursor<&mut [u8]>,
    ) {
        assert!(ciphertext.len() > 16);
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let output_slice = {
            let start = output.position() as usize;
            let end = start + ciphertext.len();
            &mut output.get_mut()[start..end]
        };
        let in_out = InOutBuf::new(ciphertext, output_slice).unwrap();
        let length = ciphertext.len();

        match self {
            Tls13Cipher::TLS_AES_128_GCM_SHA256 { key, iv } => {
                key.decrypt_inout_detached(
                    nonce.into(),
                    aad.as_slice().into(),
                    in_out,
                    tag.as_ref().try_into().unwrap(),
                )
                .unwrap();
            }
            Tls13Cipher::TLS_AES_256_GCM_SHA384 { key, iv } => {
                key.decrypt_inout_detached(
                    nonce.into(),
                    aad.as_slice().into(),
                    in_out,
                    tag.as_ref().try_into().unwrap(),
                )
                .unwrap();
            }
            Tls13Cipher::TLS_CHACHA20_POLY1305_SHA256 { key, iv } => {
                key.decrypt_inout_detached(
                    nonce.into(),
                    aad.as_slice().into(),
                    in_out,
                    tag.as_ref().try_into().unwrap(),
                )
                .unwrap();
            }
        }

        output.consume(length);
    }
}

pub struct Tls13 {
    cipher: Tls13Cipher,
    record_count: u64,
}

impl Tls13 {
    pub fn new(cipher: iana::Cipher, secret: &[u8]) -> Self {
        let cipher = Tls13Cipher::from_iana(cipher, secret).unwrap();
        Self {
            cipher,
            record_count: 0,
        }
    }

    /// XOR the IV with the record count
    fn calculate_nonce(&self) -> [u8; Tls13Cipher::IV_SIZE] {
        let mut nonce = [0_u8; Tls13Cipher::IV_SIZE];
        nonce.copy_from_slice(&self.cipher.iv());

        let record_count = self.record_count.to_be_bytes();
        let mut bytes = vec![0; nonce.len() - record_count.len()];
        bytes.extend_from_slice(&record_count);

        let xor_start = nonce.len() - std::mem::size_of_val(&self.record_count);
        for i in 0..std::mem::size_of_val(&self.record_count) {
            nonce[i + xor_start] ^= record_count[i];
        }

        nonce
    }
}

impl RecordProtocolBehavior for Tls13 {
    // TODO: I currently have an extra copy here. Which sucks.
    // but maybe can't be helped? If you want to send 30kb, that has to be split
    // up and I need to shove in the new content type. Now they're making me really
    // grumpy. Why couldn't they just use a new header 😭
    fn encap_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        ciphertext_out: &mut Cursor<&mut [u8]>,
    ) -> Result<(), RecordError> {
        // payload + content_type + gcm_tag
        let ciphertext_len = payload.len() + 1 + 16;

        let record_header = RecordHeader {
            // the outer content_type and protocol_version are hard coded
            content_type: ContentType::ApplicationData,
            protocol_version: Protocol::TLSv1_2,
            record_length: ciphertext_len as u16,
        };
        let add = record_header.encode_to_vec().unwrap();

        // write the plaintext record header out ahead of the ciphertext. This is
        // also the AEAD additional authenticated data.
        ciphertext_out
            .write_all(&add)
            .map_err(|_| RecordError::InsufficientSpace)?;

        let payload_chunk = {
            let start = ciphertext_out.position() as usize;
            let end = start + ciphertext_len;
            if end > ciphertext_out.get_ref().len() {
                return Err(RecordError::InsufficientSpace);
            }
            &mut ciphertext_out.get_mut()[start..end]
        };

        // TLS1.3 inner plaintext: content || content_type ( || zero padding, which
        // we don't emit). The trailing 16 bytes are left for the GCM/Poly1305 tag.
        payload_chunk[0..payload.len()].copy_from_slice(payload);
        payload_chunk[payload.len()] = content_type.byte_value();

        let nonce = self.calculate_nonce();

        self.cipher
            .encrypt_ciphertext(payload_chunk, &nonce, add.as_slice().try_into().unwrap());

        // advance the cursor past the ciphertext we just wrote in place.
        let end = ciphertext_out.position() + ciphertext_len as u64;
        ciphertext_out.set_position(end);

        self.record_count += 1;

        Ok(())
    }

    fn decap_record(
        &mut self,
        record: Record<&[u8]>,
        plaintext_out: &mut Cursor<&mut [u8]>,
    ) -> ContentType {
        println!(
            "decapsulating record: {:?} with length {}",
            record.header,
            record.payload.len()
        );
        let nonce = self.calculate_nonce();

        let aad = record.header.encode_to_vec().unwrap();

        // TODO: make this not explode

        let decrypted_payload = {
            let before_decrypt = plaintext_out.position() as usize;
            self.cipher.decrypt_ciphertext(
                record.payload,
                &nonce,
                &aad.try_into().unwrap(),
                plaintext_out,
            );
            let after_decrypt = plaintext_out.position() as usize;
            &plaintext_out.get_ref()[before_decrypt..after_decrypt]
        };

        // remove the padding
        let padding_bytes = {
            let mut padding = 0;
            while decrypted_payload.get(decrypted_payload.len() - padding) == Some(&0) {
                padding += 1;
            }
            padding
        };
        let (payload, _padding) =
            decrypted_payload.split_at(decrypted_payload.len() - padding_bytes);
        let (content_type, payload) = payload.split_last().unwrap();
        let content_type = ContentType::decode_from_exact([*content_type].as_slice()).unwrap();

        // padding + content type
        let garbage_bytes = padding_bytes + 1;
        plaintext_out.set_position(plaintext_out.position() - (garbage_bytes as u64));

        assert!(content_type != ContentType::ChangeCipherSpec);

        self.record_count += 1;
        content_type
    }
}
