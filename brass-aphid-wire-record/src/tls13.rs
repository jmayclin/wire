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

use crate::RecordProtocol;

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
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
}

impl Tls13Cipher {
    fn from_iana(cipher: iana::Cipher) -> Option<Self> {
        match cipher {
            iana::constants::TLS_AES_128_GCM_SHA256 => Some(Self::TLS_AES_128_GCM_SHA256),
            iana::constants::TLS_AES_256_GCM_SHA384 => Some(Self::TLS_AES_256_GCM_SHA384),
            iana::constants::TLS_CHACHA20_POLY1305_SHA256 => {
                Some(Self::TLS_CHACHA20_POLY1305_SHA256)
            }
            _ => None,
        }
    }

    const fn key_len(&self) -> u16 {
        match self {
            Tls13Cipher::TLS_AES_128_GCM_SHA256 => 16,
            Tls13Cipher::TLS_AES_256_GCM_SHA384 => 32,
            Tls13Cipher::TLS_CHACHA20_POLY1305_SHA256 => 32,
        }
    }

    const fn iv(&self) -> usize {
        12
    }

    fn derive_key(&self, secret: &[u8]) -> Vec<u8> {
        const KEY_LABEL: &[u8] = b"key";

        match self {
            // SHA256
            Self::TLS_AES_128_GCM_SHA256 | Self::TLS_CHACHA20_POLY1305_SHA256 => {
                hkdf_expand_label::<Sha256>(secret, KEY_LABEL, b"", self.key_len())
            }
            // SHA384
            Self::TLS_AES_256_GCM_SHA384 => {
                hkdf_expand_label::<Sha384>(secret, KEY_LABEL, b"", self.key_len())
            }
        }
    }

    fn derive_iv(&self, secret: &[u8]) -> Vec<u8> {
        const IV_LABEL: &[u8] = b"iv";

        match self {
            // SHA256
            Self::TLS_AES_128_GCM_SHA256 | Self::TLS_CHACHA20_POLY1305_SHA256 => {
                hkdf_expand_label::<Sha256>(secret, IV_LABEL, b"", self.key_len())
            }
            // SHA384
            Self::TLS_AES_256_GCM_SHA384 => {
                hkdf_expand_label::<Sha384>(secret, IV_LABEL, b"", self.key_len())
            }
        }
    }
}

struct Tls13 {
    cipher: Tls13Cipher,
    key: Vec<u8>,
    iv: Vec<u8>,
    record_count: u64,
}

impl Tls13 {
    fn new(cipher: iana::Cipher, secret: &[u8]) -> Self {
        let cipher = Tls13Cipher::from_iana(cipher).unwrap();
        let key = cipher.derive_key(secret);
        let iv = cipher.derive_iv(secret);
        Self {
            cipher,
            key,
            iv,
            record_count: 0,
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

impl RecordProtocol for Tls13 {
    fn encap<'a, 'b>(&'a self, content_type: ContentType, payload: &'b mut [u8]) -> crate::Record<'b> {
        todo!()
    }

    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut [u8]) -> crate::Payload<'b> {
        todo!()
    }
}
