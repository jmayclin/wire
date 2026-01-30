use ::ecdsa::{EcdsaCurve, SignatureEncoding, SigningKey};
use brass_aphid_wire_messages::{
    codec::EncodeValue,
    iana,
    prefixed_list::PrefixedBlob,
    protocol::{content_value::HandshakeMessageValue, CertVerifyTls13, Finished},
};
use ecdsa::signature::Signer;
use elliptic_curve::CurveArithmetic;
use hmac::EagerHash;
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256, Sha384};

use crate::decryption::key_space::hkdf_expand_label_rc;

//    +-----------+-------------------------+-----------------------------+
//    | Mode      | Handshake Context       | Base Key                    |
//    +-----------+-------------------------+-----------------------------+
//    | Server    | ClientHello ... later   | server_handshake_traffic_   |
//    |           | of EncryptedExtensions/ | secret                      |
//    |           | CertificateRequest      |                             |
//    |           |                         |                             |
//    | Client    | ClientHello ... later   | client_handshake_traffic_   |
//    |           | of server               | secret                      |
//    |           | Finished/EndOfEarlyData |                             |
//    |           |                         |                             |
//    | Post-     | ClientHello ... client  | client_application_traffic_ |
//    | Handshake | Finished +              | secret_N                    |
//    |           | CertificateRequest      |                             |
//    +-----------+-------------------------+-----------------------------+
struct HandshakeTranscript {
    messages: Vec<HandshakeMessageValue>,
}

// 4.4.1.  The Transcript Hash
//
//    Many of the cryptographic computations in TLS make use of a
//    transcript hash.  This value is computed by hashing the concatenation
//    of each included handshake message, including the handshake message
//    header carrying the handshake message type and length fields, but not
//    including record layer headers.  I.e.,
//
//     Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
//
// NOTE: transcript_hash uses the hash from the negotiated _cipher_, not from the
// negotiated signature
fn transcript_hash(cipher: iana::Cipher, messages: &[HandshakeMessageValue]) -> Vec<u8> {
    assert!(cipher.supports_tls13());

    let concatenated_messages: Vec<u8> = messages
        .iter()
        .map(|message| message.encode_to_vec().unwrap())
        .flatten()
        .collect();

    let digest = match cipher {
        iana::constants::TLS_AES_128_GCM_SHA256 | iana::constants::TLS_CHACHA20_POLY1305_SHA256 => {
            sha2::Sha256::digest(concatenated_messages).to_vec()
        }
        iana::constants::TLS_AES_256_GCM_SHA384 => {
            sha2::Sha384::digest(concatenated_messages).to_vec()
        }
        _ => {
            unimplemented!("{cipher:?} has some _funk_");
        }
    };

    digest
}

// C: EcdsaCurve + CurveArithmetic

/// Return a valid TLS 1.3 certificate verify message.
pub fn tls13_certificate_verify<C>(
    transcript: &[HandshakeMessageValue],
    cipher: iana::Cipher,
    signature_scheme: iana::SignatureScheme,
    private_key_pem: &str,
) -> CertVerifyTls13
where
    C: EcdsaCurve + CurveArithmetic,
{
    /// The context string for a server signature is
    ///    "TLS 1.3, server CertificateVerify"
    /// https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
    const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

    match transcript.last() {
        Some(HandshakeMessageValue::CertificateTls13(cert_value)) => cert_value,
        Some(other) => {
            panic!(
                "last message was {:?}, but should be `Certificate`",
                other.handshake_type()
            )
        }
        None => {
            panic!("transcript was empty");
        }
    };
    // let private_key: SigningKey<C> = SigningKey::from_slice(&private_key).unwrap();

    let transcript_hash = transcript_hash(cipher, transcript);

    // The digital signature is then computed over the concatenation of:
    // -  A string that consists of octet 32 (0x20) repeated 64 times
    // -  The context string
    // -  A single 0 byte which serves as the separator
    // -  The content to be signed
    // https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
    let cert_verify_message = vec![&[32; 64], CONTEXT, &[0], transcript_hash.as_slice()].concat();

    let digest_to_sign = match signature_scheme {
        iana::constants::ecdsa_secp256r1_sha256 => {
            sha2::Sha256::digest(cert_verify_message).to_vec()
        }
        iana::constants::ecdsa_secp384r1_sha384 => {
            sha2::Sha384::digest(cert_verify_message).to_vec()
        }
        _ => {
            unimplemented!("{signature_scheme:?} is not implemented");
        }
    };

    let maybe_secp256r1 = p256::ecdsa::SigningKey::from_pkcs8_pem(&private_key_pem);
    let maybe_secp384r1 = p384::ecdsa::SigningKey::from_pkcs8_pem(&private_key_pem);
    let signature = match (maybe_secp256r1, maybe_secp384r1) {
        (Ok(secp256r1), _) => {
            let signature: p256::ecdsa::Signature = secp256r1.sign(&digest_to_sign);
            signature.to_vec()
        }
        (Err(_), Ok(secp384r1)) => {
            let signature: p384::ecdsa::Signature = secp384r1.sign(&digest_to_sign);
            signature.to_vec()
        }
        (Err(_), Err(_)) => {
            panic!("unable to parse key")
        }
    };

    CertVerifyTls13 {
        algorithm: signature_scheme,
        signature: PrefixedBlob::new(signature),
    }
}

/// Create the finished message
// pub fn finished<H>(
//     base_key: &[u8],
//     cipher: iana::Cipher,
//     transcript: &[HandshakeMessageValue],
// ) -> Finished
// where
//     H: digest::Digest + EagerHash + Clone,
// {
//     use hmac::{Hmac, KeyInit, Mac};

//     let finished_key = hkdf_expand_label_rc::<H>(
//         base_key,
//         b"finished",
//         b"",
//         <H as digest::Digest>::output_size() as u16,
//     );
//     let mut mac = Hmac::<H>::new_from_slice(&finished_key).unwrap();

//     mac.update(&transcript_hash(cipher, transcript));
//     let result = mac.finalize().into_bytes().to_vec();

//     Finished {
//         verify_data: result,
//     }
// }

pub fn finished(
    base_key: &[u8],
    cipher: iana::Cipher,
    transcript: &[HandshakeMessageValue],
) -> Finished
{
    use hmac::{Hmac, KeyInit, Mac};

    let result = match cipher {
        iana::constants::TLS_AES_128_GCM_SHA256 | iana::constants::TLS_CHACHA20_POLY1305_SHA256 => {
            let finished_key = hkdf_expand_label_rc::<Sha256>(
                base_key,
                b"finished",
                b"",
                Sha256::output_size() as u16,
            );
            let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&finished_key).unwrap();
            let transcript_hash_debug = transcript_hash(cipher, transcript);
            println!("{transcript_hash_debug:?}");
            mac.update(&transcript_hash(cipher, transcript));
            mac.finalize().into_bytes().to_vec()
        }
        iana::constants::TLS_AES_256_GCM_SHA384 => {
            let finished_key = hkdf_expand_label_rc::<Sha384>(
                base_key,
                b"finished",
                b"",
                Sha384::output_size() as u16,
            );
            let mut mac = Hmac::<Sha384>::new_from_slice(&finished_key).unwrap();
            mac.update(&transcript_hash(cipher, transcript));
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            unimplemented!("{cipher:?} has some _funk_");
        }
    };

    Finished {
        verify_data: result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key_parsing() {
        const SECP_256_R1: &str = include_str!("../../certs/ecdsa256/server-key.pem");
        const SECP_384_R1: &str = include_str!("../../certs/ecdsa384/server-key.pem");

        let maybe_secp256r1 = p256::ecdsa::SigningKey::from_pkcs8_pem(&SECP_256_R1).unwrap();
        let maybe_secp384r1 = p384::ecdsa::SigningKey::from_pkcs8_pem(&SECP_384_R1).unwrap();
    }
}
