
use ::ecdsa::SignatureEncoding;
use brass_aphid_wire_messages::{
    codec::EncodeValue,
    prefixed_list::PrefixedBlob,
    protocol::{
        content_value::HandshakeMessageValue, HandshakeType,
    },
};
use hkdf::{GenericHkdf, Hkdf, HmacImpl};
use hmac::SimpleHmac;
use sha2::{Digest, Sha256, Sha384};

use crate::transcript;

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
    H: hmac::digest::Digest + hmac::EagerHash,
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

/// TODO: figure out a coherent way to work with the concrete types of digests across
/// my type parameterized function
enum KeyScheduleHash {
    Sha256,
    Sha384,
}

impl KeyScheduleHash {
    fn hash_len(&self) -> usize {
        match self {
            KeyScheduleHash::Sha256 => 32,
            KeyScheduleHash::Sha384 => 48,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum KeyScheduleState {
    Initial,
    EarlySecret,
    HandshakeSecret,
    MasterSecret,
}

struct KeySchedule {
    hash_len: KeyScheduleHash,
    secret: Vec<u8>,
    /// modelling this as type state would be more absolute, but would make it a
    /// nightmare to actually store this anywhere because the upstream thing would
    /// inherit the generic
    state: KeyScheduleState,
}

impl KeySchedule {
    ///  HKDF-Extract is drawn as taking the Salt argument from the top and
    ///  the IKM argument from the left, with its output to the bottom and
    ///  the name of the output on the right.
    /// https://www.rfc-editor.org/info/rfc8446/#section-7.1
    ///
    /// https://docs.rs/hkdf/latest/hkdf/#usage
    fn hkdf_extract(&self, ikm: &[u8], salt: &[u8]) -> Vec<u8> {
        match self.hash_len {
            KeyScheduleHash::Sha256 => {
                // needs to be sha256
                let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            KeyScheduleHash::Sha384 => {
                let (prk, _hk) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                prk.to_vec()
            }
        }
    }

    ///   Derive-Secret(Secret, Label, Messages) =
    ///        HKDF-Expand-Label(Secret, Label,
    ///                          Transcript-Hash(Messages), Hash.length)
    fn derive_secret(&self, secret: &[u8], label: &[u8], _message: &[u8]) -> Vec<u8> {
        let transcript_hash = match self.hash_len {
            KeyScheduleHash::Sha256 => transcript::transcript_hash::<Sha256>(&[]),
            KeyScheduleHash::Sha384 => transcript::transcript_hash::<Sha384>(&[]),
        };

        match self.hash_len {
            KeyScheduleHash::Sha256 => hkdf_expand_label::<Sha256>(
                secret,
                label,
                &transcript_hash,
                self.hash_len.hash_len() as u16,
            ),
            KeyScheduleHash::Sha384 => hkdf_expand_label::<Sha384>(
                secret,
                label,
                &transcript_hash,
                self.hash_len.hash_len() as u16,
            ),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////            Initial State          //////////////////////
    ////////////////////////////////////////////////////////////////////////////

    fn to_early_secret(&mut self, psk: Option<Vec<u8>>) {
        debug_assert_eq!(self.state, KeyScheduleState::Initial);

        let zero = vec![0; self.hash_len.hash_len()];
        let psk = match psk {
            Some(value) => {
                assert_eq!(value.len(), self.hash_len.hash_len());
                value
            }
            None => zero.clone(),
        };
        self.secret = Self::hkdf_extract(self, &psk, &zero);
        // hkdf extract
        self.state = KeyScheduleState::EarlySecret;
    }

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////            Early State          ////////////////////////
    ////////////////////////////////////////////////////////////////////////////

    fn client_early_traffic_secret(&self) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::EarlySecret);

        Vec::new()
    }

    fn to_handshake_secret(&mut self, _shared_secret: &[u8]) {
        debug_assert_eq!(self.state, KeyScheduleState::EarlySecret);

        //

        self.state = KeyScheduleState::HandshakeSecret
    }

    ////////////////////////////////////////////////////////////////////////////
    /////////////////            Handshake Secret          /////////////////////
    ////////////////////////////////////////////////////////////////////////////

    fn client_handshake_traffic_secret(&self, transcript: &[HandshakeMessageValue]) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::HandshakeSecret);

        assert_eq!(
            transcript.first().unwrap().handshake_type(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            transcript.last().unwrap().handshake_type(),
            HandshakeType::ServerHello
        );
        Vec::new()
    }

    fn server_handshake_traffic_secret(&self, transcript: &[HandshakeMessageValue]) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::HandshakeSecret);
        assert_eq!(
            transcript.first().unwrap().handshake_type(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            transcript.last().unwrap().handshake_type(),
            HandshakeType::ServerHello
        );
        Vec::new()
    }

    fn to_master_secret(&mut self) {
        debug_assert_eq!(self.state, KeyScheduleState::HandshakeSecret);
        self.state = KeyScheduleState::MasterSecret
    }

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////            Master Secret          //////////////////////
    ////////////////////////////////////////////////////////////////////////////

    fn client_application_traffic_secret_0(&self, _transcript: &[HandshakeMessageValue]) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::MasterSecret);
        Vec::new()
    }

    fn server_application_traffic_secret_0(&self, _transcript: &[HandshakeMessageValue]) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::MasterSecret);
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::derivation::{KeySchedule, KeyScheduleHash};

    #[test]
    fn schedule() {
        let mut schedule = KeySchedule {
            hash_len: KeyScheduleHash::Sha256,
            secret: Vec::new(),
            state: super::KeyScheduleState::Initial,
        };

        // early secret

        schedule.to_early_secret(None);
        let secret = schedule.secret.clone();
        let expected_secret = {
            let input = "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a";
            let input = input.replace(" ", "");
            hex::decode(input).unwrap()
        };
        assert_eq!(secret, expected_secret);
    }
}
