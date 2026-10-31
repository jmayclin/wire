use brass_aphid_wire_messages::{
    codec::EncodeValue, iana::HashAlgorithm, prefixed_list::PrefixedBlobWriter, protocol::{HandshakeType},
};
use hkdf::{GenericHkdf, Hkdf, HmacImpl};
use hmac::SimpleHmac;
use sha2::{Sha256, Sha384};

use crate::transcript::HandshakeTranscript;

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

        let label = [b"tls13 ".as_slice(), label].concat();
        [
            length,
            PrefixedBlobWriter::<u8>::new(&label).encode_to_vec().unwrap(),
            PrefixedBlobWriter::<u8>::new(context).encode_to_vec().unwrap(),
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
pub enum KeyScheduleHash {
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

pub struct KeySchedule {
    hash: HashAlgorithm,
    secret: Vec<u8>,
    /// modelling this as type state would be more absolute, but would make it a
    /// nightmare to actually store this anywhere because the upstream thing would
    /// inherit the generic.
    ///
    /// I'm actually reconsidering this, because we _also_ want the hash to just
    /// be part of the type state?
    state: KeyScheduleState,
}

impl KeySchedule {
    pub fn new(hash: HashAlgorithm) -> Self {
        Self { hash, secret: Vec::new(), state: KeyScheduleState::Initial }
    }

    ///  HKDF-Extract is drawn as taking the Salt argument from the top and
    ///  the IKM argument from the left, with its output to the bottom and
    ///  the name of the output on the right.
    /// https://www.rfc-editor.org/info/rfc8446/#section-7.1
    ///
    /// https://docs.rs/hkdf/latest/hkdf/#usage
    fn hkdf_extract(&self, ikm: &[u8], salt: &[u8]) -> Vec<u8> {
        match self.hash {
            HashAlgorithm::Sha256 => {
                // needs to be sha256
                let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            HashAlgorithm::Sha384 => {
                let (prk, _hk) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            _ => {
                panic!("should be unreachable, idk")
            }
        }
    }

    ///   Derive-Secret(Secret, Label, Messages) =
    ///        HKDF-Expand-Label(Secret, Label,
    ///                          Transcript-Hash(Messages), Hash.length)
    fn derive_secret(
        &self,
        secret: &[u8],
        label: &[u8],
        transcript: &HandshakeTranscript,
    ) -> Vec<u8> {
        let length = self.hash.digest_size() as u16;
        match self.hash {
            HashAlgorithm::Sha256 => {
                hkdf_expand_label::<Sha256>(secret, label, &transcript.sha256(), length)
            }
            HashAlgorithm::Sha384 => {
                hkdf_expand_label::<Sha384>(secret, label, &transcript.sha384(), length)
            }
            _ => panic!("should be unreachable, idk"),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////            Initial State          //////////////////////
    ////////////////////////////////////////////////////////////////////////////

    pub fn to_early_secret(&mut self, psk: Option<Vec<u8>>) {
        debug_assert_eq!(self.state, KeyScheduleState::Initial);

        let zero = vec![0; self.hash.digest_size()];
        let psk = match psk {
            Some(value) => {
                assert_eq!(value.len(), self.hash.digest_size());
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
        unimplemented!("oops");

        Vec::new()
    }

    // `shared_secret` is the result of the (EC)DHE computation after exchanging
    // key shares.
    pub fn to_handshake_secret(&mut self, shared_secret: &[u8]) {
        debug_assert_eq!(self.state, KeyScheduleState::EarlySecret);

        // Derive-Secret(., "derived", "") hashes the empty string
        self.secret = Self::derive_secret(
            &self,
            &self.secret,
            b"derived",
            &HandshakeTranscript::default(),
        );

        self.secret = Self::hkdf_extract(&self, &shared_secret, &self.secret);

        self.state = KeyScheduleState::HandshakeSecret
    }

    ////////////////////////////////////////////////////////////////////////////
    /////////////////            Handshake Secret          /////////////////////
    ////////////////////////////////////////////////////////////////////////////

    pub fn client_handshake_traffic_secret(&self, transcript: &HandshakeTranscript) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::HandshakeSecret);
        debug_assert_eq!(*transcript.hashed_messages.first().unwrap(), HandshakeType::ClientHello);
        debug_assert_eq!(*transcript.hashed_messages.last().unwrap(), HandshakeType::ServerHello);

        self.derive_secret(&self.secret, b"c hs traffic", transcript)
    }

    pub fn server_handshake_traffic_secret(&self, transcript: &HandshakeTranscript) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::HandshakeSecret);
        debug_assert_eq!(*transcript.hashed_messages.first().unwrap(), HandshakeType::ClientHello);
        debug_assert_eq!(*transcript.hashed_messages.last().unwrap(), HandshakeType::ServerHello);

        self.derive_secret(&self.secret, b"s hs traffic", transcript)
    }

    pub fn to_master_secret(&mut self) {
        debug_assert_eq!(self.state, KeyScheduleState::HandshakeSecret);

        // Derive-Secret(., "derived", "") hashes the empty string
        self.secret = Self::derive_secret(
            &self,
            &self.secret,
            b"derived",
            &HandshakeTranscript::default(),
        );

        let zero = vec![0; self.hash.digest_size()];
        self.secret = Self::hkdf_extract(&self, &zero, &self.secret);

        self.state = KeyScheduleState::MasterSecret
    }

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////            Master Secret          //////////////////////
    ////////////////////////////////////////////////////////////////////////////

    pub fn client_application_traffic_secret_0(&self, transcript: &HandshakeTranscript) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::MasterSecret);
        // to server finished
        debug_assert_eq!(*transcript.hashed_messages.first().unwrap(), HandshakeType::ClientHello);
        debug_assert_eq!(*transcript.hashed_messages.last().unwrap(), HandshakeType::Finished);

        self.derive_secret(&self.secret, b"c ap traffic", transcript)
    }

    pub fn server_application_traffic_secret_0(&self, transcript: &HandshakeTranscript) -> Vec<u8> {
        debug_assert_eq!(self.state, KeyScheduleState::MasterSecret);
        // to server finished
        debug_assert_eq!(*transcript.hashed_messages.first().unwrap(), HandshakeType::ClientHello);
        debug_assert_eq!(*transcript.hashed_messages.last().unwrap(), HandshakeType::Finished);

        self.derive_secret(&self.secret, b"s ap traffic", transcript)
    }
}

#[cfg(test)]
mod tests {
    use brass_aphid_wire_messages::iana::HashAlgorithm;

use crate::derivation::{KeySchedule, KeyScheduleHash};

    /// https://www.rfc-editor.org/info/rfc8448/
    #[test]
    fn rfc8448_traces() {
        let mut schedule = KeySchedule {
            hash: HashAlgorithm::Sha256,
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

        // handshake secret
        let diffie_hellman_secret = {
            let input = "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d";
            let input = input.replace(" ", "");
            hex::decode(input).unwrap()
        };
        schedule.to_handshake_secret(&diffie_hellman_secret);
        let expected_secret = {
            let input = "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac";
            let input = input.replace(" ", "");
            hex::decode(input).unwrap()
        };
        assert_eq!(expected_secret, schedule.secret);

        //    {server}  derive secret for handshake "tls13 derived":

        //       PRK (32 octets):  33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
        //          10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a

        //       hash (32 octets):  e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
        //          27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55

        //       info (49 octets):  00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64
        //          20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4
        //          64 9b 93 4c a4 95 99 1b 78 52 b8 55

        //       expanded (32 octets):  6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
        //          b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba

        //    {server}  extract secret "handshake":

        //       salt (32 octets):  6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
        //          16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba

        //       IKM (32 octets):  8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
        //          35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d

        //       secret (32 octets):  1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
        //          01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac
    }
}
