mod cert;
mod derivation;
mod protocol;
mod transcript;

use std::task::Poll;

use brass_aphid_wire_messages::{
    codec::{DecodeByteSource, DecodeValue, EncodeValue},
    iana::{self},
    protocol::{
        extensions::{
            ExtensionWriter, KeyShareClientHello, KeyShareClientHelloWriter, KeyShareWriter,
            SignatureSchemeList, SignatureSchemeListWriter, SupportedGroups, SupportedGroupsWriter,
            SupportedVersionClientHello, SupportedVersionClientHelloWriter,
        },
        handshake::{HandshakeMessage, HandshakeWriter},
        CertVerifyTls13, CertificateTls13, ClientHello, ClientHelloWriter, EncryptedExtensions,
        Finished, HandshakeType, ServerHello, SigHashOrScheme,
    },
};
use elliptic_curve::{sec1::ToSec1Point, Generate};

use crate::{derivation::KeySchedule, transcript::HandshakeTranscript};

// https://www.rfc-editor.org/info/rfc8446/#appendix-A

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Read,
    Write,
}

/// https://www.rfc-editor.org/info/rfc8446/#appendix-A.1
/// ```text
///
///                               START <----+
///                Send ClientHello |        | Recv HelloRetryRequest
///           [K_send = early data] |        |
///                                 v        |
///            /                 WAIT_SH ----+
///            |                    | Recv ServerHello
///            |                    | K_recv = handshake
///        Can |                    V
///       send |                 WAIT_EE
///      early |                    | Recv EncryptedExtensions
///       data |           +--------+--------+
///            |     Using |                 | Using certificate
///            |       PSK |                 v
///            |           |            WAIT_CERT_CR
///            |           |        Recv |       | Recv CertificateRequest
///            |           | Certificate |       v
///            |           |             |    WAIT_CERT
///            |           |             |       | Recv Certificate
///            |           |             v       v
///            |           |              WAIT_CV
///            |           |                 | Recv CertificateVerify
///            |           +> WAIT_FINISHED <+
///            |                  | Recv Finished
///            \                  | [Send EndOfEarlyData]
///                               | K_send = handshake
///                               | [Send Certificate [+ CertificateVerify]]
///     Can send                  | Send Finished
///     app data   -->            | K_send = K_recv = application
///     after here                v
///                           CONNECTED
/// ```
pub struct Client {
    /********************** Negotiated Parameters *****************************/
    negotiated_group: Option<iana::Group>,
    negotiated_cipher: Option<iana::Cipher>,
    negotiated_version: Option<iana::Protocol>,
    negotiated_signature: Option<iana::SignatureAlgorithm>,

    /*********************** Cryptographic Parameters *************************/
    client_key_share: Option<p256::SecretKey>,
    server_key_share: Option<p256::PublicKey>,
    server_cert: Option<Vec<u8>>,

    /**********************      State Stuff     ******************************/
    key_schedule: Option<KeySchedule>,
    transcript: HandshakeTranscript,
    needed_action: (Action, HandshakeType),

    /*************************    🤫 Secrets 🤫    *****************************/
    client_handshake_secret: Option<Vec<u8>>,
    server_handshake_secret: Option<Vec<u8>>,
    client_application_secret: Option<Vec<u8>>,
    server_application_secret: Option<Vec<u8>>,
}

pub struct ParsedCertificate<'a> {
    subject: &'a [u8],
    issue: &'a [u8],
    public_key: &'a [u8],
    signature: &'a [u8],
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            negotiated_group: None,
            negotiated_cipher: None,
            negotiated_version: None,
            negotiated_signature: None,
            client_key_share: None,
            server_key_share: None,
            server_cert: None,
            key_schedule: None,
            transcript: HandshakeTranscript::default(),
            needed_action: (Action::Write, HandshakeType::ClientHello),
            server_handshake_secret: None,
            client_handshake_secret: None,
            client_application_secret: None,
            server_application_secret: None,
        }
    }

    pub fn negotiated_cipher(&self) -> Option<iana::Cipher> {
        self.negotiated_cipher
    }

    // client/server
    pub fn handshake_secrets(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match (&self.client_handshake_secret, &self.server_handshake_secret) {
            (Some(client), Some(server)) => Some((client.clone(), server.clone())),
            (_, _) => None,
        }
    }

    fn needed_action(&self) -> Action {
        self.needed_action.0
    }

    pub fn read_bytes(bytes: &[u8]) -> std::io::Result<(HandshakeMessage<'_>, &[u8])> {
        let (_handshake, _remaining) = bytes.decode_value::<HandshakeMessage>()?;

        todo!()
    }

    pub fn consume_message(&mut self, message: HandshakeMessage) -> std::io::Result<()> {
        // state validation: we are reading/writing the correct message
        {
            let this_action = (Action::Read, message.handshake_type);
            assert_eq!(this_action, self.needed_action);
        }

        self.transcript.add_message(&message);

        // message processing
        match message.handshake_type {
            HandshakeType::ServerHello => {
                let sh = message.parse::<ServerHello>()?;
                assert!(!sh.is_hrr());

                let selected_cipher = sh.cipher_suite;
                let selected_version = sh.selected_version();
                let key_share = sh.key_share()?.unwrap();

                // the UncompressedPointRepresentation is a specific SEC1 encoding
                let public_key =
                    p256::PublicKey::from_sec1_bytes(key_share.key_exchange.blob()).unwrap();

                self.negotiated_cipher = Some(selected_cipher);
                self.negotiated_version = Some(selected_version.unwrap());
                self.negotiated_group = Some(key_share.group);
                self.server_key_share = Some(public_key);

                // now that cipher is negotiated, populate the key schedule
                self.key_schedule = Some(KeySchedule::new(selected_cipher.hash()));
                self.key_schedule.as_mut().unwrap().to_early_secret(None);

                let output = self
                    .client_key_share
                    .as_ref()
                    .unwrap()
                    .diffie_hellman(&public_key);

                let mut key_schedule = KeySchedule::new(selected_cipher.hash());
                key_schedule.to_early_secret(None);
                key_schedule.to_handshake_secret(output.raw_secret_bytes());
                self.client_handshake_secret =
                    Some(key_schedule.server_handshake_traffic_secret(&self.transcript));
                self.server_handshake_secret =
                    Some(key_schedule.server_handshake_traffic_secret(&self.transcript));

                self.key_schedule = Some(key_schedule)
            }
            HandshakeType::EncryptedExtensions => {
                let ee = message.parse::<EncryptedExtensions>()?;
                println!("ee: {ee:?}");
            }
            HandshakeType::Certificate => {
                let cert = message.parse::<CertificateTls13>()?;
                println!("cert tls13: {cert:?}");
                // perform certificate validation: the cert was issue by a trusted CA
                let _parsed_certs = cert
                    .certificate_list
                    .iter()
                    .map(|cert| cert.cert_data.blob());
            }
            HandshakeType::CertificateVerify => {
                let verify = message.parse::<CertVerifyTls13>()?;
                println!("cert verify: {verify:?}");
                let _negotiated_signature = verify.algorithm;
            }
            HandshakeType::NewSessionTicket => todo!(),
            HandshakeType::Finished => {
                // Safety: this should be safe, because we only get to this state
                let _message: Finished = message
                    .body
                    .decode_value_context_exact(self.negotiated_cipher.unwrap())?;
                let key_schedule = self.key_schedule.as_mut().unwrap();
                key_schedule.to_master_secret();
                self.client_application_secret =
                    Some(key_schedule.client_application_traffic_secret_0(&self.transcript));
                self.server_application_secret =
                    Some(key_schedule.server_application_traffic_secret_0(&self.transcript));
                // we can calculate the server thing here
            }
            other => panic!("did not expect {other:?}"),
        }

        self.increment_state();
        Ok(())
    }

    /// Build the ClientHello, returning it as a framed handshake message (type,
    /// u24 length, body).
    ///
    /// Every field of the hello is a borrow of something on this stack frame,
    /// and nothing is allocated except the final `Vec<u8>`.
    fn client_hello(&mut self) -> std::io::Result<Vec<u8>> {
        // generate key share information
        let key = p256::SecretKey::generate();
        let public_key = key.public_key().to_uncompressed_point();
        let public_key_ref = public_key.as_slice();
        let key_share = [KeyShareWriter {
            group: iana::constants::secp256r1,
            key_exchange: public_key_ref,
        }];
        let key_share = KeyShareClientHelloWriter {
            client_shares: key_share.as_slice(),
        };

        // supported parameters
        let supported_groups = SupportedGroupsWriter {
            named_curve_list: [iana::constants::secp256r1].as_slice(),
        };
        let supported_versions = SupportedVersionClientHelloWriter {
            versions: [iana::Protocol::TLSv1_3].as_slice(),
        };
        let signature_algorithms = SignatureSchemeListWriter {
            supported_signature_algorithms: [
                SigHashOrScheme::SignatureScheme(iana::constants::ecdsa_secp256r1_sha256),
                SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_rsae_sha256),
            ]
            .as_slice(),
        };
        let supported_ciphers = [iana::constants::TLS_AES_256_GCM_SHA384];

        // package extensions
        let extensions = [
            ExtensionWriter::of::<SupportedGroups>(&supported_groups),
            ExtensionWriter::of::<SupportedVersionClientHello>(&supported_versions),
            ExtensionWriter::of::<SignatureSchemeList>(&signature_algorithms),
            ExtensionWriter::of::<KeyShareClientHello>(&key_share),
        ];

        // assemble the client hello
        let client_hello = ClientHelloWriter {
            protocol_version: iana::Protocol::TLSv1_2,
            random: *b"https://xkcd.com/221/-----------",
            session_id: [].as_slice(),
            offered_ciphers: supported_ciphers.as_slice(),
            compression_methods: [].as_slice(),
            extensions: Some(extensions.as_slice()),
        };

        let message = HandshakeWriter::of::<ClientHello>(&client_hello);
        let message = message.encode_to_vec()?;

        self.client_key_share = Some(key);
        Ok(message)
    }

    pub fn make_message(&mut self) -> std::io::Result<Vec<u8>> {
        let (action, message) = self.needed_action;
        assert_eq!(action, Action::Write);
        let message = match message {
            HandshakeType::ClientHello => self.client_hello()?,
            HandshakeType::Finished => todo!(),
            other => {
                panic!("not expecting to write {other:?}")
            }
        };
        self.increment_state();
        // TODO: unhack this
        let parsed_message = HandshakeMessage::decode_from_exact(&message)?;
        self.transcript.add_message(&parsed_message);
        Ok(message)
    }

    fn increment_state(&mut self) -> std::task::Poll<()> {
        const STATES: &[(Action, HandshakeType)] = &[
            (Action::Write, HandshakeType::ClientHello),
            (Action::Read, HandshakeType::ServerHello),
            (Action::Read, HandshakeType::EncryptedExtensions),
            (Action::Read, HandshakeType::Certificate),
            (Action::Read, HandshakeType::CertificateVerify),
            (Action::Read, HandshakeType::Finished),
            (Action::Write, HandshakeType::Finished),
        ];

        let position = STATES
            .iter()
            .position(|state| *state == self.needed_action)
            .unwrap();
        let next = position + 1;
        if next == STATES.len() {
            Poll::Ready(())
        } else {
            self.needed_action = STATES[next];
            Poll::Pending
        }
    }
}

///
/// ```text
///
///                              START <-----+
///               Recv ClientHello |         | Send HelloRetryRequest
///                                v         |
///                             RECVD_CH ----+
///                                | Select parameters
///                                v
///                             NEGOTIATED
///                                | Send ServerHello
///                                | K_send = handshake
///                                | Send EncryptedExtensions
///                                | [Send CertificateRequest]
/// Can send                       | [Send Certificate + CertificateVerify]
/// app data                       | Send Finished
/// after   -->                    | K_send = application
/// here                  +--------+--------+
///              No 0-RTT |                 | 0-RTT
///                       |                 |
///   K_recv = handshake  |                 | K_recv = early data
/// [Skip decrypt errors] |    +------> WAIT_EOED -+
///                       |    |       Recv |      | Recv EndOfEarlyData
///                       |    | early data |      | K_recv = handshake
///                       |    +------------+      |
///                       |                        |
///                       +> WAIT_FLIGHT2 <--------+
///                                |
///                       +--------+--------+
///               No auth |                 | Client auth
///                       |                 |
///                       |                 v
///                       |             WAIT_CERT
///                       |        Recv |       | Recv Certificate
///                       |       empty |       v
///                       | Certificate |    WAIT_CV
///                       |             |       | Recv
///                       |             v       | CertificateVerify
///                       +-> WAIT_FINISHED <---+
///                                | Recv Finished
///                                | K_recv = application
///                                v
///                            CONNECTED
/// ```
struct Server;

struct HandshakeState {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check_rustcrypto() {
        let key = p256::SecretKey::generate();

        let pub_key = key.public_key();
        let point = pub_key.to_uncompressed_point().to_vec();
        let mut buffer = point.as_slice();
        let (form, remaining) = buffer.decode_value::<u8>().unwrap();
        let (x, remaining) = remaining.decode_value::<[u8; 32]>().unwrap();
        let (y, remaining) = remaining.decode_value::<[u8; 32]>().unwrap();
        assert!(remaining.is_empty());
    }
}
