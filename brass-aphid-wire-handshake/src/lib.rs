mod derivation;
mod protocol;
mod transcript;
mod cert;

use std::task::Poll;

use brass_aphid_wire_messages::{
    codec::{DecodeByteSource, DecodeValue},
    iana::{self},
    prefixed_list::{PrefixedBlob, PrefixedList},
    protocol::{
        content_value::HandshakeMessageValue,
        extensions::{
            self, ClientHelloExtension, ClientHelloExtensionData,
            ExtensionType::{self},
            KeyShareServerHello, SupportedVersionServerHello,
        },
        HandshakeType, ServerHelloConfusionMode, SigHashOrScheme,
    },
};
use elliptic_curve::{sec1::ToSec1Point, Generate};

use crate::derivation::KeySchedule;

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
    transcript: Vec<HandshakeMessageValue>,
    needed_action: (Action, HandshakeType),

    /*************************    🤫 Secrets 🤫    *****************************/
    client_handshake_secret: Option<Vec<u8>>,
    server_handshake_secret: Option<Vec<u8>>,
    client_application_secret: Option<Vec<u8>>,
    server_application_secret: Option<Vec<u8>>,
}

pub struct ParsedCertificate<'a> {
    subject: &'a[u8],
    issue: &'a[u8],
    public_key: &'a [u8],
    signature: &'a [u8],
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
            transcript: Vec::new(),
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

    pub fn read_bytes(bytes: &[u8]) -> std::io::Result<(HandshakeMessageValue, &[u8])> {
        let (_handshake, _remaining) = bytes.decode_value::<HandshakeMessageValue>()?;

        todo!()
    }

    pub fn consume_message(&mut self, message: HandshakeMessageValue) -> std::io::Result<()> {
        // state validation: we are reading/writing the correct message
        {
            let this_action = (Action::Read, message.handshake_type());
            assert_eq!(this_action, self.needed_action);
        }

        self.transcript.push(message.clone());

        // message processing
        match message {
            HandshakeMessageValue::ServerHelloConfusion(ServerHelloConfusionMode::ServerHello(
                sh,
            )) => {
                let selected_cipher = sh.cipher_suite;
                let selected_version = sh.selected_version();
                let key_share = sh.key_share().unwrap();

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
            HandshakeMessageValue::ServerHelloConfusion(
                ServerHelloConfusionMode::HelloRetryRequest(_sh),
            ) => {
                panic!("i don't support hrr yet bc im lazy")
            }
            HandshakeMessageValue::EncryptedExtensions(ee) => {
                println!("ee: {ee:?}");
            }
            HandshakeMessageValue::CertificateTls13(certificate_tls13) => {
                println!("cert tls13: {certificate_tls13:?}");
                // perform certificate validation: the cert was issue by a trusted CA
                let certs = certificate_tls13.certificate_list.list();
                let parsed_certs = certs.iter().map(|cert| cert.cert_data.blob());
            }
            HandshakeMessageValue::CertVerifyTls13(cert_verify_tls13) => {
                println!("cert verify: {cert_verify_tls13:?}");
                let negotiated_signature = cert_verify_tls13.algorithm;
            }
            HandshakeMessageValue::NewSessionTicketTls13(_new_session_ticket_tls13) => todo!(),
            HandshakeMessageValue::Finished(finished) => {
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

    pub fn make_message(&mut self) -> std::io::Result<HandshakeMessageValue> {
        let (action, message) = self.needed_action.clone();
        assert_eq!(action, Action::Write);
        let message = match message {
            HandshakeType::ClientHello => {
                let supported_version = extensions::SupportedVersionClientHello {
                    versions: PrefixedList::new(vec![iana::Protocol::TLSv1_3]),
                };
                let signature_algorithms = extensions::SignatureSchemeList {
                    supported_signature_algorithms: PrefixedList::new(vec![
                        SigHashOrScheme::SignatureScheme(iana::constants::ecdsa_secp256r1_sha256),
                        SigHashOrScheme::SignatureScheme(iana::constants::rsa_pss_rsae_sha256),
                    ]),
                };
                let supported_groups = extensions::SupportedGroups {
                    named_curve_list: PrefixedList::new(vec![iana::constants::secp256r1]),
                };
                let key = p256::SecretKey::generate();

                let key_share = {
                    let pub_key = key.public_key();

                    let key_share = extensions::KeyShare {
                        group: iana::constants::secp256r1,
                        key_exchange: PrefixedBlob::new(pub_key.to_uncompressed_point().to_vec()),
                    };
                    extensions::KeyShareClientHello {
                        client_shares: PrefixedList::new(vec![key_share]),
                    }
                };

                let client_hello_extensions = vec![
                    ClientHelloExtension {
                        extension_type: ExtensionType::SupportedGroups,
                        extension_data: ClientHelloExtensionData::SupportedGroups(supported_groups),
                    },
                    ClientHelloExtension {
                        extension_type: ExtensionType::SupportedVersions,
                        extension_data: ClientHelloExtensionData::SupportedVersions(
                            supported_version,
                        ),
                    },
                    ClientHelloExtension {
                        extension_type: ExtensionType::SignatureAlgorithms,
                        extension_data: ClientHelloExtensionData::SignatureScheme(
                            signature_algorithms,
                        ),
                    },
                    ClientHelloExtension {
                        extension_type: ExtensionType::KeyShare,
                        extension_data: ClientHelloExtensionData::KeyShare(key_share),
                    },
                ];

                let client_hello = brass_aphid_wire_messages::protocol::messages::ClientHello {
                    protocol_version: iana::Protocol::TLSv1_2,
                    random: *b"https://xkcd.com/221/-----------",
                    session_id: PrefixedBlob::new(Vec::new()),
                    offered_ciphers: PrefixedList::new(vec![
                        iana::constants::TLS_AES_256_GCM_SHA384,
                    ]),
                    compression_methods: PrefixedBlob::new(Vec::new()),
                    extensions: Some(PrefixedList::new(client_hello_extensions)),
                };

                self.client_key_share = Some(key);
                HandshakeMessageValue::ClientHello(client_hello)
            }
            HandshakeType::Finished => todo!(),
            other => {
                panic!("not expecting to write {other:?}")
            }
        };
        self.increment_state();
        self.transcript.push(message.clone());
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
            self.needed_action = STATES[next].clone();
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

impl HandshakeState {
    fn process_message(_message: &HandshakeMessageValue) {}
}

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
