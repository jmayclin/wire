mod derivation;
mod protocol;
mod transcript;

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
struct Client {
    /********************** Negotiated Parameters ******************************/
    negotiated_group: Option<iana::Group>,
    negotiated_cipher: Option<iana::Cipher>,
    negotiated_version: Option<iana::Protocol>,
    negotiated_signature: Option<iana::SignatureAlgorithm>,

    /*********************** Cryptographic Parameters *************************/
    client_key_share: Option<p256::SecretKey>,
    server_key_share: Option<p256::PublicKey>,
    server_cert: Option<Vec<u8>>,

    /**********************      State Stuff     ******************************/
    transcript: Vec<HandshakeMessageValue>,
    needed_action: (Action, HandshakeType),

    /*************************    🤫 Secrets 🤫    *****************************/
    server_handshake_secret: Option<Vec<u8>>,
}

impl Client {
    fn needed_action(&self) -> Action {
        self.needed_action.0
    }

    fn read_bytes(bytes: &[u8]) -> std::io::Result<(HandshakeMessageValue, &[u8])> {
        let (_handshake, _remaining) = bytes.decode_value::<HandshakeMessageValue>()?;

        todo!()
    }

    fn consume_message(&mut self, message: HandshakeMessageValue) -> std::io::Result<()> {
        let (action, message_type) = self.needed_action.clone();
        assert_eq!(action, Action::Read);
        assert_eq!(message.handshake_type(), message_type);
        match message {
            HandshakeMessageValue::ServerHelloConfusion(ServerHelloConfusionMode::ServerHello(
                sh,
            )) => {
                let negotiated_cipher = sh.cipher_suite;
                let negotiated_version = sh
                    .extensions
                    .list()
                    .iter()
                    .find(|e| e.extension_type == ExtensionType::SupportedVersions)
                    .map(|ext| {
                        SupportedVersionServerHello::decode_from_exact(ext.extension_data.blob())
                            .unwrap()
                    })
                    .map(|supported| supported.selected_version);
                let key_share = sh
                    .extensions
                    .list()
                    .iter()
                    .find(|e| e.extension_type == ExtensionType::KeyShare)
                    .map(|ext| {
                        KeyShareServerHello::decode_from_exact(ext.extension_data.blob()).unwrap()
                    })
                    .map(|key_share| key_share.server_share)
                    .unwrap();

                // the UncompressedPointRepresentation is a specific SEC1 encoding
                let public_key =
                    p256::PublicKey::from_sec1_bytes(key_share.key_exchange.blob()).unwrap();

                self.negotiated_cipher = Some(negotiated_cipher);
                self.negotiated_version = Some(negotiated_version.unwrap());
                self.negotiated_group = Some(key_share.group);
                self.server_key_share = Some(public_key);

                let _output = self
                    .client_key_share
                    .as_ref()
                    .unwrap()
                    .diffie_hellman(&public_key);
            }
            HandshakeMessageValue::ServerHelloConfusion(
                ServerHelloConfusionMode::HelloRetryRequest(_sh),
            ) => {}
            HandshakeMessageValue::EncryptedExtensions(ee) => {
                println!("ee: {ee:?}");
            }
            HandshakeMessageValue::CertificateTls13(_certificate_tls13) => todo!(),
            HandshakeMessageValue::CertVerifyTls13(cert_verify_tls13) => {
                let _negotiated_signature = cert_verify_tls13.algorithm;
            }
            HandshakeMessageValue::NewSessionTicketTls13(_new_session_ticket_tls13) => todo!(),
            HandshakeMessageValue::Finished(_finished) => todo!(),
            other => panic!("did not expect {other:?}"),
        }

        Ok(())
    }

    fn make_message(&mut self) -> std::io::Result<HandshakeMessageValue> {
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
