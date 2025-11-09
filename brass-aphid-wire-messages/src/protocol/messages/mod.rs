//! This module contains all of the top level message definitions

mod members;

pub use members::server_key_exchange;

use crate::{
    codec::{
        DecodeByteSource, DecodeValue, DecodeValueWithContext, EncodeBytesSink, EncodeValue, U24,
    },
    discriminant::impl_byte_value,
    iana::{self, HashAlgorithm, Protocol, SignatureAlgorithm},
    prefixed_list::{PrefixedBlob, PrefixedList},
    protocol::{
        extensions::{
            ClientHelloExtension, ClientHelloExtensionData, Extension, ExtensionType,
            KeyShareServerHello, SupportedVersionServerHello,
        },
        AlertDescription, AlertLevel, ContentType, HandshakeType,
    },
};
use brass_aphid_wire_macros::{DecodeEnum, DecodeStruct, EncodeEnum, EncodeStruct};
use std::io::{ErrorKind, Read};

const TLS13_HELLO_RETRY_RANDOM: &[u8] = &[
    207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122,
    187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156,
];

#[derive(Clone, Debug, PartialEq, Eq, EncodeStruct, DecodeStruct)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub protocol_version: Protocol,
    pub record_length: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct HandshakeMessageHeader {
    pub handshake_type: HandshakeType,
    pub handshake_message_length: U24,
}

#[derive(Clone, Debug, PartialEq, Eq, EncodeStruct)]
pub struct ClientHello {
    pub protocol_version: Protocol,
    pub random: [u8; 32],
    pub session_id: PrefixedBlob<u8>,
    pub offered_ciphers: PrefixedList<iana::Cipher, u16>,
    pub compression_methods: PrefixedBlob<u8>,
    /// Extensions are optional, and were not present in SSLv3 and TLS 1.0
    pub extensions: Option<PrefixedList<ClientHelloExtension, u16>>,
}

impl ClientHello {
    pub fn extensions(&self) -> std::io::Result<Vec<Extension>> {
        match &self.extensions {
            Some(extensions) => Ok(extensions.list().iter().map(|ext| ext.raw_extension().unwrap()).collect()),
            None => Err(std::io::Error::new(ErrorKind::NotFound, "you need hotter, younger friends (clients) who send you extensions (aren't TLS 1.0)")),
        }
    }

    /// Return the list of groups that the client supports
    pub fn supported_groups(&self) -> Option<Vec<iana::Group>> {
        for e in self.extensions.as_ref()?.list() {
            if let ClientHelloExtensionData::SupportedGroups(groups) = &e.extension_data {
                return Some(groups.named_curve_list.list().to_vec());
            }
        }
        None
    }

    /// Return the list of groups that the client sent key shares for
    pub fn key_share(&self) -> Option<Vec<iana::Group>> {
        for e in self.extensions.as_ref()?.list() {
            if let ClientHelloExtensionData::KeyShare(groups) = &e.extension_data {
                return Some(
                    groups
                        .client_shares
                        .list()
                        .iter()
                        .map(|key_share| key_share.group)
                        .collect(),
                );
            }
        }
        None
    }
}

impl DecodeValue for ClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (protocol_version, buffer) = buffer.decode_value()?;
        let (random, buffer) = buffer.decode_value()?;
        let (session_id, buffer) = buffer.decode_value()?;
        let (offered_ciphers, buffer) = buffer.decode_value()?;
        let (compression_methods, buffer) = buffer.decode_value()?;

        let protocol_has_extensions =
            protocol_version == Protocol::SSLv3 || protocol_version == Protocol::TLSv1_0;
        let (extensions, buffer) = if protocol_has_extensions {
            (None, buffer)
        } else {
            let (extension, buffer) = buffer.decode_value()?;
            (Some(extension), buffer)
        };

        let value = Self {
            protocol_version,
            random,
            session_id,
            offered_ciphers,
            compression_methods,
            extensions,
        };
        Ok((value, buffer))
    }
}

/// It is a truth universally acknowledged that it's much more fun to lie about
/// the type in the TLV specification, and that have a secret little flag on the
/// inside that actually has to be checked to figure out the real type 😀
///
/// They have to be different structs because the internal data structures are
/// different. E.g. KeyShareServerHello vs KeyShareHelloRetryRequest. This means
/// that they can _not_ be treated the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHelloConfusionMode {
    ServerHello(ServerHello),
    HelloRetryRequest(HelloRetryRequest),
}

impl ServerHelloConfusionMode {
    pub fn cipher_suite(&self) -> iana::Cipher {
        match self {
            ServerHelloConfusionMode::ServerHello(server_hello) => server_hello.cipher_suite,
            ServerHelloConfusionMode::HelloRetryRequest(hello_retry_request) => {
                hello_retry_request.cipher_suite
            }
        }
    }

    pub fn selected_protocol(&self) -> Protocol {
        match self {
            ServerHelloConfusionMode::ServerHello(server_hello) => {
                server_hello.selected_version().unwrap()
            }
            ServerHelloConfusionMode::HelloRetryRequest(hello_retry_request) => {
                hello_retry_request.selected_version().unwrap()
            }
        }
    }
}

// We don't impl EncodeValue, because this should only ever by a temporary value
impl DecodeValue for ServerHelloConfusionMode {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (_protocol, remaining) = Protocol::decode_from(buffer)?;
        let (random, _remaining) = <[u8; 32]>::decode_from(remaining)?;
        if random == HelloRetryRequest::RANDOM {
            let (hrr, remaining) = HelloRetryRequest::decode_from(buffer)?;
            Ok((ServerHelloConfusionMode::HelloRetryRequest(hrr), remaining))
        } else {
            let (sh, remaining) = ServerHello::decode_from(buffer)?;
            Ok((ServerHelloConfusionMode::ServerHello(sh), remaining))
        }
    }
}

impl EncodeValue for ServerHelloConfusionMode {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            ServerHelloConfusionMode::ServerHello(server_hello) => server_hello.encode_to(buffer),
            ServerHelloConfusionMode::HelloRetryRequest(hello_retry_request) => {
                hello_retry_request.encode_to(buffer)
            }
        }
    }
}

///= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
///> The server will send this message in response to a ClientHello
///> message to proceed with the handshake if it is able to negotiate an
///> acceptable set of handshake parameters based on the ClientHello.
///>
///> Structure of this message:
///> ```c
///> struct {
///>     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///>     Random random;
///>     opaque legacy_session_id_echo<0..32>;
///>     CipherSuite cipher_suite;
///>     uint8 legacy_compression_method = 0;
///>     Extension extensions<6..2^16-1>;
///> } ServerHello;
///> ```
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct ServerHello {
    /// remember TLS hates you, and this field is for TLS 1.3.
    ///
    /// Starting with TLS 1.3, the _real_ version is sent as an extension.
    pub protocol_version: Protocol,
    pub random: [u8; 32],
    pub session_id_echo: PrefixedBlob<u8>,
    /// the cipher suite selected by the server
    pub cipher_suite: iana::Cipher,
    pub legacy_compression_method: u8,
    pub extensions: PrefixedList<Extension, u16>,
}

impl ServerHello {
    /// Return the selected version.
    ///
    /// This is either populated from the supported_versions extension or the
    /// protocol_version field.
    pub fn selected_version(&self) -> std::io::Result<Protocol> {
        let maybe_supported_versions = self
            .extensions
            .list()
            .iter()
            .find(|extension| extension.extension_type == ExtensionType::SupportedVersions);

        if let Some(extension) = maybe_supported_versions {
            let supported_version =
                SupportedVersionServerHello::decode_from_exact(extension.extension_data.blob())?;
            Ok(supported_version.selected_version)
        } else {
            Ok(self.protocol_version)
        }
    }

    pub fn selected_group(&self) -> std::io::Result<Option<iana::Group>> {
        let maybe_key_share = self
            .extensions
            .list()
            .iter()
            .find(|extension| extension.extension_type == ExtensionType::KeyShare);

        if let Some(extension) = maybe_key_share {
            let key_share =
                KeyShareServerHello::decode_from_exact(extension.extension_data.blob())?;
            Ok(Some(key_share.server_share.group))
        } else {
            Ok(None)
        }
    }

    pub fn is_hello_retry_tls13(&self) -> bool {
        self.random == TLS13_HELLO_RETRY_RANDOM
    }
}

///= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
///> For reasons of backward compatibility with middleboxes (see
///> Appendix D.4), the HelloRetryRequest message uses the same structure
///> as the ServerHello, but with Random set to the special value of the
///> SHA-256 of "HelloRetryRequest":
///>
///> CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
///> C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct HelloRetryRequest {
    pub protocol_version: Protocol,
    pub random: [u8; 32],
    pub session_id_echo: PrefixedBlob<u8>,
    /// the cipher suite selected by the server
    pub cipher_suite: iana::Cipher,
    pub legacy_compression_method: u8,
    pub extensions: PrefixedList<Extension, u16>,
}

impl HelloRetryRequest {
    pub const RANDOM: [u8; 32] = [
        207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22,
        122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156,
    ];

    /// Return the selected version.
    ///
    /// This is either populated from the supported_versions extension or the
    /// protocol_version field.
    pub fn selected_version(&self) -> std::io::Result<Protocol> {
        let maybe_supported_versions = self
            .extensions
            .list()
            .iter()
            .find(|extension| extension.extension_type == ExtensionType::SupportedVersions);

        if let Some(extension) = maybe_supported_versions {
            let supported_version =
                SupportedVersionServerHello::decode_from_exact(extension.extension_data.blob())?;
            Ok(supported_version.selected_version)
        } else {
            Ok(self.protocol_version)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, EncodeStruct, DecodeStruct)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

#[derive(Clone, Debug, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum ChangeCipherSpec {
    ChangeCipherSpec = 1,
}
impl_byte_value!(ChangeCipherSpec, u8);

// TODO: fix encode
#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

/// Because TLS hates you, you have to choose your form of torture
/// Option 1: embrace the SignatureScheme definition defined in TLS 1.3, and acknowledge
/// that the curve constraint just secretly doesn't apply for TLS 1.2
///
/// Option 2: stick with the SignatureScheme definition and acknowledge that they
/// flipped the order of signature/hash types, so you're parsing has to special
/// case the new variants :ahhhhhh: *head slam into desk*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigHashOrScheme {
    SignatureScheme(iana::SignatureScheme),
    SignatureHash(SignatureAndHashAlgorithm),
}

impl DecodeValue for SigHashOrScheme {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        // try to decode as a signature/hash algorithm
        if let Ok((value, buffer)) = buffer.decode_value() {
            Ok((Self::SignatureHash(value), buffer))
        } else {
            let (value, buffer) = buffer.decode_value()?;
            Ok((Self::SignatureScheme(value), buffer))
        }
    }
}

impl EncodeValue for SigHashOrScheme {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            SigHashOrScheme::SignatureScheme(value) => value.encode_to(buffer)?,
            SigHashOrScheme::SignatureHash(value) => value.encode_to(buffer)?,
        }
        Ok(())
    }
}

///   struct {
///      SignatureAndHashAlgorithm algorithm;
///      opaque signature<0..2^16-1>;
///   } DigitallySigned;
/// https://datatracker.ietf.org/doc/html/rfc5246#section-4.7
#[derive(Debug, Clone, PartialEq, Eq, EncodeStruct, DecodeStruct)]
pub struct DigitallySignedElement {
    pub algorithm: SigHashOrScheme,
    pub signature: PrefixedBlob<u16>,
}

// impl DecodeValue for DigitallySignedElement {
//     fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
//         let (algorithm, mut buffer) = SignatureAndHashAlgorithm::decode_from(buffer)?;
//         let signature_size = algorithm.hash.digest_size();
//         let mut signature: Vec<u8> = vec![0; signature_size];
//         buffer.read_exact(signature.as_mut_slice())?;
//         // TODO: if hash is none, then presumably there is _no_ signature size?
//         let value = Self {
//             algorithm,
//             signature,
//         };
//         Ok((value, buffer))
//     }
// }

// This struct has two variants, but they're both the same length so parsing
// like this is fine.
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateEntry {
    pub cert_data: PrefixedBlob<U24>,
    pub extensions: PrefixedBlob<u16>,
}

/// Used in TLS 1.0 - TLS 1.2
/// Defined in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateTls12ish {
    pub certificate_list: PrefixedBlob<U24>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.3.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct EncryptedExtensions {
    pub extensions: PrefixedBlob<u16>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateRequest {
    pub certificate_request_context: PrefixedBlob<u8>,
    pub extensions: PrefixedBlob<u16>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateTls13 {
    pub certificate_request_context: PrefixedBlob<u8>,
    pub certificate_list: PrefixedList<CertificateEntry, U24>,
}

/// This message is used in TLS 1.2 to convey the server's key material
///
/// This message is omitted for RSA, DH_DSS, and DH_RSA ciphersuites.
///
/// Also, this message is the winner of the "ugliest and nastiest TLS message"
/// award! 🥇
///
/// Check out the `members` modules to see the magnificent slopfest of 15 distinct
/// entities required to parse this message. It also features secret discriminant
/// values that you need to look at the RFC Errata to figure out. Absolutely
/// beautiful 🌸 🌈
///
/// I don't know what TLS is so hard-core committed to a stateful wire protocol,
/// but I am not enjoying it. Like, there are so many funky compromises in the name
/// of legacy/middlebox compatibility, why can't we be nice and include the selected
/// variant in the actual message 🥺? Like, who looked at Type-Length-Value encoding
/// and was like "it'd be so much more fun if you have to reference the Type from
/// six messages ago to figure out what this is 🥰". We are not friends.
///
/// Also because TLS hates you, the EC signature stuff is defined differently than
/// the DHE signature stuff.
///
/// DHE has two different enums, DHE_with_sig and DHE_anon which influences whether
/// there is a digitally signed struct.
///
/// EC only has one enum, and then the signed_param field might just be empty if
/// the cipher suite is anonymous
///
/// Defined in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3
/// Extended in https://datatracker.ietf.org/doc/html/rfc4492#section-5.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKeyExchange {
    // TODO: I'm ignoring ECDH (static) because its awful and ugly
    Ecdhe {
        params: server_key_exchange::ServerEcdhParams,
        signature: server_key_exchange::Signature,
    },
    Dhe {
        params: server_key_exchange::ServerDhParams,
        // we stray slightly from the RFC to reuse the same approach as the EC stuff.
        // there is a single enum for DHE, and signature is internally an optional value
        signed_params: server_key_exchange::Signature,
    },
}

impl DecodeValueWithContext for ServerKeyExchange {
    type Context = iana::Cipher;

    fn decode_from_with_context(
        buffer: &[u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &[u8])> {
        let key_exchange = match context.key_exchange() {
            Some(kx) => kx,
            None => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "server key exchange requires a selected cipher with a key exchange method"
                        .to_string(),
                ));
            }
        };
        println!("selected kx {key_exchange:?} from cipher {context:?}");

        match key_exchange {
            iana::KeyExchange::DHE => {
                let (params, buffer) = server_key_exchange::ServerDhParams::decode_from(buffer)?;
                let (signed_params, buffer) =
                    server_key_exchange::Signature::decode_from_with_context(buffer, context)?;
                Ok((
                    Self::Dhe {
                        params,
                        signed_params,
                    },
                    buffer,
                ))
            }
            iana::KeyExchange::ECDHE => {
                let (params, buffer) = server_key_exchange::ServerEcdhParams::decode_from(buffer)?;
                println!("parsed ecdh params: {params:?}");
                let (signature, buffer) =
                    server_key_exchange::Signature::decode_from_with_context(buffer, context)?;
                Ok((Self::Ecdhe { params, signature }, buffer))
            }
            iana::KeyExchange::RSA => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "server key exchange should not be sent with RSA".to_string(),
            )),
        }
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl DecodeValueWithContext for Finished {
    type Context = iana::Cipher;

    fn decode_from_with_context(
        mut buffer: &[u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &[u8])> {
        let hash_size = context.hash().digest_size();
        let mut verify_data = vec![0; hash_size];
        buffer.read_exact(&mut verify_data)?;

        let value = Self { verify_data };
        Ok((value, buffer))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct NewSessionTicketTls13 {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: PrefixedBlob<u8>,
    pub ticket: PrefixedBlob<u16>,
    pub extensions: PrefixedList<Extension, u16>,
}

/// CertificateVerify definition: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
/// SignatureScheme definition: https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3.1.3
///
/// The TLS 1.2 Cert Verify looks mostly the same on the wire, but uses a sig/hash
/// tuple (ECDSA, SHA256) instead of a signature scheme (ecdsa_secp256r1_sha256).
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertVerifyTls13 {
    pub algorithm: iana::SignatureScheme,
    pub signature: PrefixedBlob<u16>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
}
impl_byte_value!(KeyUpdateRequest, u8);

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct KeyUpdate {
    pub request_update: KeyUpdateRequest,
}

#[cfg(test)]
mod tests {
    use crate::protocol::messages::TLS13_HELLO_RETRY_RANDOM;

    #[test]
    fn hrr() {
        let hex = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";
        assert_eq!(TLS13_HELLO_RETRY_RANDOM, &hex::decode(hex).unwrap());
    }
}
