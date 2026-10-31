//! This module contains all of the top level message definitions

mod members;

pub use members::server_key_exchange;

use crate::{
    codec::{
        take, DecodeByteSource, DecodeValue, DecodeValueWithContext, EncodeBytesSink, EncodeValue,
        RawBytes, U24,
    },
    discriminant::impl_byte_value,
    iana::{self, HashAlgorithm, Protocol, SignatureAlgorithm},
    prefixed_list::{PrefixedBlob, PrefixedList},
    protocol::{
        extensions::{
            Extension, ExtensionType, KeyShare, KeyShareClientHello, KeyShareRetryRequest,
            KeyShareServerHello, SignatureSchemeList, SupportedGroups, SupportedVersionClientHello,
            SupportedVersionServerHello,
        },
        handshake::HandshakeData,
        AlertDescription, AlertLevel, ContentType, HandshakeType,
    },
    writer::{peek_written, Writer},
};
use brass_aphid_wire_macros::{
    DecodeEnum, DecodeStruct, EncodeEnum, EncodeStruct, Writer, WriterStruct,
};
use std::io::ErrorKind;

#[derive(Clone, Debug, PartialEq, Eq, EncodeStruct, DecodeStruct)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub protocol_version: Protocol,
    pub record_length: u16,
}

impl RecordHeader {
    pub const ENCODE_LENGTH: usize = 5;

    pub fn array_encode(&self) -> [u8; Self::ENCODE_LENGTH] {
        let mut aad = [0_u8; RecordHeader::ENCODE_LENGTH];
        let mut aad_view = std::io::Cursor::new(aad.as_mut_slice());
        self.encode_to(&mut aad_view).unwrap();
        aad
    }
}

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct HandshakeMessageHeader {
    pub handshake_type: HandshakeType,
    pub handshake_message_length: U24,
}

#[derive(Clone, Debug, PartialEq, Eq, EncodeStruct, WriterStruct)]
pub struct ClientHello<'a> {
    pub protocol_version: Protocol,
    pub random: [u8; 32],
    pub session_id: PrefixedBlob<'a, u8>,
    pub offered_ciphers: PrefixedList<'a, iana::Cipher, u16>,
    pub compression_methods: PrefixedBlob<'a, u8>,
    /// Extensions are optional, and were not present in SSLv3 and TLS 1.0.
    ///
    /// These are deliberately the generic [`Extension`] (a type plus opaque
    /// bytes) rather than a parsed enum, so that callers only pay to parse the
    /// extensions they actually look at.
    pub extensions: Option<PrefixedList<'a, Extension<'a>, u16>>,
}

/// `ClientHelloWriter` comes from `#[derive(WriterStruct)]`. The encoding is by
/// hand because whether the extensions are written depends on the *value* of the
/// protocol version, which the writer only knows how to write, not how to read.
/// `peek_written` reads it back from the bytes that were just written.
impl<T1, T2, T3, T4, T5, T6> EncodeValue for ClientHelloWriter<T1, T2, T3, T4, T5, T6>
where
    T1: Writer<Protocol>,
    T2: Writer<[u8; 32]>,
    T3: Writer<PrefixedBlob<'static, u8>>,
    T4: Writer<PrefixedList<'static, iana::Cipher, u16>>,
    T5: Writer<PrefixedBlob<'static, u8>>,
    T6: Writer<PrefixedList<'static, Extension<'static>, u16>>,
{
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        let protocol_version = peek_written(
            buffer,
            |buffer| self.protocol_version.encode_transform(buffer),
            |bytes| Protocol::decode_from_exact(bytes),
        )?;

        self.random.encode_transform(buffer)?;
        self.session_id.encode_transform(buffer)?;
        self.offered_ciphers.encode_transform(buffer)?;
        self.compression_methods.encode_transform(buffer)?;

        // the same rule that decoding uses
        match (
            &self.extensions,
            ClientHello::version_has_extensions(protocol_version),
        ) {
            (Some(extensions), true) => extensions.encode_transform(buffer),
            (None, _) => Ok(()),
            (Some(_), false) => Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("{protocol_version:?} client hellos can not have extensions"),
            )),
        }
    }
}

impl<'a> ClientHello<'a> {
    /// Extensions were not present in SSLv3 and TLS 1.0.
    fn version_has_extensions(protocol_version: Protocol) -> bool {
        protocol_version != Protocol::SSLv3 && protocol_version != Protocol::TLSv1_0
    }

    /// All of the extensions, as (type, opaque bytes) pairs. Nothing is parsed
    /// beyond the extension framing.
    pub fn extensions(&self) -> std::io::Result<Vec<Extension<'a>>> {
        match &self.extensions {
            Some(extensions) => Ok(extensions.iter().collect()),
            None => Err(std::io::Error::new(ErrorKind::NotFound, "you need hotter, younger friends (clients) who send you extensions (aren't TLS 1.0)")),
        }
    }

    /// Find the first extension of the given type, without parsing its contents.
    pub fn extension(&self, extension_type: ExtensionType) -> Option<Extension<'a>> {
        self.extensions
            .as_ref()?
            .iter()
            .find(|ext| ext.extension_type == extension_type)
    }

    // NOTE: the typed accessors below parse the extension on demand. An extension
    // that is present but malformed is reported the same as an absent one (None).

    /// Return the list of groups that the client supports
    pub fn supported_groups(&self) -> Option<Vec<iana::Group>> {
        let ext = self.extension(ExtensionType::SupportedGroups)?;
        let groups = SupportedGroups::decode_from_exact(ext.extension_data.blob()).ok()?;
        Some(groups.named_curve_list.iter().collect())
    }

    /// Returns the list of values in the supported versions extension, or the
    /// single value in the client hello `protocol_version` field
    pub fn supported_versions(&self) -> Vec<iana::Protocol> {
        let supported_version = self
            .extension(ExtensionType::SupportedVersions)
            .and_then(|ext| {
                SupportedVersionClientHello::decode_from_exact(ext.extension_data.blob()).ok()
            })
            .map(|versions| versions.versions.iter().collect());

        if let Some(versions) = supported_version {
            versions
        } else {
            vec![self.protocol_version]
        }
    }

    /// Return the offered_ciphers field.
    pub fn supported_ciphers(&self) -> Vec<iana::Cipher> {
        self.offered_ciphers.iter().collect()
    }

    /// Return the values from the signature_scheme extension.
    pub fn supported_signatures(&self) -> Option<Vec<SigHashOrScheme>> {
        let ext = self.extension(ExtensionType::SignatureAlgorithms)?;
        let signatures = SignatureSchemeList::decode_from_exact(ext.extension_data.blob()).ok()?;
        Some(signatures.supported_signature_algorithms.iter().collect())
    }

    /// Return the list of groups that the client sent key shares for
    pub fn key_share(&self) -> Option<Vec<iana::Group>> {
        let ext = self.extension(ExtensionType::KeyShare)?;
        let shares = KeyShareClientHello::decode_from_exact(ext.extension_data.blob()).ok()?;
        Some(
            shares
                .client_shares
                .iter()
                .map(|share| share.group)
                .collect(),
        )
    }
}

impl<'a> DecodeValue<'a> for ClientHello<'a> {
    fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let (protocol_version, buffer) = buffer.decode_value()?;
        let (random, buffer) = buffer.decode_value()?;
        let (session_id, buffer) = buffer.decode_value()?;
        let (offered_ciphers, buffer) = buffer.decode_value()?;
        let (compression_methods, buffer) = buffer.decode_value()?;

        let (extensions, buffer) = if !Self::version_has_extensions(protocol_version) {
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
///
/// This is both a ServerHello and a HelloRetryRequest.
///
/// ///= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
/// > For reasons of backward compatibility with middleboxes (see
/// > Appendix D.4), the HelloRetryRequest message uses the same structure
/// > as the ServerHello, but with Random set to the special value of the
/// > SHA-256 of "HelloRetryRequest".
///
/// Use [`ServerHello::is_hrr`] to tell them apart. The `key_share` extension has
/// a different body in each ([`KeyShareServerHello`] and [`KeyShareRetryRequest`]),
/// so which one to read is chosen by whoever is reading the extension.
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct, Writer)]
pub struct ServerHello<'a> {
    /// remember TLS hates you, and this field is for TLS 1.3.
    ///
    /// Starting with TLS 1.3, the _real_ version is sent as an extension.
    pub protocol_version: Protocol,
    pub random: [u8; 32],
    pub session_id_echo: PrefixedBlob<'a, u8>,
    /// the cipher suite selected by the server
    pub cipher_suite: iana::Cipher,
    pub legacy_compression_method: u8,
    pub extensions: PrefixedList<'a, Extension<'a>, u16>,
}

impl<'a> ServerHello<'a> {
    /// The `random` that marks a HelloRetryRequest: the SHA-256 of
    /// "HelloRetryRequest".
    pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
        207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22,
        122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156,
    ];

    /// Whether this is a HelloRetryRequest rather than a regular ServerHello.
    pub fn is_hrr(&self) -> bool {
        self.random == Self::HELLO_RETRY_REQUEST_RANDOM
    }

    /// Find the first extension of the given type, without parsing its body.
    pub fn extension(&self, extension_type: ExtensionType) -> Option<Extension<'a>> {
        self.extensions
            .iter()
            .find(|ext| ext.extension_type == extension_type)
    }

    /// Return the selected version.
    ///
    /// This is either populated from the supported_versions extension or the
    /// protocol_version field.
    pub fn selected_version(&self) -> std::io::Result<Protocol> {
        match self.extension(ExtensionType::SupportedVersions) {
            Some(extension) => Ok(SupportedVersionServerHello::decode_from_exact(
                extension.extension_data.blob(),
            )?
            .selected_version),
            None => Ok(self.protocol_version),
        }
    }

    /// The key share that the server sent. Only a regular ServerHello has one: a
    /// HelloRetryRequest holds a different structure, see
    /// [`ServerHello::selected_group`], and this is an error for it.
    pub fn key_share(&self) -> std::io::Result<Option<KeyShare<'a>>> {
        if self.is_hrr() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "a HelloRetryRequest has no server share, use selected_group",
            ));
        }
        match self.extension(ExtensionType::KeyShare) {
            Some(ext) => Ok(Some(
                KeyShareServerHello::decode_from_exact(ext.extension_data.blob())?.server_share,
            )),
            None => Ok(None),
        }
    }

    /// The group that a HelloRetryRequest asks for a new key share in. A regular
    /// ServerHello holds a different structure, see [`ServerHello::key_share`],
    /// and this is an error for it.
    pub fn selected_group(&self) -> std::io::Result<Option<iana::Group>> {
        if !self.is_hrr() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "only a HelloRetryRequest has a selected group, use key_share",
            ));
        }
        match self.extension(ExtensionType::KeyShare) {
            Some(ext) => Ok(Some(
                KeyShareRetryRequest::decode_from_exact(ext.extension_data.blob())?.selected_group,
            )),
            None => Ok(None),
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
    Unknown(u8),
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

impl<'a> DecodeValue<'a> for SigHashOrScheme {
    fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        // Try to decode as a signature/hash algorithm pair. Only accept it if
        // both the hash and signature are recognized variants — otherwise treat
        // the two bytes as a SignatureScheme value.
        //
        // Peek via `freeze()` so we don't consume `buffer` before we know which
        // variant to decode; both variants consume the same number of bytes.
        if let Ok((value, _)) = SignatureAndHashAlgorithm::decode_from(buffer) {
            if !matches!(value.hash, HashAlgorithm::Unknown(_))
                && !matches!(value.signature, SignatureAlgorithm::Unknown(_))
            {
                let (value, buffer) = SignatureAndHashAlgorithm::decode_from(buffer)?;
                return Ok((Self::SignatureHash(value), buffer));
            }
        }
        let (value, buffer) = buffer.decode_value()?;
        Ok((Self::SignatureScheme(value), buffer))
    }
}

/// A bare `SignatureScheme` is a valid `SigHashOrScheme`, so it can be written as
/// one without wrapping it. (The reverse is not true.)
impl Writer<SigHashOrScheme> for iana::SignatureScheme {
    fn encode_transform(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        self.encode_to(buffer)
    }
}

impl EncodeValue for SigHashOrScheme {
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
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
pub struct DigitallySignedElement<'a> {
    pub algorithm: SigHashOrScheme,
    pub signature: PrefixedBlob<'a, u16>,
}

// impl<'a> DecodeValue<'a> for DigitallySignedElement<'a> {
//     fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
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
pub struct CertificateEntry<'a> {
    pub cert_data: PrefixedBlob<'a, U24>,
    pub extensions: PrefixedBlob<'a, u16>,
}

/// Used in TLS 1.0 - TLS 1.2
/// Defined in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateTls12ish<'a> {
    pub certificate_list: PrefixedBlob<'a, U24>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.3.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct, Writer)]
pub struct EncryptedExtensions<'a> {
    pub extensions: PrefixedList<'a, Extension<'a>, u16>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateRequest<'a> {
    pub certificate_request_context: PrefixedBlob<'a, u8>,
    pub extensions: PrefixedBlob<'a, u16>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateTls13<'a> {
    pub certificate_request_context: PrefixedBlob<'a, u8>,
    pub certificate_list: PrefixedList<'a, CertificateEntry<'a>, U24>,
}

impl<'a> HandshakeData for CertificateTls13<'a> {
    const TYPE: HandshakeType = HandshakeType::Certificate;
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
pub enum ServerKeyExchange<'a> {
    // TODO: I'm ignoring ECDH (static) because its awful and ugly
    Ecdhe {
        params: server_key_exchange::ServerEcdhParams<'a>,
        signature: server_key_exchange::Signature<'a>,
    },
    Dhe {
        params: server_key_exchange::ServerDhParams<'a>,
        // we stray slightly from the RFC to reuse the same approach as the EC stuff.
        // there is a single enum for DHE, and signature is internally an optional value
        signed_params: server_key_exchange::Signature<'a>,
    },
}

impl<'a> DecodeValueWithContext<'a> for ServerKeyExchange<'a> {
    type Context = iana::Cipher;

    fn decode_from_with_context(
        buffer: &'a [u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &'a [u8])> {
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
///
/// The `verify_data` is not length prefixed. Its length is the hash size of the
/// negotiated cipher, so decoding needs that cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EncodeStruct, Writer)]
pub struct Finished<'a> {
    pub verify_data: RawBytes<'a>,
}

impl<'a> DecodeValueWithContext<'a> for Finished<'a> {
    type Context = iana::Cipher;

    fn decode_from_with_context(
        buffer: &'a [u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &'a [u8])> {
        // the cipher comes from the peer, so an unknown one is an error, not a panic
        let hash = context.try_hash().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("{context} does not name a hash, so the Finished length is unknown"),
            )
        })?;
        let (verify_data, buffer) = take(buffer, hash.digest_size())?;
        let value = Self {
            verify_data: RawBytes(verify_data),
        };
        Ok((value, buffer))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct NewSessionTicketTls13<'a> {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: PrefixedBlob<'a, u8>,
    pub ticket: PrefixedBlob<'a, u16>,
    pub extensions: PrefixedList<'a, Extension<'a>, u16>,
}

/// CertificateVerify definition: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
/// SignatureScheme definition: https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3.1.3
///
/// The TLS 1.2 Cert Verify looks mostly the same on the wire, but uses a sig/hash
/// tuple (ECDSA, SHA256) instead of a signature scheme (ecdsa_secp256r1_sha256).
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertVerifyTls13<'a> {
    pub algorithm: iana::SignatureScheme,
    pub signature: PrefixedBlob<'a, u16>,
}

impl<'a> HandshakeData for CertVerifyTls13<'a> {
    const TYPE: HandshakeType = HandshakeType::CertificateVerify;
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
    Unknown(u8),
}
impl_byte_value!(KeyUpdateRequest, u8);

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct KeyUpdate {
    pub request_update: KeyUpdateRequest,
}

#[cfg(test)]
mod tests {
    use crate::protocol::ServerHello;

    #[test]
    fn hrr() {
        let hex = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";
        assert_eq!(
            ServerHello::HELLO_RETRY_REQUEST_RANDOM.as_slice(),
            &hex::decode(hex).unwrap()
        );
    }
}
