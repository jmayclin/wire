//! This module contains all of the data shapes for TLS extensions.
//! TLS extension are used in many different handshake message. Most importantly
//! they are used in the ClientHello and the ServerHello, but that are also used
//! in messages like EncryptedExtensions, Certificate, NewSessionTicket, and others.
//!
//! Because the TLS is sentient and loathes you, it loves to define structs as a
//! dynamic "switch" statement that depend on external runtime information.
//!
//! For example, the ServerKeyExchange

use crate::codec::{DecodeValueWithContext, EncodeBytesSink};
use crate::discriminant::impl_byte_value;
use crate::iana;
use crate::protocol::SigHashOrScheme;
use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeValue},
    iana::Protocol,
    prefixed_list::{PrefixedBlob, PrefixedList},
};
use brass_aphid_wire_macros::{DecodeEnum, DecodeStruct, EncodeEnum, EncodeStruct};
use std::fmt::Debug;
use std::io::{ErrorKind, Read};
use strum::IntoEnumIterator;

/// This is the "basic" extension struct. Any extension will be able to be parsed
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct Extension {
    // TODO: emit metrics whenever we see an extension type that isn't recognized
    pub extension_type: ExtensionType,
    pub extension_data: PrefixedBlob<u16>,
}

/// Extensions can be sent in many messages, including but not limited to
/// - ClientHello
/// - ServerHello
/// - EncryptedExtensions (TLS 1.3, server)
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter)]
#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    /// Indicates the curves/groups that the client is willing to use for key exchange.
    ///
    /// In TLS 1.2, this extension is referred to as "supported curves".                    
    SupportedGroups = 10,
    EcPointFormats = 11,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    EncryptThenMac = 22,
    ExtendedMasterSecret = 23,
    RecordSizeLimit = 28,
    SessionTicket = 35,
    PreSharedKey = 41,
    EarlyData = 42,
    /// An extension introduced in TLS 1.3 that is used to negotiate the TLS version              
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    RenegotiationInfo = 65281,
    Unknown(u16),
}
impl_byte_value!(ExtensionType, u16);

impl EncodeValue for ExtensionType {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        if let Self::Unknown(ext) = self {
            buffer.encode_value(ext)?
        } else {
            buffer.encode_value(&self.byte_value())?
        }
        Ok(())
    }
}

impl DecodeValue for ExtensionType {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, buffer) = u16::decode_from(buffer)?;
        let value = match ExtensionType::iter().find(|x| x.byte_value() == value) {
            Some(ExtensionType::Unknown(_)) => ExtensionType::Unknown(value),
            Some(known) => known,
            None => ExtensionType::Unknown(value),
        };
        Ok((value, buffer))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, DecodeEnum, EncodeEnum)]
#[repr(u8)]
enum NameType {
    Host = 0,
}
impl_byte_value!(NameType, u8);

#[derive(DecodeStruct, PartialEq, Eq, Clone, EncodeStruct)]
pub struct ServerName {
    name_type: NameType,
    pub host_name: PrefixedBlob<u16>,
}

impl Debug for ServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerName")
            .field("name_type", &self.name_type)
            .field("host_name", &String::from_utf8_lossy(self.host_name.blob()))
            .finish()
    }
}

/// the actual extension value for an SNI extension
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct ServerNameClientHello {
    pub server_name_list: PrefixedList<ServerName, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct SupportedVersionClientHello {
    pub versions: PrefixedList<Protocol, u8>,
}

/// https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct SupportedGroups {
    pub named_curve_list: PrefixedList<iana::Group, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
struct ServerSupportedVersions {
    versions: PrefixedList<Protocol, u8>,
}

/// Defined in https://datatracker.ietf.org/doc/html/rfc4492#section-5.1.2
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, DecodeEnum, EncodeEnum)]
#[repr(u8)]
pub enum EcPointFormat {
    Uncompressed = 0,
    AnsiX962CompressedPrime = 1,
    AnsiX962CompressedChar2 = 2,
    /* Reserver 248..255 */
}
impl_byte_value!(EcPointFormat, u8);

/// Defined in https://datatracker.ietf.org/doc/html/rfc4492#section-5.1.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct EcPointFormatList {
    pub ec_point_format_list: PrefixedList<EcPointFormat, u8>,
}

/// Defined in https://www.ietf.org/rfc/rfc7627.html#section-5.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct ExtendedMasterSecret {}

/// Defined in https://datatracker.ietf.org/doc/html/rfc5746#section-3.2
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct RenegotiationInfo {
    renegotiated_connection: PrefixedBlob<u8>,
}

/// https://www.rfc-editor.org/rfc/rfc6066#section-4
#[derive(Debug, PartialEq, Eq, strum::EnumIter, DecodeEnum)]
#[repr(u8)]
pub enum MaxFragmentLength {
    F512 = 1,
    F1024 = 2,
    F2048 = 3,
    F4096 = 4,
}
impl_byte_value!(MaxFragmentLength, u8);

#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct KeyShare {
    pub group: iana::Group,
    pub key_exchange: PrefixedBlob<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, DecodeEnum, EncodeEnum)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}
impl_byte_value!(PskKeyExchangeMode, u8);

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct PskKeyExchangeModes {
    ke_modes: PrefixedList<PskKeyExchangeMode, u8>,
}

/// Defined in https://datatracker.ietf.org/doc/html/rfc5077#section-3.2
/// AHHHHHH why are you like this. I do not approve. You have to look backwards.
#[derive(Debug, Clone, PartialEq, Eq, EncodeStruct)]
pub struct SessionTicket {
    pub ticket: Vec<u8>,
}

impl DecodeValueWithContext for SessionTicket {
    /// the length of the extension data
    type Context = u16;

    fn decode_from_with_context(
        mut buffer: &[u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &[u8])> {
        let mut ticket = vec![0; context as usize];
        buffer.read_exact(&mut ticket)?;
        let value = Self { ticket };
        Ok((value, buffer))
    }
}

/// AHHHHHHH
/// Defined in https://www.rfc-editor.org/rfc/rfc7685.html#section-3
#[derive(Debug, Clone, PartialEq, Eq, EncodeStruct)]
pub struct Padding {
    pub padding: Vec<u8>,
}

impl DecodeValueWithContext for Padding {
    /// length of the extension data
    type Context = u16;

    fn decode_from_with_context(
        mut buffer: &[u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &[u8])> {
        let mut padding = vec![0; context as usize];
        buffer.read_exact(&mut padding)?;
        let value = Self { padding };
        Ok((value, buffer))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct EarlyDataClientHello {}

#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct RecordSizeLimit {
    pub limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct KeyShareClientHello {
    pub client_shares: PrefixedList<KeyShare, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct SignatureSchemeList {
    pub supported_signature_algorithms: PrefixedList<SigHashOrScheme, u16>,
}

/// definition: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
#[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct SupportedVersionServerHello {
    pub selected_version: Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct PskIdentity {
    pub identity: PrefixedBlob<u16>,
    pub obfuscated_ticket_age: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct PskBinderEntry {
    entry: PrefixedBlob<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct PresharedKeyClientHello {
    pub identities: PrefixedList<PskIdentity, u16>,
    pub binders: PrefixedList<PskBinderEntry, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, DecodeEnum, EncodeEnum)]
#[repr(u8)]
enum CertificateStatusType {
    Ocsp = 1,
}
impl_byte_value!(CertificateStatusType, u8);

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
struct OcspStatusRequest {
    responder_id_list: PrefixedList<ResponderId, u16>,
    extensions: PrefixedBlob<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
struct ResponderId {
    id: PrefixedBlob<u16>,
}

/// Defined in https://www.rfc-editor.org/rfc/rfc6066.html#section-8
#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct CertificateStatus {
    status_type: CertificateStatusType,
    request: OcspStatusRequest,
}

/// Defined in https://datatracker.ietf.org/doc/html/rfc7366#section-2
/// Sent in ClientHello or ServerHello in TLS 1.2(ish?)
#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct EncryptThenMac {}

/// Defined in https://www.rfc-editor.org/rfc/rfc6962#section-3.3.1
#[derive(Clone, Debug, PartialEq, Eq, DecodeStruct, EncodeStruct)]
pub struct SignedCertificateTimestampClientHello {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloExtensionData {
    PreSharedKey(PresharedKeyClientHello),
    SignatureScheme(SignatureSchemeList),
    ServerName(ServerNameClientHello),
    SupportedVersions(SupportedVersionClientHello),
    SupportedGroups(SupportedGroups),
    KeyShare(KeyShareClientHello),
    EcPointFormat(EcPointFormatList),
    ExtendedMasterSecret(ExtendedMasterSecret),
    RenegotiationInfo(RenegotiationInfo),
    SessionTicket(SessionTicket),
    EarlyData(EarlyDataClientHello),
    PskKeyExchangeModes(PskKeyExchangeModes),
    RecordSizeLimit(RecordSizeLimit),
    Padding(Padding),
    EncryptThenMac(EncryptThenMac),
    StatusRequest(CertificateStatus),
    SignedCertificateTimestamp(SignedCertificateTimestampClientHello),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloExtension {
    pub extension_type: ExtensionType,
    pub extension_data: ClientHelloExtensionData,
}

impl ClientHelloExtension {
    pub fn raw_extension(&self) -> std::io::Result<Extension> {
        let buffer = self.encode_to_vec()?;
        Extension::decode_from_exact(&buffer)
    }
}

// dyn DecodeValue, EncodeValue, Debug

// TODO: would be run to look at the truncated hmac extension (who thought that was a good idea 😭)

impl DecodeValue for ClientHelloExtension {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (extension, buffer) = Extension::decode_from(buffer)?;
        let value = match extension.extension_type {
            ExtensionType::ServerName => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::ServerName(value)
            }
            ExtensionType::PreSharedKey => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::PreSharedKey(value)
            }
            ExtensionType::MaxFragmentLength => todo!(),
            ExtensionType::StatusRequest => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::StatusRequest(value)
            }
            ExtensionType::SupportedGroups => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::SupportedGroups(value)
            }
            ExtensionType::EcPointFormats => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::EcPointFormat(value)
            }
            ExtensionType::SignatureAlgorithms => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::SignatureScheme(value)
            }
            ExtensionType::UseSrtp => todo!(),
            ExtensionType::Heartbeat => todo!(),
            ExtensionType::ApplicationLayerProtocolNegotiation => todo!(),
            ExtensionType::SignedCertificateTimestamp => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::SignedCertificateTimestamp(value)
            }
            ExtensionType::ClientCertificateType => todo!(),
            ExtensionType::ServerCertificateType => todo!(),
            ExtensionType::Padding => {
                let data = &extension.extension_data;
                let (value, buffer) =
                    Padding::decode_from_with_context(data.blob(), data.blob().len() as u16)?;
                if !buffer.is_empty() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "failed to fully parse session ticket",
                    ));
                }
                ClientHelloExtensionData::Padding(value)
            }
            ExtensionType::EncryptThenMac => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::EncryptThenMac(value)
            }
            ExtensionType::ExtendedMasterSecret => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::ExtendedMasterSecret(value)
            }
            ExtensionType::RecordSizeLimit => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::RecordSizeLimit(value)
            }
            ExtensionType::SessionTicket => {
                let data = &extension.extension_data;
                let (value, buffer) =
                    SessionTicket::decode_from_with_context(data.blob(), data.blob().len() as u16)?;
                if !buffer.is_empty() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "failed to fully parse session ticket",
                    ));
                }
                ClientHelloExtensionData::SessionTicket(value)
            }
            ExtensionType::EarlyData => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::EarlyData(value)
            }
            ExtensionType::SupportedVersions => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::SupportedVersions(value)
            }
            ExtensionType::Cookie => todo!(),
            ExtensionType::PskKeyExchangeModes => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::PskKeyExchangeModes(value)
            }
            ExtensionType::CertificateAuthorities => todo!(),
            ExtensionType::OidFilters => todo!(),
            ExtensionType::PostHandshakeAuth => todo!(),
            ExtensionType::SignatureAlgorithmsCert => todo!(),
            ExtensionType::KeyShare => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::KeyShare(value)
            }
            ExtensionType::RenegotiationInfo => {
                let value = extension.extension_data.blob().decode_value_exact()?;
                ClientHelloExtensionData::RenegotiationInfo(value)
            }
            ExtensionType::Unknown(_) => {
                ClientHelloExtensionData::Unknown(extension.extension_data.blob().to_vec())
            }
        };

        let value = Self {
            extension_type: extension.extension_type,
            extension_data: value,
        };

        Ok((value, buffer))
    }
}

impl EncodeValue for ClientHelloExtension {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.extension_type)?;
        let extension_data = match &self.extension_data {
            ClientHelloExtensionData::PreSharedKey(e) => e.encode_to_vec(),
            ClientHelloExtensionData::SignatureScheme(e) => e.encode_to_vec(),
            ClientHelloExtensionData::ServerName(e) => e.encode_to_vec(),
            ClientHelloExtensionData::SupportedVersions(e) => e.encode_to_vec(),
            ClientHelloExtensionData::SupportedGroups(e) => e.encode_to_vec(),
            ClientHelloExtensionData::KeyShare(e) => e.encode_to_vec(),
            ClientHelloExtensionData::Unknown(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::EcPointFormat(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::ExtendedMasterSecret(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::RenegotiationInfo(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::SessionTicket(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::EarlyData(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::PskKeyExchangeModes(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::RecordSizeLimit(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::Padding(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::EncryptThenMac(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::StatusRequest(extension) => extension.encode_to_vec(),
            ClientHelloExtensionData::SignedCertificateTimestamp(extension) => {
                extension.encode_to_vec()
            }
        }?;
        let length = extension_data.len() as u16;
        buffer.encode_value(&length)?;
        buffer.encode_value(&extension_data)?;
        Ok(())
    }
}
