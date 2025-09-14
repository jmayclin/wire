pub mod content_value;
pub mod extensions;
pub mod messages;

use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeValue},
    discriminant::impl_byte_value,
};
use brass_aphid_wire_macros::{DecodeEnum, EncodeEnum};
pub use messages::*;

/// ContentType is a field on TLS records indicating the kind of data that the
/// record holds.
///
/// - [RFC reference](https://www.rfc-editor.org/rfc/rfc8446#section-5.1)
/// - [IANA reference](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5)
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}
impl_byte_value!(ContentType, u8);

/// The message contained in Handshake content.
///
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    /// https://datatracker.ietf.org/doc/html/rfc5246#section-7.4
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}
impl_byte_value!(HandshakeType, u8);

/// AlertLevel is a field on Alert
/// [RFC reference](https://www.rfc-editor.org/rfc/rfc8446#section-6)
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}
impl_byte_value!(AlertLevel, u8);

/// AlertDescription is a field on Alert
/// [RFC reference](https://www.rfc-editor.org/rfc/rfc8446#section-6)
/// [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6)
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailedReserved = 21,
    RecordOverflow = 22,
    DecompressionFailureReserved = 30,
    HandshakeFailure = 40,
    NoCertificateReserved = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    TooManyCidsRequested = 52,
    ExportRestrictionReserved = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiationReserved = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    CertificateUnobtainableReserved = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValueReserved = 114,
    UnknownPSKIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}
impl_byte_value!(AlertDescription, u8);

#[cfg(test)]
mod tests {
    use crate::codec::{DecodeByteSource, EncodeBytesSink};

    #[test]
    fn decoding() -> std::io::Result<()> {
        let bytes: Vec<u8> = vec![1, 0b11111111, 0b10101010, 32];
        let buffer = bytes.as_slice();
        let (a, buffer): (u8, &[u8]) = buffer.decode_value()?;
        let (b, buffer): (u16, &[u8]) = buffer.decode_value()?;
        let (c, buffer): (u8, &[u8]) = buffer.decode_value()?;
        assert!(buffer.is_empty());

        println!("{b:#b}");

        assert_eq!(a, 1);
        assert_eq!(b, 0b1111111110101010);
        assert_eq!(c, 32);

        let mut sink: Vec<u8> = Vec::new();
        sink.encode_value(&a)?;
        sink.encode_value(&b)?;
        sink.encode_value(&c)?;

        assert_eq!(sink, bytes);

        Ok(())
    }
}
