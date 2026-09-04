pub mod constants;
mod definitions;

use crate::codec::DecodeByteSource;
use crate::{
    codec::{DecodeValue, EncodeValue},
    discriminant::impl_byte_value,
};
use brass_aphid_wire_macros::{DecodeEnum, EncodeEnum};
use byteorder::{BigEndian, ReadBytesExt};
pub use definitions::*;
use std::io::Read;

impl DecodeValue for SignatureScheme {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.decode_value()?;
        Ok((SignatureScheme { value }, remaining))
    }
}

impl DecodeValue for Group {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.decode_value()?;
        Ok((Group { value }, remaining))
    }
}

impl DecodeValue for Cipher {
    fn decode_from<S: DecodeByteSource>(buffer: S) -> std::io::Result<(Self, S)> {
        let (value, remaining) = buffer.decode_value()?;
        Ok((Cipher { value }, remaining))
    }
}

impl EncodeValue for SignatureScheme {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        self.value.encode_to(buffer)
    }
}

impl EncodeValue for Group {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        self.value.encode_to(buffer)
    }
}

impl EncodeValue for Cipher {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        self.value.encode_to(buffer)
    }
}

impl SignatureScheme {
    pub fn hash(&self) -> Option<HashAlgorithm> {
        let description = self.description()?;
        if description.ends_with("sha256") {
            Some(HashAlgorithm::Sha256)
        } else if description.ends_with("sha384") {
            Some(HashAlgorithm::Sha384)
        } else if description.ends_with("sha512") {
            Some(HashAlgorithm::Sha512)
        } else {
            None
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::EnumIter,
    DecodeEnum,
    EncodeEnum,
    Ord,
    PartialOrd,
    Hash,
)]
#[repr(u16)]
pub enum Protocol {
    SSLv2 = 0x0002,
    SSLv3 = 0x0300,
    TLSv1_0 = 0x0301,
    TLSv1_1 = 0x0302,
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
    Unknown(u16),
}
impl_byte_value!(Protocol, u16);

impl Cipher {
    pub fn hash(&self) -> HashAlgorithm {
        let description = self.description().expect("no description for cipher");
        if description.ends_with("SHA512") {
            HashAlgorithm::Sha512
        } else if description.ends_with("SHA384") {
            HashAlgorithm::Sha384
        } else if description.ends_with("SHA256") {
            HashAlgorithm::Sha256
        } else if description.ends_with("SHA224") {
            HashAlgorithm::Sha224
        } else {
            todo!("no recognized hash for {self}");
        }
    }
}

/// Defined in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum HashAlgorithm {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
    Unknown(u8),
}
impl_byte_value!(HashAlgorithm, u8);
impl HashAlgorithm {
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::None => 0,
            HashAlgorithm::Md5 => 16,    // 128 bits
            HashAlgorithm::Sha1 => 20,   // 160 bits
            HashAlgorithm::Sha224 => 28, // 224 bits
            HashAlgorithm::Sha256 => 32, // 256 bits
            HashAlgorithm::Sha384 => 48, // 384 bits
            HashAlgorithm::Sha512 => 64, // 512 bits
            HashAlgorithm::Unknown(_) => 0,
        }
    }
}

/// Defined in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
///
/// Note that RSA-PSS is not defined as a signature algorithm variant. Rather is
/// part of the new SignatureScheme thing that complicates my parsing
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    Anonymous = 0,
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
    Unknown(u8),
}
impl_byte_value!(SignatureAlgorithm, u8);

#[derive(Debug)]
pub enum KeyExchange {
    DHE,
    RSA,
    ECDHE,
}

impl Cipher {
    /// return the key exchange used for the cipher.
    ///
    /// This will be None for TLS 1.3 or other NULL ciphers.
    pub fn key_exchange(&self) -> Option<KeyExchange> {
        let description = self.description()?;
        if description.contains("TLS_DHE") || description.contains("TLS_DH_anon") {
            Some(KeyExchange::DHE)
        } else if description.contains("TLS_RSA") {
            Some(KeyExchange::RSA)
        } else if description.contains("TLS_ECDHE") || description.contains("TLS_ECDH_anon") {
            Some(KeyExchange::ECDHE)
        } else {
            None
        }
    }

    /// Return the authentication signature associated with a cipher.
    ///
    /// This is generally the third token in a cipher string. For example
    /// `TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256.auth_signature()` will return
    /// `Some(Sig::RSA)`.
    pub fn auth_signature(&self) -> Option<SignatureAlgorithm> {
        if self.supports_tls13() {
            return None;
        }

        let description = self.description()?;
        let without_prefix = &description["TLS_".len()..];
        // RSA kx and PSK kx don't have signatures
        if without_prefix.starts_with("RSA_WITH")
            || without_prefix.starts_with("RSA_EXPORT_WITH")
            || without_prefix.starts_with("PSK_WITH")
            || without_prefix.starts_with("SRP_SHA")
            || without_prefix.starts_with("ADH")
            || without_prefix.starts_with("NULL")
        {
            return None;
        }

        let kx_and_auth = without_prefix.find("_WITH_").unwrap();
        let kx_and_auth = &without_prefix[0..kx_and_auth];

        if kx_and_auth.contains("RSA") {
            Some(SignatureAlgorithm::Rsa)
        } else if kx_and_auth.contains("ECDSA") {
            Some(SignatureAlgorithm::Ecdsa)
        } else if kx_and_auth.contains("DSS") {
            Some(SignatureAlgorithm::Dsa)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check that the generated constants have the expected values.
    #[test]
    fn constants_match() {
        // "0x00,0x07",TLS_RSA_WITH_IDEA_CBC_SHA,Y,N,[RFC8996]
        assert_eq!(
            constants::TLS_RSA_WITH_IDEA_CBC_SHA.description(),
            Some("TLS_RSA_WITH_IDEA_CBC_SHA")
        );
        assert_eq!(constants::TLS_RSA_WITH_IDEA_CBC_SHA.value, [0x00, 0x07]);
    }
}
