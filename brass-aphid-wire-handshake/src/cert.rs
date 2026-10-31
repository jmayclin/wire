//! A minimal X509 parser to efficiently extract the limited information that we
//! care about.
//!
//! ### Why not get this from s2n-tls?
//!
//! C/Rust FFI gets you the worst of both worlds. It would require defining all
//! of the enums on the C side, and threading that access through into the rust
//! bindings. Additionally, most of these fields are not currently public. With
//! the current state of the C library, it seems better to have a strongly encapsulated
//! chunk of complexity in the non-security critical component, rather than pushing
//! that down into the TLS layer.
//!
//! Additionally, this keeps open a future where the metrics subscriber is also
//! used by AWS-LC's libssl.
//!
//! ### Why not use an existing library?
//!
//! Performance.
//!
//! These are numbers from a very rough benchmark that I did 2026-04-17.
//!
//! |    Parser   | Per-cert |
//! |-------------|----------|
//! | webpki      |  0.333µs (no key/sig) |
//! | s2n-codec   |  0.222µs |
//! | x509-parser |  5.7µs |
//! | x509-cert   | 13.8µs |
//! | aws-lc      | 21.7µs |
//!
//! Existing cert parsing libraries are roughly 25x slower than this custom implementation.
//! webpki is very speedy, but doesn't pull out the key/signature information that
//! we need.
//!
//! While 5.7 us may seem pretty fast, in an mTLS case we might end up parsing 6
//! cert chains per handshake, and adding 34.2 us would be a nearly 10% performance
//! hit.

/// The public key algorithm (and size/curve) of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKeyType {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    RsaPss2048,
    RsaPss3072,
    RsaPss4096,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    Unknown,
}

/// The signature algorithm used to sign a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSignatureAlgorithm {
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    RsaPss,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Unknown,
}

/// Parsed cert fields from the TBSCertificate.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCertContent {
    /// The certificate serial number (raw INTEGER content bytes).
    pub serial: Vec<u8>,
    /// The issuer (CA) of the certificate, e.g. `Amazon Root CA 1`
    pub issuer: String,
    /// The subject of the certificate subject, e.g. `sqs.us-east-2.amazonaws.com`
    pub common_name: String,
    /// The public key algorithm of the certificate.
    pub key_type: CertKeyType,
    /// The signature algorithm used to sign the certificate.
    pub signature: CertSignatureAlgorithm,
}

mod der_codec {
    use super::{CertKeyType, CertSignatureAlgorithm};
    use brass_aphid_wire_messages::codec::{DecodeByteSource, DecodeValue};
    use const_oid::ObjectIdentifier;
    use core::mem::size_of;
    use std::io::{Error, ErrorKind};

    /// Build an `InvalidData` error for a DER invariant violation.
    fn invariant(message: &'static str) -> Error {
        Error::new(ErrorKind::InvalidData, message)
    }

    // DER tag constants
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_OID: u8 = 0x06;
    const TAG_BIT_STRING: u8 = 0x03;
    const TAG_CONTEXT_0: u8 = 0xa0; // [0] EXPLICIT (certificate version)
                                    // X.520 DirectoryString types (RFC 5280 §4.1.2.4)
    /// Full Unicode via UTF-8. The modern default for new certificates.
    const TAG_UTF8_STRING: u8 = 0x0c;
    /// Restricted to A-Z, a-z, 0-9, space, and ' ( ) + , - . / : = ?
    const TAG_PRINTABLE_STRING: u8 = 0x13;
    /// ASCII (0x00-0x7F). Used for email addresses and domain names.
    const TAG_IA5_STRING: u8 = 0x16;

    // Signature algorithm OIDs
    const OID_RSA_PKCS_SHA1: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5").as_bytes();
    const OID_RSA_PKCS_SHA256: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11").as_bytes();
    const OID_RSA_PKCS_SHA384: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12").as_bytes();
    const OID_RSA_PKCS_SHA512: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13").as_bytes();
    const OID_RSA_PSS: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10").as_bytes();
    const OID_ECDSA_SHA256: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2").as_bytes();
    const OID_ECDSA_SHA384: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3").as_bytes();
    const OID_ECDSA_SHA512: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4").as_bytes();

    // Key algorithm OIDs
    const OID_RSA_KEY: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1").as_bytes();
    const OID_RSA_PSS_KEY: &[u8] = OID_RSA_PSS;
    const OID_EC_PUBLIC_KEY: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1").as_bytes();

    // EC named curve OIDs
    const OID_SECP256R1: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7").as_bytes();
    const OID_SECP384R1: &[u8] = ObjectIdentifier::new_unwrap("1.3.132.0.34").as_bytes();
    const OID_SECP521R1: &[u8] = ObjectIdentifier::new_unwrap("1.3.132.0.35").as_bytes();

    // Common Name OID
    const OID_CN: &[u8] = ObjectIdentifier::new_unwrap("2.5.4.3").as_bytes();

    pub fn signature_from_oid(oid: &[u8]) -> CertSignatureAlgorithm {
        match oid {
            OID_RSA_PKCS_SHA1 => CertSignatureAlgorithm::RsaPkcsSha1,
            OID_RSA_PKCS_SHA256 => CertSignatureAlgorithm::RsaPkcsSha256,
            OID_RSA_PKCS_SHA384 => CertSignatureAlgorithm::RsaPkcsSha384,
            OID_RSA_PKCS_SHA512 => CertSignatureAlgorithm::RsaPkcsSha512,
            OID_RSA_PSS => CertSignatureAlgorithm::RsaPss,
            OID_ECDSA_SHA256 => CertSignatureAlgorithm::EcdsaSha256,
            OID_ECDSA_SHA384 => CertSignatureAlgorithm::EcdsaSha384,
            OID_ECDSA_SHA512 => CertSignatureAlgorithm::EcdsaSha512,
            _ => CertSignatureAlgorithm::Unknown,
        }
    }

    /// A DER-encoded length field.
    ///
    /// DER length encoding:
    /// - `< 0x80`: short form — the byte IS the length (0–127)
    /// - `>= 0x80`: long form — low 7 bits = number of subsequent bytes
    ///   encoding the length as a big-endian unsigned integer
    /// - `0x80` (indefinite length) is invalid in DER
    struct DerLength(usize);

    enum DerLengthEncoding {
        Short,
        Long,
        Indefinite,
    }

    impl DerLengthEncoding {
        const SENTINEL_VALUE: u8 = 0b10000000;
        const LONG_FORM_MASK: u8 = 0b01111111;
        fn from_first_byte(first_length_byte: u8) -> Self {
            if first_length_byte < Self::SENTINEL_VALUE {
                Self::Short
            } else if first_length_byte > Self::SENTINEL_VALUE {
                Self::Long
            } else {
                Self::Indefinite
            }
        }
    }

    impl<'a> DecodeValue<'a> for DerLength {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            let first = *buffer
                .first()
                .ok_or_else(|| invariant("no bytes remain while decoding DER length"))?;
            let encoding = DerLengthEncoding::from_first_byte(first);
            match encoding {
                DerLengthEncoding::Short => {
                    let (length, buffer) = buffer.decode_value::<u8>()?;
                    Ok((DerLength(length as usize), buffer))
                }
                DerLengthEncoding::Long => {
                    // the number of bytes in the length encoding
                    let (length_encoding_size, buffer) = {
                        let (size, buffer) = buffer.decode_value::<u8>()?;
                        let size = (size & DerLengthEncoding::LONG_FORM_MASK) as usize;
                        if size > size_of::<usize>() {
                            return Err(invariant("DER length exceeds usize capacity"));
                        }
                        (size, buffer)
                    };
                    let (length, buffer) = {
                        let (raw, buffer) =
                            brass_aphid_wire_messages::codec::take(buffer, length_encoding_size)?;
                        let mut buf = [0u8; size_of::<usize>()];
                        let start = size_of::<usize>()
                            .checked_sub(raw.len())
                            .ok_or_else(|| invariant("DER length exceeds usize capacity"))?;
                        buf.get_mut(start..)
                            .ok_or_else(|| invariant("DER length exceeds usize capacity"))?
                            .copy_from_slice(raw);
                        (usize::from_be_bytes(buf), buffer)
                    };
                    // X.690 §10.1: DER requires minimal length encoding.
                    // Values < 0x80 must use the short (single-byte) form.
                    if length < DerLengthEncoding::SENTINEL_VALUE as usize {
                        return Err(invariant("non-minimal length encoding"));
                    }
                    Ok((DerLength(length), buffer))
                }
                DerLengthEncoding::Indefinite => {
                    // "indefinite" form of length encoding, not allowed for DER
                    // > The definite form of length encoding shall be used, encoded in the minimum number of octets.
                    // > 10.1 - Distinguished Encoding Rules: Length Forms
                    // > ITU-T X.690
                    Err(invariant("indefinite length encoding not allowed"))
                }
            }
        }
    }

    /// A DER tag-length-value: (tag, content bytes).
    ///
    /// Prefer to use strongly typed containers like [`DerSequence`], [`DerSet`],
    /// etc for decoding ease.
    ///
    /// Developer note: I previously tried to parse tag into an enum, but the 10-ish
    /// way match statement nearly doubled the cost of cert parsing.
    struct Tlv {
        tag: u8,
        content: Vec<u8>,
    }

    impl<'a> DecodeValue<'a> for Tlv {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            let (tag, buffer) = buffer.decode_value::<u8>()?;
            const MULTI_BYTE_TAG_MASK: u8 = 0x1F;
            // X.509 certificates only use single-byte tags. Multi-byte tags
            // (low 5 bits all set) would cause us to misparse subsequent bytes.
            if tag & MULTI_BYTE_TAG_MASK == MULTI_BYTE_TAG_MASK {
                return Err(invariant("multi-byte tags not supported"));
            }
            let (DerLength(len), buffer) = buffer.decode_value::<DerLength>()?;
            let (content, buffer) = brass_aphid_wire_messages::codec::take(buffer, len)?;
            Ok((
                Tlv {
                    tag,
                    content: content.to_vec(),
                },
                buffer,
            ))
        }
    }

    /// Macro to define a typed DER element that decodes a TLV and asserts the
    /// expected tag. Each generated struct contains only the content bytes.
    macro_rules! der_element {
        ($name:ident, $tag:expr, $doc:expr) => {
            #[doc = $doc]
            pub struct $name {
                // allow dead code because this field may not be read for all
                // der element types
                #[allow(dead_code)]
                pub content: Vec<u8>,
            }

            impl<'a> DecodeValue<'a> for $name {
                fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
                    let (tlv, buffer) = buffer.decode_value::<Tlv>()?;
                    if tlv.tag != $tag {
                        return Err(invariant(concat!("expected ", stringify!($name))));
                    }
                    Ok((
                        $name {
                            content: tlv.content,
                        },
                        buffer,
                    ))
                }
            }
        };
    }

    der_element!(DerSequence, TAG_SEQUENCE, "A DER SEQUENCE element.");
    der_element!(DerSet, TAG_SET, "A DER SET element.");
    der_element!(DerInteger, TAG_INTEGER, "A DER INTEGER element.");
    der_element!(DerOid, TAG_OID, "A DER OID element.");
    der_element!(DerContext0, TAG_CONTEXT_0, "A DER [0] EXPLICIT element.");

    /// A DER BIT STRING element.
    ///
    /// The first content byte is the unused bits count (0–7), indicating how
    /// many trailing bits in the last byte are padding.
    pub struct DerBitString {
        pub unused_bits: u8,
        pub content: Vec<u8>,
    }

    impl<'a> DecodeValue<'a> for DerBitString {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            let (tlv, buffer) = buffer.decode_value::<Tlv>()?;
            if tlv.tag != TAG_BIT_STRING {
                return Err(invariant("expected DerBitString"));
            }
            let (&unused_bits, content) = tlv
                .content
                .split_first()
                .ok_or_else(|| invariant("BIT STRING content too short"))?;
            Ok((
                DerBitString {
                    unused_bits,
                    content: content.to_vec(),
                },
                buffer,
            ))
        }
    }

    /// A DER string element that must contain valid UTF-8.
    ///
    /// Accepts UTF8String (0x0c), PrintableString (0x13), and IA5String (0x16).
    pub struct DerUtf8ishString {
        pub content: String,
    }

    impl<'a> DecodeValue<'a> for DerUtf8ishString {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            let (tlv, buffer) = buffer.decode_value::<Tlv>()?;
            match tlv.tag {
                // PrintableString and IA5String are subsets of UTF-8
                TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => {}
                _ => {
                    return Err(invariant("expected UTF-8 string tag"));
                }
            }
            let content = String::from_utf8(tlv.content).map_err(|_| invariant("invalid utf8"))?;
            Ok((DerUtf8ishString { content }, buffer))
        }
    }

    /// Helper: decode an OID and return the raw content bytes.
    fn decode_oid(buffer: &[u8]) -> std::io::Result<(Vec<u8>, &[u8])> {
        let (oid, buffer) = buffer.decode_value::<DerOid>()?;
        Ok((oid.content, buffer))
    }

    /// The RSA public key decoded from a BIT STRING containing
    /// SEQUENCE { INTEGER(modulus), INTEGER(exponent) }.
    struct RsaPublicKey {
        modulus: Vec<u8>,
    }

    impl<'a> DecodeValue<'a> for RsaPublicKey {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            // BIT STRING wrapper
            let (bits, buffer) = buffer.decode_value::<DerBitString>()?;
            if bits.unused_bits != 0 {
                return Err(invariant("BIT STRING has non-zero unused bits"));
            }
            // outer SEQUENCE
            let (seq, _) = bits.content.as_slice().decode_value::<DerSequence>()?;
            // first INTEGER is the modulus
            let (modulus_int, _) = seq.content.as_slice().decode_value::<DerInteger>()?;
            let modulus = modulus_int.content;
            // strip leading 0x00 sign padding
            let modulus = if modulus.first() == Some(&0x00) {
                modulus.get(1..).map(<[u8]>::to_vec).unwrap_or(modulus)
            } else {
                modulus
            };
            Ok((RsaPublicKey { modulus }, buffer))
        }
    }

    /// A newtype wrapper so we can implement `DecodeValue` for the key type.
    pub struct CertKeyWrapper(pub CertKeyType);

    /// Decode a KeyType from the content of a subjectPublicKeyInfo SEQUENCE.
    impl<'a> DecodeValue<'a> for CertKeyWrapper {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            // AlgorithmIdentifier SEQUENCE
            let (key_alg, rest) = buffer.decode_value::<DerSequence>()?;
            let (key_oid, key_alg_rest) = decode_oid(key_alg.content.as_slice())?;

            match key_oid.as_slice() {
                OID_EC_PUBLIC_KEY => {
                    let (curve_oid, _) = decode_oid(key_alg_rest)?;
                    let key_type = match curve_oid.as_slice() {
                        OID_SECP256R1 => CertKeyType::Secp256r1,
                        OID_SECP384R1 => CertKeyType::Secp384r1,
                        OID_SECP521R1 => CertKeyType::Secp521r1,
                        _ => CertKeyType::Unknown,
                    };
                    Ok((CertKeyWrapper(key_type), rest))
                }
                OID_RSA_KEY | OID_RSA_PSS_KEY => {
                    let (rsa_key, buffer) = rest.decode_value::<RsaPublicKey>()?;
                    let is_pss = key_oid.as_slice() == OID_RSA_PSS_KEY;

                    let key_type = match (is_pss, rsa_key.modulus.len() * 8) {
                        (false, 1024) => CertKeyType::Rsa1024,
                        (false, 2048) => CertKeyType::Rsa2048,
                        (false, 3072) => CertKeyType::Rsa3072,
                        (false, 4096) => CertKeyType::Rsa4096,
                        (true, 2048) => CertKeyType::RsaPss2048,
                        (true, 3072) => CertKeyType::RsaPss3072,
                        (true, 4096) => CertKeyType::RsaPss4096,
                        _ => CertKeyType::Unknown,
                    };
                    Ok((CertKeyWrapper(key_type), buffer))
                }
                _ => Ok((CertKeyWrapper(CertKeyType::Unknown), rest)),
            }
        }
    }

    /// Extract the Common Name (CN) from a Relative Distinguished Name (RDN) Sequence.
    ///
    /// For our purposes, we discard all other fields (e.g. organization, country)
    ///
    /// Returns an empty string if no CN is found.
    fn decode_common_name(content: &[u8]) -> std::io::Result<String> {
        let mut buffer: &[u8] = content;
        while !buffer.is_empty() {
            let (set, rest) = buffer.decode_value::<DerSet>()?;
            let mut set_buf: &[u8] = set.content.as_slice();
            while !set_buf.is_empty() {
                let (attr, set_rest) = set_buf.decode_value::<DerSequence>()?;
                let (oid, val_buf) = attr.content.as_slice().decode_value::<DerOid>()?;
                if oid.content.as_slice() == OID_CN {
                    let (cn, _) = val_buf.decode_value::<DerUtf8ishString>()?;
                    return Ok(cn.content);
                }
                set_buf = set_rest;
            }
            buffer = rest;
        }
        Ok(String::new())
    }

    impl<'a> DecodeValue<'a> for super::ParsedCertContent {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            // Certificate ::= SEQUENCE { tbs, sigAlg, sig }
            let (cert_seq, outer) = buffer.decode_value::<DerSequence>()?;

            // TBSCertificate ::= SEQUENCE { ... }
            let (tbs, _) = cert_seq.content.as_slice().decode_value::<DerSequence>()?;
            let mut buffer: &[u8] = tbs.content.as_slice();

            // [0] EXPLICIT version (optional, tag 0xa0)
            if buffer.first() == Some(&TAG_CONTEXT_0) {
                let (_, b) = buffer.decode_value::<DerContext0>()?;
                buffer = b;
            }

            // serial
            let (serial, buffer) = buffer.decode_value::<DerInteger>()?;

            // signature AlgorithmIdentifier
            let (sig_alg, buffer) = buffer.decode_value::<DerSequence>()?;
            let (sig_oid, _) = decode_oid(sig_alg.content.as_slice())?;

            // issuer
            let (issuer, buffer) = buffer.decode_value::<DerSequence>()?;

            // validity (skip)
            let (_, buffer) = buffer.decode_value::<DerSequence>()?;

            // subject
            let (subject, buffer) = buffer.decode_value::<DerSequence>()?;

            // subjectPublicKeyInfo
            let (spki, _) = buffer.decode_value::<DerSequence>()?;
            let (key_type, _) = spki.content.as_slice().decode_value::<CertKeyWrapper>()?;

            Ok((
                super::ParsedCertContent {
                    serial: serial.content,
                    issuer: decode_common_name(issuer.content.as_slice())?,
                    common_name: decode_common_name(subject.content.as_slice())?,
                    key_type: key_type.0,
                    signature: signature_from_oid(&sig_oid),
                },
                outer,
            ))
        }
    }
}

/// Parse a DER-encoded certificate into its component fields.
pub fn parse(der: &[u8]) -> std::io::Result<ParsedCertContent> {
    use brass_aphid_wire_messages::codec::DecodeByteSource;
    let (parsed, _) = der.decode_value::<ParsedCertContent>()?;
    Ok(parsed)
}
