// NOTE: This file is unhygenically used by `build.rs`.
//
// In order to generate all of the constants for each cipher, we need to be able
// to parse the IANA CSV's during build time. We use this file for that by directly
// `concat`ing it into build.rs.
//
// Generally this means that dependencies in the file must be kept to a minimum,
// and if you encounter any odd errors while modifying this file it is likely
// that it is the build.rs instance of it that is actually breaking.
//
// Example 1: This comment can't be a module comment, because that breaks during
// the `concat`.

use std::{
    fmt::{Debug, Display},
    str::FromStr,
    sync::LazyLock,
};

static IANA_SIGNATURE_SCHEMES: LazyLock<Vec<SignatureScheme>> =
    LazyLock::new(SignatureScheme::parse_iana_csv);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureScheme {
    pub value: u16,
    pub description: &'static str,
}

impl SignatureScheme {
    /// From the CSV provided at https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
    /// Downloaded on 2025-03-04
    const IANA_SIGNATURE_SCHEME_CSV: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/iana/tls-signaturescheme.csv"
    ));

    /// Parse the IANA CSV
    fn parse_iana_csv() -> Vec<SignatureScheme> {
        Self::IANA_SIGNATURE_SCHEME_CSV
            .lines()
            .skip(1)
            .filter_map(|line| {
                const VALUE_LENGTH: usize = "0x0804".len();
                // We want to skip lines like the following:
                // 0x0800-0x0803,Reserved for backward compatibility,,[RFC8446]
                if line.as_bytes()[VALUE_LENGTH] != b',' {
                    return None;
                }
                let mut tokens = line.split(",");
                let value = {
                    let value_token = tokens.next().unwrap().strip_prefix("0x").unwrap();
                    u16::from_str_radix(value_token, 16).unwrap()
                };
                let description = tokens.next().unwrap();

                if description.contains("Reserved") {
                    return None;
                }

                Some(SignatureScheme { value, description })
            })
            .collect()
    }

    pub fn from_value(value: u16) -> Option<SignatureScheme> {
        IANA_SIGNATURE_SCHEMES
            .iter()
            .find(|cipher| cipher.value == value)
            .cloned()
    }

    pub fn from_description(description: &str) -> Option<SignatureScheme> {
        IANA_SIGNATURE_SCHEMES
            .iter()
            .find(|cipher| cipher.description == description)
            .cloned()
    }
}

#[derive(
    PartialEq,
    Eq,
    Hash,
    Copy,
    Clone,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
    PartialOrd,
    Ord,
)]
pub struct Cipher {
    pub value: [u8; 2],
    pub description: &'static str,
}

/// This contains all of the ciphers from the IANA CSV, as well as [`NON_STANDARD_CIPHERS`].
static IANA_CIPHERS: LazyLock<Vec<Cipher>> = LazyLock::new(|| {
    let mut ciphers = Cipher::parse_iana_csv();
    for cipher in NON_STANDARD_CIPHERS {
        ciphers.push(*cipher);
    }
    ciphers
});

/// A list of cipher suites which are not on the official IANA CSV.
///
/// These ciphers are mostly pulled from the following list: https://testssl.sh/openssl-iana.mapping.html
///
/// Some are draft ciphers which were never standardized. Others are ciphers that
/// OpenSSL unofficially used code points for without any RFC/Draft.
const NON_STANDARD_CIPHERS: &[Cipher] = &[
    Cipher {
        description: "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
        value: [0, 96],
    },
    Cipher {
        description: "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
        value: [0, 97],
    },
    Cipher {
        description: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        value: [0, 98],
    },
    Cipher {
        description: "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
        value: [0, 99],
    },
    Cipher {
        description: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
        value: [0, 100],
    },
    Cipher {
        description: "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
        value: [0, 101],
    },
    Cipher {
        description: "TLS_DHE_DSS_WITH_RC4_128_SHA",
        value: [0, 102],
    },
    Cipher {
        description: "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
        value: [0, 128],
    },
    Cipher {
        description: "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
        value: [0, 129],
    },
    Cipher {
        description: "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
        value: [0, 130],
    },
    Cipher {
        description: "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
        value: [0, 131],
    },
    Cipher {
        description: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
        value: [204, 19],
    },
    Cipher {
        description: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
        value: [204, 20],
    },
    Cipher {
        description: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
        value: [204, 21],
    },
    Cipher {
        description: "TLS_GOSTR341094_RSA_WITH_28147_CNT_MD5",
        value: [255, 0],
    },
    Cipher {
        description: "TLS_RSA_WITH_28147_CNT_GOST94",
        value: [255, 1],
    },
    Cipher {
        description: "TLS_OSSL_GOST_GOST89MAC",
        value: [255, 2],
    },
    Cipher {
        description: "TLS_OSSL_GOST_GOST89STREAM",
        value: [255, 3],
    },
];

impl Cipher {
    /// From the CSV provided at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
    /// Downloaded on 2025-02-20
    const IANA_CIPHER_CSV: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/iana/tls-parameters-4.csv"
    ));

    pub fn all_ciphers() -> Vec<Cipher> {
        let mut ciphers = IANA_CIPHERS.clone();
        // SCSV ciphers are "signalling cipher suite values". They are not cryptographic
        // parameters. They are used to toggle TLS features and behaviors.
        ciphers.retain(|c| !c.description.ends_with("_SCSV"));
        ciphers
    }

    /// input `byte` should be of the form `0x02`.
    fn parse_hex_byte(byte: &'static str) -> u8 {
        u8::from_str_radix(&byte[2..], 16).unwrap()
    }

    /// Parse the IANA CSV
    fn parse_iana_csv() -> Vec<Cipher> {
        let iana_ciphers: Vec<Cipher> = Self::IANA_CIPHER_CSV
            .lines()
            .skip(1)
            .filter_map(|line| {
                const VALUE_LENGTH: usize = r#""0x00,0x02""#.len();
                const FIRST_COMMA: usize = r#""0x00"#.len();
                // We want to skip lines like the following:
                // "0x00,0x1C-1D",Reserved to avoid conflicts with SSLv3,,,[RFC5246]
                // "0xCD-CF,*",Unassigned,,,
                if line.as_bytes()[VALUE_LENGTH] != b',' || line.as_bytes()[FIRST_COMMA] != b',' {
                    return None;
                }
                let mut value = line[1..(VALUE_LENGTH - 1)].split(",");

                let value = [
                    Self::parse_hex_byte(value.next().unwrap()),
                    Self::parse_hex_byte(value.next().unwrap()),
                ];

                let mut other_tokens = line[VALUE_LENGTH + 1..].split(",");
                let description = other_tokens.next().unwrap();
                if description == "Reserved" || description == "Unassigned" {
                    return None;
                }

                Some(Cipher { value, description })
            })
            .collect();
        iana_ciphers
    }

    pub fn from_value(value: [u8; 2]) -> Option<Cipher> {
        IANA_CIPHERS
            .iter()
            .find(|cipher| cipher.value == value)
            .cloned()
    }

    pub fn from_description(description: &str) -> Option<Cipher> {
        IANA_CIPHERS
            .iter()
            .find(|cipher| cipher.description == description)
            .cloned()
    }

    /// TLS 1.2-ish ciphersuites are spelled as `<auth>_WITH_<cipher>`, but TLS
    /// 1.3 ciphersuites are just the cipher name.
    ///
    /// TLS 1.2-ish ciphersuites
    /// - `TLS_RSA_WITH_AES_256_GCM_SHA384`
    /// - `TLS_ECDSA_WITH_AES_256_GCM_SHA384`
    ///
    /// TLS 1.3 ciphersuite
    /// - `TLS_RSA_WITH_AES_256_GCM_SHA384`
    pub fn supports_tls13(&self) -> bool {
        !self.description.contains("_WITH_")
    }

    /// `true` if the cipher supports uses anonymous key exchange
    ///
    /// For example, `TLS_ECDH_anon_WITH_RC4_128_SHA` supports anonymous key exchange.
    /// TODO: Should NULL ciphers also return "true" here?
    pub fn anonymous_kx(&self) -> bool {
        self.description.contains("_anon_")
    }
}

impl Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Cipher {
    type Err = u8;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cipher::from_description(s).ok_or(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Group {
    pub value: u16,
    pub description: &'static str,
}

// We use this to "cache" the CSV parsing, and allows us to expose the getter methods
// as associated functions rather than methods.
static IANA_GROUPS: LazyLock<Vec<Group>> = LazyLock::new(Group::parse_iana_csv);

impl Group {
    /// From the CSV provided at https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
    /// Downloaded on 2025-03-20
    const IANA_GROUPS_CSV: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/iana/tls-parameters-8.csv"
    ));

    /// Parse the IANA CSV
    fn parse_iana_csv() -> Vec<Group> {
        Self::IANA_GROUPS_CSV
            .lines()
            .skip(1)
            .filter_map(|line| {
                let mut tokens = line.split(",");
                let value = tokens.next().unwrap();
                let description = tokens.next().unwrap();
                if description.contains("Reserved") || description.contains("Unassigned") {
                    return None;
                }
                // "X25519Kyber768Draft00 (OBSOLETE)" <- only take the first token
                let mut description = description.split_ascii_whitespace();
                let description = description.next().unwrap();

                let value: u16 = value.parse().unwrap();
                Some(Group { value, description })
            })
            .collect()
    }

    pub fn from_value(value: u16) -> Option<Group> {
        IANA_GROUPS
            .iter()
            .find(|group| group.value == value)
            .cloned()
    }

    pub fn from_description(description: &str) -> Option<Group> {
        IANA_GROUPS
            .iter()
            .find(|group| group.description == description)
            .cloned()
    }
}

#[cfg(test)]
mod cipher_tests {
    use super::*;

    #[test]
    fn csv_parsing() {
        assert_eq!(IANA_CIPHERS.len(), 370);
    }

    #[test]
    fn cipher_without_iana_value() {
        assert_eq!(Cipher::from_description("CUSTOM_NOT_IANA"), None);
    }

    #[test]
    fn get_round_trip() {
        const DESCRIPTION: &str = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384";
        const VALUE: [u8; 2] = [208, 2];
        const CIPHER: Cipher = Cipher {
            value: VALUE,
            description: DESCRIPTION,
        };

        assert_eq!(Cipher::from_description(DESCRIPTION), Some(CIPHER));
        assert_eq!(
            Cipher::from_description(DESCRIPTION),
            Cipher::from_value(VALUE)
        );
    }
}

#[cfg(test)]
mod signature_scheme_tests {
    use super::*;

    #[test]
    fn csv_parsing() {
        let iana_signature_schemes = SignatureScheme::parse_iana_csv();
        println!("{iana_signature_schemes:#?}");
        assert_eq!(iana_signature_schemes.len(), 34);
    }

    #[test]
    fn get_round_trip() {
        const DESCRIPTION: &str = "ecdsa_secp521r1_sha512";
        const VALUE: u16 = 1539;
        const SIGNATURE: SignatureScheme = SignatureScheme {
            value: VALUE,
            description: DESCRIPTION,
        };

        assert_eq!(
            SignatureScheme::from_description(DESCRIPTION),
            Some(SIGNATURE)
        );
        assert_eq!(SignatureScheme::from_value(VALUE), Some(SIGNATURE));
    }

    #[test]
    fn mldsa() {
        let dsa = SignatureScheme::from_value(2309).unwrap();
    }
}

#[cfg(test)]
mod groups {
    use std::collections::HashSet;

    use super::*;
    use crate::iana;

    #[test]
    fn csv_parsing() {
        let iana_signature_schemes = Group::parse_iana_csv();
        println!("{iana_signature_schemes:#?}");
        assert_eq!(iana_signature_schemes.len(), 56);
    }

    #[test]
    fn get_round_trip() {
        const DESCRIPTION: &str = "MLKEM768";
        const VALUE: u16 = 513;
        const GROUP: Group = Group {
            value: VALUE,
            description: DESCRIPTION,
        };

        assert_eq!(Group::from_description(DESCRIPTION), Some(GROUP));
        assert_eq!(Group::from_value(VALUE), Some(GROUP));
    }

    /// Ensure that all of the cipher names and value are unique.
    ///
    /// This is necessary because we have a hand-curated list of non-standard
    /// ciphers. We want to ensure that none of the entries in that list overlap
    /// with the actual IANA CSV.
    #[test]
    fn cipher_uniqueness() {
        let cipher_count = iana::Cipher::all_ciphers().len();
        let cipher_ids: HashSet<[u8; 2]> = iana::Cipher::all_ciphers()
            .iter()
            .map(|c| c.value)
            .collect();
        let cipher_descriptions: HashSet<&str> = iana::Cipher::all_ciphers()
            .iter()
            .map(|c| c.description)
            .collect();
        assert_eq!(cipher_count, cipher_ids.len());
        assert_eq!(cipher_count, cipher_descriptions.len());
    }
}
