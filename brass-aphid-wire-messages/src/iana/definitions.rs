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

static IANA_SIGNATURE_SCHEMES: LazyLock<Vec<(u16, &'static str)>> =
    LazyLock::new(SignatureScheme::parse_iana_csv);

#[derive(PartialEq, Eq, Hash, Copy, Clone, PartialOrd, Ord)]
pub struct SignatureScheme {
    pub value: u16,
}

impl Debug for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.description() {
            Some(desc) => write!(f, "{desc}"),
            None => write!(f, "SignatureScheme(0x{:04X})", self.value),
        }
    }
}

impl SignatureScheme {
    /// From the CSV provided at https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
    /// Downloaded on 2025-03-04
    const IANA_SIGNATURE_SCHEME_CSV: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/iana/tls-signaturescheme.csv"
    ));

    pub fn description(&self) -> Option<&'static str> {
        IANA_SIGNATURE_SCHEMES
            .iter()
            .find(|(v, _)| *v == self.value)
            .map(|(_, d)| *d)
    }

    /// Parse the IANA CSV
    fn parse_iana_csv() -> Vec<(u16, &'static str)> {
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

                Some((value, description))
            })
            .collect()
    }

    pub fn from_value(value: u16) -> Option<SignatureScheme> {
        if IANA_SIGNATURE_SCHEMES.iter().any(|(v, _)| *v == value) {
            Some(SignatureScheme { value })
        } else {
            None
        }
    }

    pub fn from_description(description: &str) -> Option<SignatureScheme> {
        IANA_SIGNATURE_SCHEMES
            .iter()
            .find(|(_, d)| *d == description)
            .map(|(v, _)| SignatureScheme { value: *v })
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
}

/// This contains all of the ciphers from the IANA CSV, as well as [`NON_STANDARD_CIPHERS`].
static IANA_CIPHERS: LazyLock<Vec<([u8; 2], &'static str)>> = LazyLock::new(|| {
    let mut ciphers = Cipher::parse_iana_csv();
    ciphers
});

impl Cipher {
    /// From the CSV provided at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
    /// Downloaded on 2025-02-20
    const IANA_CIPHER_CSV: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/iana/tls-parameters-4.csv"
    ));

    pub fn description(&self) -> Option<&'static str> {
        IANA_CIPHERS
            .iter()
            .find(|(v, _)| *v == self.value)
            .map(|(_, d)| *d)
    }

    pub fn all_ciphers() -> Vec<Cipher> {
        let mut ciphers: Vec<Cipher> = IANA_CIPHERS
            .iter()
            .map(|(v, _)| Cipher { value: *v })
            .collect();
        // SCSV ciphers are "signalling cipher suite values". They are not cryptographic
        // parameters. They are used to toggle TLS features and behaviors.
        ciphers.retain(|c| {
            c.description()
                .map(|d| !d.ends_with("_SCSV"))
                .unwrap_or(true)
        });
        ciphers
    }

    /// input `byte` should be of the form `0x02`.
    fn parse_hex_byte(byte: &'static str) -> u8 {
        u8::from_str_radix(&byte[2..], 16).unwrap()
    }

    /// Parse the IANA CSV
    fn parse_iana_csv() -> Vec<([u8; 2], &'static str)> {
        Self::IANA_CIPHER_CSV
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

                Some((value, description))
            })
            .collect()
    }

    pub fn from_value(value: [u8; 2]) -> Option<Cipher> {
        if IANA_CIPHERS.iter().any(|(v, _)| *v == value) {
            Some(Cipher { value })
        } else {
            None
        }
    }

    pub fn from_description(description: &str) -> Option<Cipher> {
        IANA_CIPHERS
            .iter()
            .find(|(_, d)| *d == description)
            .map(|(v, _)| Cipher { value: *v })
    }

    /// TLS 1.2-ish ciphersuites are spelled as `<auth>_WITH_<cipher>`, but TLS
    /// 1.3 ciphersuites are just the cipher name.
    pub fn supports_tls13(&self) -> bool {
        self.description()
            .map(|d| !d.contains("_WITH_"))
            .unwrap_or(false)
    }

    /// `true` if the cipher supports uses anonymous key exchange
    pub fn anonymous_kx(&self) -> bool {
        self.description()
            .map(|d| d.contains("_anon_"))
            .unwrap_or(false)
    }
}

impl Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.description() {
            Some(desc) => write!(f, "{desc}"),
            None => write!(f, "Cipher(0x{:02X},0x{:02X})", self.value[0], self.value[1]),
        }
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

#[derive(PartialEq, Eq, Hash, Copy, Clone, PartialOrd, Ord)]
pub struct Group {
    pub value: u16,
}

impl Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.description() {
            Some(desc) => write!(f, "{desc}"),
            None => write!(f, "Group(0x{:04X})", self.value),
        }
    }
}

// We use this to "cache" the CSV parsing, and allows us to expose the getter methods
// as associated functions rather than methods.
static IANA_GROUPS: LazyLock<Vec<(u16, &'static str)>> = LazyLock::new(Group::parse_iana_csv);

impl Group {
    /// From the CSV provided at https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
    /// Downloaded on 2025-03-20
    const IANA_GROUPS_CSV: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/iana/tls-parameters-8.csv"
    ));

    pub fn description(&self) -> Option<&'static str> {
        IANA_GROUPS
            .iter()
            .find(|(v, _)| *v == self.value)
            .map(|(_, d)| *d)
    }

    /// Parse the IANA CSV
    fn parse_iana_csv() -> Vec<(u16, &'static str)> {
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
                Some((value, description))
            })
            .collect()
    }

    pub fn from_value(value: u16) -> Option<Group> {
        if IANA_GROUPS.iter().any(|(v, _)| *v == value) {
            Some(Group { value })
        } else {
            None
        }
    }

    pub fn from_description(description: &str) -> Option<Group> {
        IANA_GROUPS
            .iter()
            .find(|(_, d)| *d == description)
            .map(|(v, _)| Group { value: *v })
    }
}

#[cfg(test)]
mod cipher_tests {
    use super::*;

    #[test]
    fn csv_parsing() {
        assert_eq!(IANA_CIPHERS.len(), 356);
    }

    #[test]
    fn cipher_without_iana_value() {
        assert_eq!(Cipher::from_description("CUSTOM_NOT_IANA"), None);
    }

    #[test]
    fn get_round_trip() {
        const DESCRIPTION: &str = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384";
        const VALUE: [u8; 2] = [208, 2];

        let cipher = Cipher::from_description(DESCRIPTION).unwrap();
        assert_eq!(cipher.value, VALUE);
        assert_eq!(cipher, Cipher::from_value(VALUE).unwrap());
    }

    #[test]
    fn unknown_cipher() {
        let cipher = Cipher { value: [0xFF, 0xFE] };
        assert_eq!(cipher.description(), None);
        assert_eq!(cipher.supports_tls13(), false);
        assert_eq!(cipher.anonymous_kx(), false);
    }
}

#[cfg(test)]
mod signature_scheme_tests {
    use super::*;

    #[test]
    fn csv_parsing() {
        let iana_signature_schemes = SignatureScheme::parse_iana_csv();
        assert_eq!(iana_signature_schemes.len(), 37);
    }

    #[test]
    fn get_round_trip() {
        const DESCRIPTION: &str = "ecdsa_secp521r1_sha512";
        const VALUE: u16 = 1539;

        let sig = SignatureScheme::from_description(DESCRIPTION).unwrap();
        assert_eq!(sig.value, VALUE);
        assert_eq!(sig, SignatureScheme::from_value(VALUE).unwrap());
    }

    #[test]
    fn mldsa() {
        let dsa = SignatureScheme::from_value(2309).unwrap();
        assert_eq!(dsa.description(), Some("mldsa65"));
    }

    #[test]
    fn unknown_signature_scheme() {
        let sig = SignatureScheme { value: 0xFFFF };
        assert_eq!(sig.description(), None);
    }
}

#[cfg(test)]
mod groups {
    use std::collections::HashSet;

    use super::*;
    use crate::iana;

    #[test]
    fn csv_parsing() {
        let iana_groups = Group::parse_iana_csv();
        assert_eq!(iana_groups.len(), 57);
    }

    #[test]
    fn get_round_trip() {
        const DESCRIPTION: &str = "MLKEM768";
        const VALUE: u16 = 513;

        let group = Group::from_description(DESCRIPTION).unwrap();
        assert_eq!(group.value, VALUE);
        assert_eq!(group, Group::from_value(VALUE).unwrap());
    }

    #[test]
    fn unknown_group() {
        let group = Group { value: 0xFFFF };
        assert_eq!(group.description(), None);
    }

    /// Ensure that all of the cipher names and value are unique.
    #[test]
    fn cipher_uniqueness() {
        let cipher_count = iana::Cipher::all_ciphers().len();
        let cipher_ids: HashSet<[u8; 2]> = iana::Cipher::all_ciphers()
            .iter()
            .map(|c| c.value)
            .collect();
        let cipher_descriptions: HashSet<&str> = iana::Cipher::all_ciphers()
            .iter()
            .filter_map(|c| c.description())
            .collect();
        assert_eq!(cipher_count, cipher_ids.len());
        assert_eq!(cipher_count, cipher_descriptions.len());
    }
}
