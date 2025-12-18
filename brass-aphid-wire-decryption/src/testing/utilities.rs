use std::ops::Deref;

use brass_aphid_wire_messages::protocol::{
    content_value::ContentValue, ContentType, HandshakeType,
};

pub fn s2n_server_config(
    security_policy: &str,
    cert_type: &[SigType],
) -> Result<s2n_tls::config::Builder, Box<dyn std::error::Error>> {
    let policy = s2n_tls::security::Policy::from_version(security_policy)?;

    let mut builder = s2n_tls::config::Config::builder();
    builder.with_system_certs(false)?;
    builder.set_security_policy(&policy)?;
    builder.set_max_blinding_delay(0)?;

    unsafe { builder.disable_x509_verification().unwrap() };

    for ct in cert_type {
        builder.trust_pem(&read_to_bytes(PemType::CACert, *ct))?;
        let cert = read_to_bytes(PemType::ServerCertChain, *ct);
        let key = read_to_bytes(PemType::ServerKey, *ct);
        builder.load_pem(&cert, &key)?;
    }

    Ok(builder)
}

#[derive(Clone, Copy, strum::EnumIter)]
pub enum PemType {
    ServerKey,
    ServerCertChain,
    ClientKey,
    ClientCertChain,
    CACert,
}

impl PemType {
    fn get_filename(&self) -> &str {
        match self {
            PemType::ServerKey => "server-key.pem",
            PemType::ServerCertChain => "server-chain.pem",
            PemType::ClientKey => "client-key.pem",
            PemType::ClientCertChain => "client-cert.pem",
            PemType::CACert => "ca-cert.pem",
        }
    }
}

#[derive(Clone, Copy, Default, strum::EnumIter)]
pub enum SigType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    #[default]
    Ecdsa384,
    Ecdsa256,
    Ecdsa521,
    Rsassa2048,
}

impl SigType {
    pub fn get_dir_name(&self) -> &str {
        match self {
            SigType::Rsa2048 => "rsa2048",
            SigType::Rsa3072 => "rsa3072",
            SigType::Rsa4096 => "rsa4096",
            SigType::Rsassa2048 => "rsapss2048",
            SigType::Ecdsa256 => "ecdsa256",
            SigType::Ecdsa384 => "ecdsa384",
            SigType::Ecdsa521 => "ecdsa521",
        }
    }
}

pub fn get_cert_path(pem_type: PemType, sig_type: SigType) -> String {
    format!(
        "../certs/{}/{}",
        sig_type.get_dir_name(),
        pem_type.get_filename()
    )
}

fn read_to_bytes(pem_type: PemType, sig_type: SigType) -> Vec<u8> {
    std::fs::read_to_string(get_cert_path(pem_type, sig_type))
        .unwrap()
        .into_bytes()
}

/// This is a test utility which makes it easier for us to assert against an expected
/// TLS transcript without having to write a million match statements
pub trait ContentValueTestEquality {
    fn same_as(&self, content_value: ContentValue) -> bool;
}

// they are getting angry about my blanket impl
// impl<T: PartialEq<ContentValue>> ContentValueTestEquality for T {
//     fn same_as(&self, content_value: ContentValue) -> bool {
//         self.eq(&content_value)
//     }
// }


impl ContentValueTestEquality for ContentValue {
    fn same_as(&self, content_value: ContentValue) -> bool {
        *self == content_value
    }
}

impl ContentValueTestEquality for HandshakeType {
    fn same_as(&self, content_value: ContentValue) -> bool {
        match content_value {
            ContentValue::Handshake(handshake_message_value) => {
                handshake_message_value.handshake_type() == *self
            }
            incorrect => {
                tracing::error!("Expected handshake but was {incorrect:?}");
                false
            }
        }
    }
}

impl ContentValueTestEquality for ContentType {
    fn same_as(&self, content_value: ContentValue) -> bool {
        content_value.content_type() == *self
    }
}
