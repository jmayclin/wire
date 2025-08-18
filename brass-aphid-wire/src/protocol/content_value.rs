use std::io::ErrorKind;

use crate::{
    codec::{DecodeByteSource, DecodeValue, DecodeValueWithContext},
    iana::{self, Protocol},
    protocol::{
        Alert, CertVerifyTls13, CertificateRequest, CertificateTls12ish, CertificateTls13,
        ChangeCipherSpec, ClientHello, ContentType, EncryptedExtensions, Finished,
        HandshakeMessageHeader, HandshakeType, KeyUpdate, NewSessionTicketTls13, ServerHello,
        ServerKeyExchange,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentValue {
    Alert(Alert),
    ApplicationData(Vec<u8>),
    Handshake(HandshakeMessageValue),
    ChangeCipherSpec(ChangeCipherSpec),
}

impl ContentValue {
    pub fn content_type(&self) -> ContentType {
        match self {
            ContentValue::Alert(_) => ContentType::Alert,
            ContentValue::ApplicationData(_) => ContentType::ApplicationData,
            ContentValue::Handshake(_) => ContentType::Handshake,
            ContentValue::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
        }
    }

    #[cfg(test)]
    pub fn as_handshake(&self) -> &HandshakeMessageValue {
        if let ContentValue::Handshake(hm) = self {
            hm
        } else {
            panic!("content type was {:?}, not handshake", self.content_type());
        }
    }
}

// TODO: I am inconsistent about when I specify "Tls13" and when it's just the plain
// name. It should only be used on messages where the struct is actually different
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessageValue {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EncryptedExtensions(EncryptedExtensions),
    CertificateTls13(CertificateTls13),
    CertificateTls12ish(CertificateTls12ish),
    ServerKeyExchange(ServerKeyExchange),
    CertVerifyTls13(CertVerifyTls13),
    CertificateRequestTls13(CertificateRequest),
    NewSessionTicketTls13(NewSessionTicketTls13),
    KeyUpdate(KeyUpdate),
    Finished(Finished),
}

impl HandshakeMessageValue {
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            HandshakeMessageValue::ClientHello(_) => HandshakeType::ClientHello,
            HandshakeMessageValue::ServerHello(_) => HandshakeType::ServerHello,
            HandshakeMessageValue::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            HandshakeMessageValue::CertificateTls13(_) => HandshakeType::Certificate,
            HandshakeMessageValue::CertificateTls12ish(_) => HandshakeType::Certificate,
            HandshakeMessageValue::ServerKeyExchange(_) => HandshakeType::ServerKeyExchange,
            HandshakeMessageValue::CertVerifyTls13(_) => HandshakeType::CertificateVerify,
            HandshakeMessageValue::CertificateRequestTls13(_) => HandshakeType::CertificateRequest,
            HandshakeMessageValue::NewSessionTicketTls13(_) => HandshakeType::NewSessionTicket,
            HandshakeMessageValue::KeyUpdate(_) => HandshakeType::KeyUpdate,
            HandshakeMessageValue::Finished(_) => HandshakeType::Finished,
        }
    }

    // None when the plain "decode" implementation is used
    // Some when the decode_with_context impl is used
    fn base_decode(
        buffer: &[u8],
        protocol: Option<Protocol>,
        cipher: Option<iana::Cipher>,
    ) -> std::io::Result<(Self, &[u8])> {
        let (message_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
        tracing::trace!("handshake message header: {message_header:?}");
        let (value, buffer) = match message_header.handshake_type {
            HandshakeType::HelloRequest => {
                todo!("{:?} not implemented", message_header.handshake_type);
            }
            HandshakeType::ClientHello => {
                let (message, buffer) = buffer.decode_value()?;
                (HandshakeMessageValue::ClientHello(message), buffer)
            }
            HandshakeType::ServerHello => {
                let (message, buffer) = buffer.decode_value()?;
                (HandshakeMessageValue::ServerHello(message), buffer)
            }
            HandshakeType::NewSessionTicket => {
                let context = needs_protocol(message_header.handshake_type, protocol)?;
                if context == Protocol::TLSv1_3 {
                    let (message, buffer) = buffer.decode_value()?;
                    (
                        HandshakeMessageValue::NewSessionTicketTls13(message),
                        buffer,
                    )
                } else {
                    todo!();
                }
            }
            HandshakeType::EndOfEarlyData => todo!(),
            HandshakeType::EncryptedExtensions => {
                let (message, buffer) = buffer.decode_value()?;
                (HandshakeMessageValue::EncryptedExtensions(message), buffer)
            }
            HandshakeType::Certificate => {
                let context = needs_protocol(message_header.handshake_type, protocol)?;
                if context == Protocol::TLSv1_3 {
                    let (message, buffer) = buffer.decode_value()?;
                    (HandshakeMessageValue::CertificateTls13(message), buffer)
                } else {
                    let (message, buffer) = buffer.decode_value()?;
                    (HandshakeMessageValue::CertificateTls12ish(message), buffer)
                }
            }
            HandshakeType::ServerKeyExchange => {
                let cipher = needs_cipher(message_header.handshake_type, cipher)?;
                let (message, buffer) =
                    ServerKeyExchange::decode_from_with_context(buffer, cipher)?;
                (HandshakeMessageValue::ServerKeyExchange(message), buffer)
            }
            HandshakeType::CertificateRequest => {
                let (message, buffer) = buffer.decode_value()?;
                (
                    HandshakeMessageValue::CertificateRequestTls13(message),
                    buffer,
                )
            }
            HandshakeType::ServerHelloDone => todo!(),
            HandshakeType::CertificateVerify => {
                let (message, buffer) = buffer.decode_value()?;
                (HandshakeMessageValue::CertVerifyTls13(message), buffer)
            }
            HandshakeType::ClientKeyExchange => todo!(),
            HandshakeType::Finished => {
                let cipher = needs_cipher(message_header.handshake_type, cipher)?;
                let (message, buffer) = Finished::decode_from_with_context(buffer, cipher)?;
                (HandshakeMessageValue::Finished(message), buffer)
            }
            HandshakeType::KeyUpdate => {
                let (message, buffer) = buffer.decode_value()?;
                (HandshakeMessageValue::KeyUpdate(message), buffer)
            }
            HandshakeType::MessageHash => todo!(),
        };

        Ok((value, buffer))
    }
}

fn needs_protocol(
    handshake_type: HandshakeType,
    protocol_context: Option<Protocol>,
) -> std::io::Result<Protocol> {
    if let Some(protocol) = protocol_context {
        Ok(protocol)
    } else {
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            format!("decoding {handshake_type:?} requires a protocol to be selected"),
        ))
    }
}

fn needs_cipher(
    handshake_type: HandshakeType,
    cipher_context: Option<iana::Cipher>,
) -> std::io::Result<iana::Cipher> {
    if let Some(cipher) = cipher_context {
        Ok(cipher)
    } else {
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            format!("decoding {handshake_type:?} requires a cipher to be selected"),
        ))
    }
}

impl DecodeValue for HandshakeMessageValue {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        Self::base_decode(buffer, None, None)
    }
}

impl DecodeValueWithContext for HandshakeMessageValue {
    type Context = (Protocol, iana::Cipher);

    fn decode_from_with_context(
        buffer: &[u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &[u8])> {
        let (protocol, cipher) = context;
        Self::base_decode(buffer, Some(protocol), Some(cipher))
    }
}
