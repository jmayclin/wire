//! Handshake message framing.
//!
//! On the wire every handshake message is `type (u8) || length (u24) || body`.
//! There is deliberately no enum of all of the messages. A message is read as a
//! generic [`HandshakeMessage`], and the caller, who always knows which message
//! it expects, casts it to a concrete type with [`HandshakeMessage::parse`]. That
//! also means that the context a message needs (a cipher, a protocol version) is
//! supplied at the call site, rather than threaded through one big decode
//! function.
//!
//! Writing is the mirror image: [`HandshakeWriter::of`] frames a body.

use crate::{
    codec::{take, DecodeValue, DecodeValueWithContext, EncodeValue, U24},
    prefixed_list::PrefixedBlobWriter,
    protocol::{ClientHello, EncryptedExtensions, Finished, HandshakeType, ServerHello},
    writer::Writer,
};

/// A message body that knows which [`HandshakeType`] it is sent under.
pub trait HandshakeData {
    const TYPE: HandshakeType;
}

impl HandshakeData for ClientHello<'_> {
    const TYPE: HandshakeType = HandshakeType::ClientHello;
}
impl HandshakeData for ServerHello<'_> {
    const TYPE: HandshakeType = HandshakeType::ServerHello;
}
impl HandshakeData for EncryptedExtensions<'_> {
    const TYPE: HandshakeType = HandshakeType::EncryptedExtensions;
}
impl HandshakeData for Finished<'_> {
    const TYPE: HandshakeType = HandshakeType::Finished;
}

/// A handshake message with its framing parsed and its body left alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    pub handshake_type: HandshakeType,
    /// the message body, without the 4 byte header
    pub body: &'a [u8],
    /// the whole message, header included, exactly as it was on the wire. This is
    /// what goes into the transcript hash.
    pub raw: &'a [u8],
}

impl<'a> DecodeValue<'a> for HandshakeMessage<'a> {
    fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
        let (handshake_type, rest) = HandshakeType::decode_from(buffer)?;
        let (length, rest) = U24::decode_from(rest)?;
        let (body, remaining) = take(rest, length.into())?;
        let consumed = buffer.len() - remaining.len();
        let message = Self {
            handshake_type,
            body,
            raw: &buffer[..consumed],
        };
        Ok((message, remaining))
    }
}

impl<'a> HandshakeMessage<'a> {
    fn check_type<M: HandshakeData>(&self) -> std::io::Result<()> {
        if self.handshake_type == M::TYPE {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "expected {:?}, but found {:?}",
                    M::TYPE,
                    self.handshake_type
                ),
            ))
        }
    }

    /// Cast to a specific message. Fails if this is a different kind of message,
    /// or if the body doesn't decode as `M`.
    pub fn parse<M: HandshakeData + DecodeValue<'a>>(&self) -> std::io::Result<M> {
        self.check_type::<M>()?;
        M::decode_from_exact(self.body)
    }

    /// [`HandshakeMessage::parse`] for messages that need context to decode.
    pub fn parse_with_context<M: HandshakeData + DecodeValueWithContext<'a>>(
        &self,
        context: M::Context,
    ) -> std::io::Result<M> {
        self.check_type::<M>()?;
        M::decode_from_with_context_exact(self.body, context)
    }
}

/// The write side of [`HandshakeMessage`]: frames `body` with a type and a u24
/// length.
///
/// ```ignore
/// HandshakeWriter::of::<ClientHello>(&client_hello_writer).encode_to_vec()
/// ```
pub struct HandshakeWriter<'w, B> {
    handshake_type: HandshakeType,
    body: &'w B,
}

impl<'w, B> HandshakeWriter<'w, B> {
    /// `M` selects the handshake type, and the body must be able to write itself
    /// as an `M`.
    pub fn of<M: HandshakeData>(body: &'w B) -> Self
    where
        B: Writer<M> + EncodeValue,
    {
        Self {
            handshake_type: M::TYPE,
            body,
        }
    }
}

impl<B: EncodeValue> EncodeValue for HandshakeWriter<'_, B> {
    fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
        self.handshake_type.encode_to(buffer)?;
        PrefixedBlobWriter::<U24, B>::new(self.body).encode_to(buffer)
    }
}
