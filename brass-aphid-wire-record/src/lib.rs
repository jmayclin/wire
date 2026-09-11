//! IO setups
//!
//! ## Single Application Buffer - Decrypt In Place
//!
//! ```text
//! kernel ---read---> |==========|
//!                       ^
//!                       1. TLS decrypts in place
//!                       2. Application parses here
//! ```
//!
//! This is generally the simplest setup.
//! Benefits
//! - low memory: only single buffer
//! Disadvantages
//! - requires parsing to operate in ~ 16 kB chunks. And technically a peer could
//!   fragment into smaller chunks, so generally this requires e.g. incremental
//!   parsing.
//!
//! As long as your support incremental parsing, you can scale this up to read
//! multiple records at a time from the kernel. But note that the resulting decrypted
//! records are _not_ contiguous, because each TLS record header is "dead space"
//! in between records
//!
//! ## Multiple Application Buffers - Decrypt to Destination
//! ```text
//! kernel ---read---> |==========|  ----decrypt---> |---------|
//!                        ^                            ^
//!                     ciphertext                    plaintext            
//! ```
//!
//! Note that the intermediate ciphertext buffer is _not_ decrypted in place.
//! Remember that decrypting is a pseudo copy. We use that to decryption to pseudo-copy
//! to the applications plaintext buffer.
//!
//! Benefits
//! - allows application to build arbitrarily large contiguous plaintext chunks
//! Cons
//! - doesn't support partial application reads ("let me read 5 bytes from the peer" - not allowed)
//! - two buffers instead of one
//!
//!
//!
//!
//!
//! ##

mod tls13;

use std::io::{Cursor, Write};

pub use tls13::Tls13;

use brass_aphid_wire_messages::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink},
    iana::{self, Protocol},
    protocol::{ContentType, RecordHeader},
};

pub struct Record<T> {
    pub header: RecordHeader,
    pub payload: T,
}

/// we unfortunately implement DecodeValue here, because the generic is in the
/// wrong place
impl<T: DecodeByteSource> Record<T> {
    fn decode_from(buffer: T) -> std::io::Result<(Self, T)> {
        let (header, remaining) = buffer.decode_value::<RecordHeader>()?;
        let (payload, remaining) = remaining.pull(header.record_length.into())?;
        let value = Self { header, payload };
        Ok((value, remaining))
    }
}

#[derive(Debug)]
pub enum Payload<'a> {
    Application(&'a [u8]),
    Handshake(&'a [u8]),
    Alert(&'a [u8]),
    CCS(&'a [u8]),
}

impl Payload<'_> {
    pub fn assert_application(&mut self) -> &[u8] {
        if let Payload::Application(data) = self {
            return *data;
        }
        panic!("expected Application, but was {self:?}");
    }

    pub fn assert_handshake(&mut self) -> &[u8] {
        if let Payload::Handshake(data) = self {
            return *data;
        }
        panic!("expected Handshake, but was {self:?}");
    }

    pub fn assert_ccs(&mut self) -> &[u8] {
        if let Payload::CCS(data) = self {
            return *data;
        }
        panic!("expected Change Cipher Spec, but was {self:?}");
    }
}

/// The top level record protocol is responsible for record framing and dispatch
/// 
/// It is _not_ aware of when the underlying state should be switched. That must
/// be managed by a higher level construct. Generally you need a higher level 
/// Connection struct which intercepts non-application data and handle it appropriately
pub struct RecordProtocol<T> {
    pub state: T,
}

impl RecordProtocol<Plaintext> {
    pub fn select_tls13(self, cipher: iana::Cipher, secret: &[u8]) -> RecordProtocol<Tls13> {
        RecordProtocol {
            state: Tls13::new(cipher, secret),
        }
    }
}

impl<T: RecordProtocolBehavior> RecordProtocol<T> {
    /// content type is the "real" content type, not the content type of the outer
    /// record header
    ///
    /// encapsulate bytes is necessary for framing, the underlying RecordBehavior
    /// layers are not responsible for enforcing record sizes
    pub fn encapsulate_bytes(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        ciphertext_out: &mut Cursor<&mut [u8]>,
    ) {
        self.state
            .encap_record(content_type, payload, ciphertext_out)
            .unwrap();
    }

    pub fn decapsulate_bytes<'a, 'b: 'a, 'c>(
        &'a mut self,
        record: &'b [u8],
        plaintext: &'a mut Cursor<&'c mut [u8]>,
    ) -> std::io::Result<(Payload<'a>, &'b [u8])> {
        // TODO: SSLv2 stuff would be handled here? But I don't have to tolerate
        // silly gooses in my personal projects

        let (record, remaining) = Record::decode_from(record)?;
        let start = plaintext.position() as usize;
        let payload = self.state.decap_record(record, plaintext);
        let finish = plaintext.position() as usize;
        let written = &plaintext.get_ref()[start..finish];
        let payload = match payload {
            ContentType::ChangeCipherSpec => Payload::CCS(written),
            ContentType::Alert => Payload::Alert(written),
            ContentType::Handshake => Payload::Handshake(written),
            ContentType::ApplicationData => Payload::Application(written),
        };

        Ok((payload, remaining))
    }
}

pub trait RecordProtocolBehavior {
    /// encapsulate in place
    fn encap_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        ciphertext_out: &mut Cursor<&mut [u8]>,
    ) -> Result<(), RecordError>;

    /// decapsulate in place
    fn decap_record(
        &mut self,
        record: Record<&[u8]>,
        plaintext_out: &mut Cursor<&mut [u8]>,
    ) -> ContentType;
}

/// Plaintext records are always used for the Client Hello and Server Hello in
/// all protocol versions. Additionally, legacy TLS (TLS 1.0 -> TLS 1.2) use plaintex
/// records for all of the handshake phase.
/// 
/// ### Record Structure
/// ```text
/// 5 byte record header    plaintext payload
///     v                       v 
/// |hhhhh|------------------------------------|
/// ```
pub struct Plaintext {
    /// should not be TLS 1.3
    pub record_header_version: Protocol,
}

impl Plaintext {
    pub fn new() -> Self {
        Self {
            record_header_version: Protocol::TLSv1_2,
        }
    }
}

#[derive(Debug)]
pub enum RecordError {
    InvalidHeader,
    InsufficientSpace,
}

// simplest path
// 1. network -> application buffer

// network -> tls record buffer -> decrypt into application buffer

impl RecordProtocolBehavior for Plaintext {
    fn encap_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        output: &mut Cursor<&mut [u8]>,
    ) -> Result<(), RecordError> {
        let header = RecordHeader {
            content_type,
            protocol_version: self.record_header_version,
            record_length: payload.len() as u16,
        };
        output.encode_value(&header).unwrap();
        output.write_all(&payload).unwrap();

        Ok(())
    }

    // what's the performance difference between AES-GCM decrypting in place vs
    // decrypting to another thing? I think that _if_ you are going to make the
    // copy, then folks would prefer to have an explicit out buffer? And that decrpt_in_place
    // is only useful for minimizing memory usage? Although if they're willing to
    // do multiple reads, then this is probably maximally efficient, because we
    // can decrypt in place and let the application _stack_ data into a single
    // big buffer

    fn decap_record(
        &mut self,
        record: Record<&[u8]>,
        plaintext_out: &mut Cursor<&mut [u8]>,
    ) -> ContentType {
        plaintext_out.write_all(record.payload).unwrap();
        record.header.content_type
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
