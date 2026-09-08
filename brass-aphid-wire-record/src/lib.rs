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

use brass_aphid_wire_messages::{
    codec::{DecodeByteSource, DecodeValue}, iana::{self, Cipher, Protocol}, prefixed_list::PrefixedBlob, protocol::{ContentType, RecordHeader},
};
use brass_aphid_wire_messages::codec::EncodeValue;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::{GenericHkdf, HmacImpl};
use hmac::{EagerHash, SimpleHmac};
use sha2::{Sha256, Sha384};

struct Record<'a> {
    header: RecordHeader,
    payload: &'a mut [u8],
}

enum Payload<'a> {
    Application(&'a mut [u8]),
    Handshake(&'a mut [u8]),
    Alert(&'a mut [u8]),
    CCS(&'a mut [u8]),
}

struct Tls13RecordState {}

enum ProtocolVersion {
    /// The record contents are not encrypted
    /// Used for the initial message of TLS 1.3 handshakes, or the entire legacy TLS
    /// handshake sequence
    Plaintext,
    Tls13(),
    Tls12(),
}

struct RecordProcotol {}

impl RecordProcotol {
    /// content type is the "real" content type, not the content type of the outer
    /// record header
    fn encapsulate_record(&self, content_type: ContentType, payload: &[u8], record_out: &mut [u8]) {
        // match
    }

    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut [u8]) -> Payload<'b> {
        Payload::CCS(record)
    }
}

trait RecordProtocol {
    /// encapsulate in place
    fn encap<'a, 'b>(&'a self, content_type: ContentType, payload: &'b mut [u8]) -> Record<'b>;

    /// decapsulate in place
    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut [u8]) -> Payload<'b>;
}

struct Plaintext {
    /// should not be TLS 1.3
    pub record_header_version: Protocol,
}

// simplest path
// 1. network -> application buffer

// network -> tls record buffer -> decrypt into application buffer

impl RecordProtocol for Plaintext {
    fn encap<'a, 'b>(&'a self, content_type: ContentType, payload: &'b mut [u8]) -> Record<'b> {
        let header = RecordHeader {
            content_type,
            protocol_version: self.record_header_version,
            record_length: payload.len() as u16,
        };
        Record { header, payload }
    }

    // If you can work inside a single record or incrementally, prefer 
    // what's the performance difference between AES-GCM decrypting in place vs
    // decrypting to another thing? I think that _if_ you are going to make the 
    // copy, then folks would prefer to have an explicit out buffer? And that decrpt_in_place
    // is only useful for minimizing memory usage? Although if they're willing to
    // do multiple reads, then this is probably maximally efficient, because we
    // can decrypt in place and let the application _stack_ data into a single
    // big buffer

    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut [u8]) -> Payload<'b> {
        let (record_header, remaining) = RecordHeader::decode_from(record).unwrap();
        let (payload, remaining) = remaining.pull(record_header.record_length.into()).unwrap();
        // todo: zip function
        match record_header.content_type {
            ContentType::ChangeCipherSpec => Payload::CCS(payload),
            ContentType::Alert => Payload::Alert(payload),
            ContentType::Handshake => Payload::Handshake(payload),
            ContentType::ApplicationData => Payload::Application(payload),
        }
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
