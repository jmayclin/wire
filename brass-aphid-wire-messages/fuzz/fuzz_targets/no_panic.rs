#![no_main]

use brass_aphid_wire_messages::{
    codec::DecodeValue,
    protocol::messages::{ClientHello, HandshakeMessageHeader, RecordHeader},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let _ = RecordHeader::decode_from(data);
    let _ = HandshakeMessageHeader::decode_from(data);
    let _ = ClientHello::decode_from(data);
});
