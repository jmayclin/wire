#![no_main]

use brass_aphid_wire_messages::{codec::DecodeValue, protocol::messages::ClientHello};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip empty inputs
    if data.is_empty() {
        return;
    }

    let _ = ClientHello::decode_from(data);
});
