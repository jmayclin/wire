#![no_main]

use brass_aphid_wire::{codec::DecodeValue, protocol::extensions::PresharedKeyClientHello};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip empty inputs
    if data.is_empty() {
        return;
    }

    let _ = PresharedKeyClientHello::decode_from(data);
});
