//! This module include the code generates `const` items. Notably this includes
//! ciphers. Generate this items as contants like `iana::TLS_AES_128_GCM_SHA256`
//! makes certain kinds of kind (e.g. unit tests) much easier to read.

include!(concat!(env!("OUT_DIR"), "/iana_constants.rs"));
