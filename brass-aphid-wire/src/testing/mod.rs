// Observed behaviors
// s2n-tls: server traffic is available ?
// openssl: server keys available _after_ the read call has finished
//          therefore must not attempt to retrieve keys until you actually go to 
//          read the next type of message
// rustls: seems to be more delayed than either of them.


// basic online decryption tests
mod openssl_decrypted_transcript;
mod s2n_decrypted_transcript;
mod rustls_decrypted_transcript;


// This has a tiny bit of extra TLS 1.2 coverage
mod s2n_encrypted_transcripts;

// TLS edge cases
mod key_update;
mod messages_across_records;
mod hello_retry;

pub mod utilities;
