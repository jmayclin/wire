// Observed behaviors
// s2n-tls: server traffic is available ?
// openssl: server keys available _after_ the read call has finished
//          therefore must not attempt to retrieve keys until you actually go to 
//          read the next type of message
// rustls: seems to be more delayed than either of them.

mod openssl_decrypted_transcript;
mod s2n_decrypted_transcript;
mod s2n_encrypted_transcripts;
mod rustls_decrypted_transcript;
pub mod utilities;
