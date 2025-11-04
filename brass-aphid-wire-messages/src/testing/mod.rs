// Observed behaviors
// s2n-tls: server traffic is available ?
// openssl: server keys available _after_ the read call has finished
//          therefore must not attempt to retrieve keys until you actually go to
//          read the next type of message
// rustls: seems to be more delayed than either of them.

// This has a tiny bit of extra TLS 1.2 coverage
mod other_client_hellos;
mod s2n_encrypted_transcripts;

mod s2n_tls_intercept;
mod transcript;
pub mod utilities;
