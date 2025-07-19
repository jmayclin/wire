use std::{ffi::c_void, sync::{Arc, Mutex}};

use crate::{
    decryption::{key_manager::KeyManager, s2n_tls_intercept::{generic_recv_cb, generic_send_cb}},
    stream_decrypter::{Mode, StreamDecrypter},
};

pub mod s2n_tls_intercept;
pub mod transcript;
pub mod key_manager;

// basic test -> 1 message, 1 record,
// harder test -> 2 messages, 1 record,
// hardest test -> 1 message, 2 records,

// how funky can the message framing get?
// would this be allowed? I certainly hope not.
// but it seems like a simple thing that would make maintainers lives easier, so
// it probably is allowed
// |         record          |        record     |
// |  message   |    message        |  message   |

/// This makes it easy to decrypt the traffic from a TLS implementation which operates
/// over some generic type implementing Read + Write. E.g. `openssl::SslStream`
pub struct DecryptingPipe<T> {
    pub pipe: T,
    // currently the mutex is a really ugly way for us to maintain access to this. 
    // need something better.
    pub decrypter: Arc<Mutex<StreamDecrypter>>,
    pub identity: Option<Mode>,
}

impl<T: std::io::Read + std::io::Write> DecryptingPipe<T> {
    pub fn new(key_manager: KeyManager, pipe: T) -> Self {
        Self {
            pipe,
            decrypter: Arc::new(Mutex::new(StreamDecrypter::new(key_manager))),
            identity: None,
        }
    }

    /// Used to decrypt s2n-tls connections
    ///
    /// First the underlying "real" connection IO stuff needs to be retrieved and
    /// packaged into an `ArchaicCPipe`. At that point this can be used to set the
    /// appropriate callbacks on s2n-tls.
    pub fn enable_s2n_tls_decryption(
        decrypter: &Box<Self>,
        connection: &mut s2n_tls::connection::Connection,
    ) {
        connection
            .set_send_callback(Some(generic_send_cb::<Self>))
            .unwrap();
        connection
            .set_receive_callback(Some(generic_recv_cb::<Self>))
            .unwrap();
        unsafe {
            connection
                .set_send_context(decrypter.as_ref() as *const Self as *mut c_void)
                .unwrap();
            connection
                .set_receive_context(decrypter.as_ref() as *const Self as *mut c_void)
                .unwrap();
        }
    }
}

// designed to work with an IO callback based pattern, such as that used by s2n-tls
// and OpenSSL
impl<T: std::io::Read> std::io::Read for DecryptingPipe<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.identity.is_none() {
            // reading first is server behavior
            self.identity = Some(Mode::Server);
        }

        let read = self.pipe.read(buf)?;

        let peer = self.identity.unwrap().peer();

        self.decrypter.lock().unwrap().record_tx(&buf[..read], peer);
        self.decrypter.lock().unwrap().assemble_records(peer);
        self.decrypter.lock().unwrap().decrypt_records(peer).unwrap();

        Ok(read)
    }
}

impl<T: std::io::Write> std::io::Write for DecryptingPipe<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.identity.is_none() {
            // writing first is client behavior
            self.identity = Some(Mode::Client);
        }

        let written = self.pipe.write(buf)?;

        let identity = self.identity.unwrap();

        self.decrypter.lock().unwrap().record_tx(&buf[..written], identity);
        self.decrypter.lock().unwrap().assemble_records(self.identity.unwrap());
        self.decrypter.lock().unwrap().decrypt_records(self.identity.unwrap()).unwrap();

        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        /* no op */
        Ok(())
    }
}
