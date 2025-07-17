use crate::decryption::s2n_tls_intercept::{self, intercept_send_callback};
use s2n_tls::{enums::Mode, testing::TestPair};
use std::{cell::RefCell, ffi::c_void, io::Write, pin::Pin, sync::Arc};

use crate::decryption::s2n_tls_intercept::InterceptedSendCallback;
pub trait TestPairExtension {
    /// Record all bytes sent by the connections.
    ///
    /// This does not decrypt the bytes
    fn enable_transcript(&mut self) -> TestPairTranscript;
}

impl TestPairExtension for TestPair {
    fn enable_transcript(&mut self) -> TestPairTranscript {
        TestPairTranscript::new(self)
    }
}

/// Holds all of the writes that occurred during a TLS handshake
pub struct TestPairTranscript {
    records: Pin<Arc<RefCell<Vec<(Mode, Vec<u8>)>>>>,
    client_handle: Box<RecordingSendHandle>,
    server_handle: Box<RecordingSendHandle>,
}

impl TestPairTranscript {
    /// Create a new empty transcript
    fn new(pair: &mut TestPair) -> Self {
        let records = Arc::pin(RefCell::new(Vec::new()));

        // configure client
        let client_send = intercept_send_callback(pair, Mode::Client);
        let client_record_handle =
            RecordingSendHandle::new(Mode::Client, records.clone(), client_send);
        let client_boxed = Box::new(client_record_handle);

        pair.client
            .set_send_callback(Some(s2n_tls_intercept::generic_send_cb::<RecordingSendHandle>))
            .unwrap();
        unsafe { pair.client.set_send_context(client_boxed.as_ref() as *const RecordingSendHandle as *mut c_void) }.unwrap();

        let server_send = intercept_send_callback(pair, Mode::Server);
        let server_record_handle =
            RecordingSendHandle::new(Mode::Server, records.clone(), server_send);
        let server_boxed = Box::new(server_record_handle);

        pair.server
            .set_send_callback(Some(s2n_tls_intercept::generic_send_cb::<RecordingSendHandle>))
            .unwrap();
        unsafe { pair.server.set_send_context(server_boxed.as_ref() as *const RecordingSendHandle as *mut c_void) }.unwrap();

        Self {
            records,
            client_handle: client_boxed,
            server_handle: server_boxed,
        }
    }

    /// Get all records in order of transmission
    pub fn get_all_records(&self) -> Vec<(Mode, Vec<u8>)> {
        self.records.borrow().clone()
    }
}

/// A handle that records data sent through it and forwards it to the original IO stream
pub struct RecordingSendHandle {
    // client or server
    identity: Mode,
    records: Pin<Arc<RefCell<Vec<(Mode, Vec<u8>)>>>>,
    // Reference to the TestPair's IO stream to forward data to
    io_stream: InterceptedSendCallback,
}

impl RecordingSendHandle {
    pub fn new(
        identity: Mode,
        records: Pin<Arc<RefCell<Vec<(Mode, Vec<u8>)>>>>,
        io_stream: InterceptedSendCallback,
    ) -> Self {
        Self {
            identity,
            records,
            io_stream,
        }
    }
}

impl Write for RecordingSendHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Record the data
        self.records
            .borrow_mut()
            .push((self.identity, buf.to_vec()));

        let bytes_written = self.io_stream.write(buf).unwrap();
        // should be local io
        assert_eq!(bytes_written, buf.len());

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        /* no op */
        Ok(())
    }
}
