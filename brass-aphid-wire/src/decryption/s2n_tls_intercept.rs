use std::{
    cell::RefCell,
    collections::VecDeque,
    ffi::{c_int, c_void},
    io::{ErrorKind, Read, Write},
};

use s2n_tls::{enums::Mode, testing::TestPair};

////////////////////////////////////////////////////////////////////////////////
/////////////////// redefinition of items in s2n-tls crate /////////////////////
////////////////////////////////////////////////////////////////////////////////

pub type LocalDataBuffer = RefCell<VecDeque<u8>>;

// this is the callback defined for the test pair in the s2n-tls crate. Should be
// made public
pub(crate) unsafe extern "C" fn test_pair_send_cb(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    let context = &*(context as *const LocalDataBuffer);
    let data = core::slice::from_raw_parts(data, len as _);
    let bytes_written = context.borrow_mut().write(data).unwrap();
    bytes_written as c_int
}

// Note: this callback will be invoked multiple times in the event that
// the byte-slices of the VecDeque are not contiguous (wrap around).
pub(crate) unsafe extern "C" fn test_pair_recv_cb(
    context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    let context = &*(context as *const LocalDataBuffer);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    match context.borrow_mut().read(data) {
        Ok(len) => {
            if len == 0 {
                // returning a length of 0 indicates a channel close (e.g. a
                // TCP Close) which would not be correct here. To just communicate
                // that there is no more data, we instead set the errno to
                // WouldBlock and return -1.
                errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                -1
            } else {
                len as c_int
            }
        }
        Err(err) => {
            // VecDeque IO Operations should never fail
            panic!("{err:?}");
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////// Read & Write for repackaged C callbacks /////////////////////
////////////////////////////////////////////////////////////////////////////////

/// This struct is used to hold the nasty C callbacks that customers are
/// doing IO with.
#[derive(Debug)]
pub struct InterceptedSendCallback {
    pub send_ctx: *mut c_void,
    pub send_cb: s2n_tls_sys::s2n_send_fn,
}

impl std::io::Write for InterceptedSendCallback {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let res = unsafe { self.send_cb.unwrap()(self.send_ctx, buf.as_ptr(), buf.len() as u32) };
        if res == -1 {
            Err(std::io::Error::new(
                ErrorKind::WouldBlock,
                "from intercepted",
            ))
        } else {
            Ok(res as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        /* no op */
        Ok(())
    }
}

#[derive(Debug)]
pub struct InterceptedRecvCallback {
    pub recv_ctx: *mut c_void,
    pub recv_cb: s2n_tls_sys::s2n_recv_fn,
}

impl std::io::Read for InterceptedRecvCallback {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res =
            unsafe { self.recv_cb.unwrap()(self.recv_ctx, buf.as_mut_ptr(), buf.len() as u32) };
        if res == -1 {
            Err(std::io::Error::new(
                ErrorKind::WouldBlock,
                "from intercepted",
            ))
        } else {
            Ok(res as usize)
        }
    }
}

pub struct ArchaicCPipe {
    send: InterceptedSendCallback,
    recv: InterceptedRecvCallback,
}

impl ArchaicCPipe {
    pub fn new(send: InterceptedSendCallback, recv: InterceptedRecvCallback) -> Self {
        Self { send, recv }
    }
}

impl std::io::Read for ArchaicCPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv.read(buf)
    }
}

impl std::io::Write for ArchaicCPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        /* no op */
        Ok(())
    }
}

/// Reconstruct the send callback used for the TestPair connections.
///
/// There is not getter for this, so we have to "reconstruct" them. If the TestPair
/// implementation ever changes, then this will all break.
pub fn intercept_send_callback(test_pair: &TestPair, mode: Mode) -> InterceptedSendCallback {
    // let server send_cb
    let tx_stream = match mode {
        Mode::Server => &test_pair.io.server_tx_stream,
        Mode::Client => &test_pair.io.client_tx_stream,
    };

    InterceptedSendCallback {
        send_ctx: tx_stream as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
        send_cb: Some(test_pair_send_cb),
    }
}

/// Reconstruct the send callback used for the TestPair connections.
///
/// There is not getter for this, so we have to "reconstruct" them. If the TestPair
/// implementation ever changes, then this will all break.
pub fn intercept_recv_callback(test_pair: &TestPair, mode: Mode) -> InterceptedRecvCallback {
    // let server send_cb
    let rx_stream = match mode {
        Mode::Server => &test_pair.io.client_tx_stream,
        Mode::Client => &test_pair.io.server_tx_stream,
    };

    InterceptedRecvCallback {
        recv_ctx: rx_stream as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
        recv_cb: Some(test_pair_recv_cb),
    }
}

////////////////////////////////////////////////////////////////////////////////
///////////////////// generic Read & Write C callbacks /////////////////////////
////////////////////////////////////////////////////////////////////////////////

// This callback can be used where ctx is `Box<T: Write>`
pub(crate) unsafe extern "C" fn generic_send_cb<T: std::io::Write>(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    // we need to double box because Box<dyn Write> is a fat pointer (16 bytes)
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts(data, len as _);
    let bytes_written = context.write(data).unwrap();
    bytes_written as c_int
}

// This callback can be used where ctx is `Box<T: Read>`
pub(crate) unsafe extern "C" fn generic_recv_cb<T: std::io::Read>(
    context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    // we need to double box because Box<dyn Write> is a fat pointer (16 bytes)
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    match context.read(data) {
        Ok(len) => {
            if len == 0 {
                // returning a length of 0 indicates a channel close (e.g. a
                // TCP Close) which would not be correct here. To just communicate
                // that there is no more data, we instead set the errno to
                // WouldBlock and return -1.
                errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                -1
            } else {
                len as c_int
            }
        }
        Err(err) => {
            if err.kind() == ErrorKind::WouldBlock {
                -1
            } else {
                panic!("unrecognized error {err:?}")
            }
        }
    }
}
