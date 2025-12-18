use std::{
    any::type_name, ffi::{c_int, c_void}, io::ErrorKind
};

use s2n_tls::connection::Connection as S2NConnection;

// TODO: make these dynamic. If the struct layout changes across version then this
// will explode spectacularly.
const SEND_CB_OFFSET: usize = 48;
const RECV_CB_OFFSET: usize = 56;
const SEND_CTX_OFFSET: usize = 64;
const RECV_CTX_OFFSET: usize = 72;

pub trait PeerIntoS2ntlsInsides {
    fn steal_send_cb(&self) -> InterceptedSendCallback;

    fn steal_recv_cb(&self) -> InterceptedRecvCallback;
}

unsafe fn pointer_from_offset(conn: &S2NConnection, offset: usize) -> *mut u8 {
    let conn = *(conn as *const S2NConnection as *const *const s2n_tls_sys::s2n_connection);
    let conn_bytes = conn as *mut u8;

    let requested_ptr = conn_bytes.add(offset) as *mut *mut u8;
    *requested_ptr
}

impl PeerIntoS2ntlsInsides for S2NConnection {
    fn steal_send_cb(&self) -> InterceptedSendCallback {
        unsafe {
            let send_cb = pointer_from_offset(self, SEND_CB_OFFSET);
            let send_ctx = pointer_from_offset(self, SEND_CTX_OFFSET);
            InterceptedSendCallback {
                send_ctx: std::mem::transmute(send_ctx),
                send_cb: std::mem::transmute(send_cb),
            }
        }
    }

    fn steal_recv_cb(&self) -> InterceptedRecvCallback {
        unsafe {
            let recv_cb = pointer_from_offset(self, RECV_CB_OFFSET);
            let recv_ctx = pointer_from_offset(self, RECV_CTX_OFFSET);
            InterceptedRecvCallback {
                recv_ctx: std::mem::transmute(recv_ctx),
                recv_cb: std::mem::transmute(recv_cb),
            }
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
            // TODO: check the errno here
            let errno = errno::errno().0;
            let err = std::io::Error::from_raw_os_error(errno);
            tracing::debug!("error from intercepted write callback: {err:?}");
            Err(err)
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
            // TODO: check errno here
            let errno = errno::errno().0;
            let err = std::io::Error::from_raw_os_error(errno);
            tracing::debug!("error from intercepted read callback: {err:?}");
            Err(err)
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

////////////////////////////////////////////////////////////////////////////////
///////////////////// generic Read & Write C callbacks /////////////////////////
////////////////////////////////////////////////////////////////////////////////

// This callback can be used where ctx is `Box<T: Write>`
pub(crate) unsafe extern "C" fn generic_send_cb<T: std::io::Write>(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts(data, len as _);
    match context.write(data) {
        Ok(bytes_written) => bytes_written as i32,
        Err(err) => {
            match err.raw_os_error() {
                Some(os_err) => {
                    tracing::debug!("setting errno for {err}");
                    errno::set_errno(errno::Errno(os_err))
                }
                None => {
                    tracing::warn!("Err {err} doesn't have a corresponding os err 😬")
                }
            }
            -1
        },
    }
}

// This callback can be used where ctx is `Box<T: Read>`
pub(crate) unsafe extern "C" fn generic_recv_cb<T: std::io::Read>(
    raw_context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(raw_context as *mut T);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    tracing::trace!("generic recv cb {:?} into: buffer of size {}", type_name::<T>(), data.len());
    let read_result = context.read(data);
    tracing::trace!("generic recv cb: read result: {read_result:?}");
    match read_result {
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
            match err.raw_os_error() {
                Some(os_err) => {
                    tracing::debug!("setting errno for {err}");
                    errno::set_errno(errno::Errno(os_err))
                }
                None => {
                    tracing::warn!("Err {err} doesn't have a corresponding os err 😬")
                }
            }
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::c_void, ptr::NonNull};

    use crate::decryption::s2n_tls_intercept::{
        RECV_CB_OFFSET, RECV_CTX_OFFSET, SEND_CB_OFFSET, SEND_CTX_OFFSET,
    };

    #[test]
    fn s2n_tls_inspection() {
        // these will be the "needles" that we search for in the "haystack" of
        // s2n-tls connection memory
        let send_cb_value: u8 = 0;
        let send_cb_ptr = &send_cb_value as *const u8 as *mut u8;

        let send_ctx_value: u8 = 0;
        let send_ctx_ptr = &send_ctx_value as *const u8 as *mut u8;

        let recv_cb_value: u8 = 0;
        let recv_cb_ptr = &recv_cb_value as *const u8 as *mut u8;

        let recv_ctx_value: u8 = 0;
        let recv_ctx_ptr = &recv_ctx_value as *const u8 as *mut u8;

        let mut conn = s2n_tls::connection::Connection::new_server();
        conn.set_send_callback(unsafe { std::mem::transmute(send_cb_ptr) })
            .unwrap();
        unsafe { conn.set_send_context(send_ctx_ptr as *mut c_void) }.unwrap();

        conn.set_receive_callback(unsafe { std::mem::transmute(recv_cb_ptr) })
            .unwrap();
        unsafe { conn.set_receive_context(recv_ctx_ptr as *mut c_void) }.unwrap();

        // todo: usize pointer casts instead
        let conn: NonNull<s2n_tls_sys::s2n_connection> = unsafe { std::mem::transmute(conn) };
        let conn = conn.as_ptr() as *mut u8;

        let send_cb_offset = offset(conn, send_cb_ptr);
        assert_eq!(send_cb_offset, SEND_CB_OFFSET);

        let send_ctx_offset = offset(conn, send_ctx_ptr);
        assert_eq!(send_ctx_offset, SEND_CTX_OFFSET);

        let recv_cb_offset = offset(conn, recv_cb_ptr);
        assert_eq!(recv_cb_offset, RECV_CB_OFFSET);

        let recv_ctx_offset = offset(conn, recv_ctx_ptr);
        assert_eq!(recv_ctx_offset, RECV_CTX_OFFSET);
    }

    /// Find the offset of `needle` in `haystack`
    ///
    /// If `needle` isn't in `haystack` then this function will simply yeet itself
    /// over the edge into SegSev canyon.
    ///
    /// TODO: can we assume that this is aligned? If it's not we blow up anyways.
    /// "misaligned pointer dereference: address must be a multiple of 0x8 but is 0xe945f0108831"
    fn offset(haystack: *mut u8, needle: *mut u8) -> usize {
        // I could make this all work with usize's, but it's nice to have the actu
        assert_eq!(std::mem::size_of::<u64>(), std::mem::size_of::<usize>());
        let needle = needle as usize;
        let needle = needle.to_ne_bytes();
        let mut offset = 0;
        loop {
            // check for needle
            let mut found_needle = true;
            for (i, byte) in needle.iter().enumerate() {
                if unsafe { *haystack.add(offset + i) } != *byte {
                    found_needle = false;
                }
            }

            if found_needle {
                return offset;
            }

            offset += 1;
        }
    }
}
