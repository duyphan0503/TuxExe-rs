use std::ffi::c_void;
use tracing::trace;

pub extern "win64" fn TlsGetValue(_dwTlsIndex: u32) -> *mut c_void {
    trace!("TlsGetValue Stub index={}", _dwTlsIndex);
    std::ptr::null_mut()
}
