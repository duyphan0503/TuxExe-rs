use std::ffi::c_void;
use tracing::trace;

pub extern "win64" fn VirtualProtect(
    _lpAddress: *mut c_void,
    _dwSize: usize,
    _flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> i32 {
    trace!("VirtualProtect Stub");
    unsafe {
        if !lpflOldProtect.is_null() {
            *lpflOldProtect = 0x04; // PAGE_READWRITE for now
        }
    }
    1 // Success
}

pub extern "win64" fn VirtualQuery(
    _lpAddress: *const c_void,
    _lpBuffer: *mut c_void,
    _dwLength: usize,
) -> usize {
    trace!("VirtualQuery Stub");
    0 // Error for now? Or fill some dummy struct.
}
