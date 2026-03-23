use std::ffi::c_void;
use tracing::trace;

pub extern "win64" fn InitializeCriticalSection(_lpCriticalSection: *mut c_void) {
    trace!("InitializeCriticalSection()");
}

pub extern "win64" fn EnterCriticalSection(_lpCriticalSection: *mut c_void) {
    // For now, assume single threaded and just succeed
}

pub extern "win64" fn LeaveCriticalSection(_lpCriticalSection: *mut c_void) {
    // No-op for now
}

pub extern "win64" fn DeleteCriticalSection(_lpCriticalSection: *mut c_void) {
    trace!("DeleteCriticalSection()");
}
