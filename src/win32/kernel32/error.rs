//! GetLastError, SetLastError (thread-local).

use tracing::trace;

thread_local! {
    static LAST_ERROR: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub extern "win64" fn get_last_error() -> u32 {
    let err = LAST_ERROR.with(|e| e.get());
    trace!("GetLastError() -> {}", err);
    err
}

pub extern "win64" fn set_last_error(err_code: u32) {
    trace!("SetLastError({})", err_code);
    LAST_ERROR.with(|e| e.set(err_code));
}

static mut UNHANDLED_EXCEPTION_FILTER: usize = 0;

pub extern "win64" fn set_unhandled_exception_filter(
    lp_top_level_exception_filter: usize,
) -> usize {
    trace!("SetUnhandledExceptionFilter({:#x})", lp_top_level_exception_filter);
    unsafe {
        let old = UNHANDLED_EXCEPTION_FILTER;
        UNHANDLED_EXCEPTION_FILTER = lp_top_level_exception_filter;
        old
    }
}

pub extern "win64" fn unhandled_exception_filter(exception_info: *mut std::ffi::c_void) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    let filter = unsafe { UNHANDLED_EXCEPTION_FILTER };
    trace!("UnhandledExceptionFilter(filter={:#x})", filter);
    if filter == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // SAFETY: Windows contract stores a function pointer set by SetUnhandledExceptionFilter.
    unsafe {
        let handler: extern "win64" fn(*mut std::ffi::c_void) -> i32 = std::mem::transmute(filter);
        handler(exception_info)
    }
}

pub extern "win64" fn raise_exception(
    dw_exception_code: u32,
    dw_exception_flags: u32,
    n_number_of_arguments: u32,
    _lp_arguments: *const usize,
) {
    trace!(
        "RaiseException(code=0x{:08x}, flags=0x{:08x}, args={})",
        dw_exception_code,
        dw_exception_flags,
        n_number_of_arguments
    );

    // Minimal behavior: invoke top-level filter if configured.
    // Full SEH dispatch is tracked as a later compatibility milestone.
    let _ = unhandled_exception_filter(std::ptr::null_mut());
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "win64" fn test_filter(_info: *mut std::ffi::c_void) -> i32 {
        1
    }

    #[test]
    fn unhandled_exception_filter_uses_registered_handler() {
        let _guard = crate::test_support::serial_guard();
        let old = set_unhandled_exception_filter(test_filter as usize);
        let result = unhandled_exception_filter(std::ptr::null_mut());
        assert_eq!(result, 1);
        let _ = set_unhandled_exception_filter(old);
    }

    #[test]
    fn raise_exception_is_callable() {
        raise_exception(0xE000_0001, 0, 0, std::ptr::null());
    }
}
