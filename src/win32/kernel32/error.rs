//! GetLastError, SetLastError (thread-local).

use tracing::trace;

thread_local! {
    static LAST_ERROR: std::cell::Cell<u32> = std::cell::Cell::new(0);
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

pub extern "win64" fn set_unhandled_exception_filter(lp_top_level_exception_filter: usize) -> usize {
    trace!("SetUnhandledExceptionFilter({:#x})", lp_top_level_exception_filter);
    unsafe {
        let old = UNHANDLED_EXCEPTION_FILTER;
        UNHANDLED_EXCEPTION_FILTER = lp_top_level_exception_filter;
        old
    }
}
