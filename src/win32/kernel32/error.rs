//! GetLastError, SetLastError (thread-local).

use crate::utils::wide_string::from_wide_ptr;
use std::ffi::CStr;
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
    let allow_registration = std::env::var("TUXEXE_ENABLE_UNHANDLED_FILTER")
        .ok()
        .is_some_and(|value| value == "1");
    unsafe {
        let old = UNHANDLED_EXCEPTION_FILTER;
        if allow_registration {
            UNHANDLED_EXCEPTION_FILTER = lp_top_level_exception_filter;
        } else {
            // Windows crash-report filters often expect full SEH/EXCEPTION_POINTERS semantics.
            // Until we implement that path, keep custom filters disabled by default.
            UNHANDLED_EXCEPTION_FILTER = 0;
        }
        old
    }
}

pub extern "win64" fn unhandled_exception_filter(exception_info: *mut std::ffi::c_void) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

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
    const MSVC_THREAD_NAME_EXCEPTION: u32 = 0x406D_1388;

    trace!(
        "RaiseException(code=0x{:08x}, flags=0x{:08x}, args={})",
        dw_exception_code,
        dw_exception_flags,
        n_number_of_arguments
    );

    // MSVC uses this exception to name worker threads for debuggers.
    // Real Windows SEH treats it as a continuable notification.
    if dw_exception_code == MSVC_THREAD_NAME_EXCEPTION {
        return;
    }

    // We do not implement full SEH dispatch yet; treat synthetic raises as no-op.
    // This avoids crashing on null EXCEPTION_POINTERS in handlers that expect OS-populated data.
}

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;
const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0000_0100;
const FORMAT_MESSAGE_FROM_STRING: u32 = 0x0000_0400;
const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x0000_1000;

fn system_message_for_error(message_id: u32) -> String {
    match message_id {
        0 => "The operation completed successfully.".to_string(),
        2 => "The system cannot find the file specified.".to_string(),
        3 => "The system cannot find the path specified.".to_string(),
        5 => "Access is denied.".to_string(),
        6 => "The handle is invalid.".to_string(),
        87 => "The parameter is incorrect.".to_string(),
        122 => "The data area passed to a system call is too small.".to_string(),
        183 => "Cannot create a file when that file already exists.".to_string(),
        996 => "Overlapped I/O event is not in a signaled state.".to_string(),
        997 => "Overlapped I/O operation is in progress.".to_string(),
        _ => format!("Windows error {}", message_id),
    }
}

pub extern "win64" fn format_message_a(
    dw_flags: u32,
    lp_source: *const std::ffi::c_void,
    dw_message_id: u32,
    _dw_language_id: u32,
    lp_buffer: *mut u8,
    n_size: u32,
    _arguments: *const std::ffi::c_void,
) -> u32 {
    let mut message = String::new();
    if (dw_flags & FORMAT_MESSAGE_FROM_STRING) != 0 {
        if lp_source.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let src = unsafe { CStr::from_ptr(lp_source.cast::<i8>()) };
        message = src.to_string_lossy().to_string();
    } else if (dw_flags & FORMAT_MESSAGE_FROM_SYSTEM) != 0 {
        message = system_message_for_error(dw_message_id);
    } else if dw_message_id != 0 {
        message = system_message_for_error(dw_message_id);
    }

    if message.is_empty() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let bytes = message.as_bytes();
    if (dw_flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0 {
        if lp_buffer.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let total = bytes.len().saturating_add(1);
        let mem = unsafe { libc::malloc(total) }.cast::<u8>();
        if mem.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, bytes.len());
            *mem.add(bytes.len()) = 0;
            *lp_buffer.cast::<*mut u8>() = mem;
        }
        set_last_error(0);
        return bytes.len() as u32;
    }

    if lp_buffer.is_null() || n_size == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let cap = n_size as usize;
    if cap <= 1 {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let to_copy = bytes.len().min(cap - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, to_copy);
        *lp_buffer.add(to_copy) = 0;
    }

    if to_copy < bytes.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
    } else {
        set_last_error(0);
    }
    to_copy as u32
}

pub extern "win64" fn format_message_w(
    dw_flags: u32,
    lp_source: *const std::ffi::c_void,
    dw_message_id: u32,
    _dw_language_id: u32,
    lp_buffer: *mut u16,
    n_size: u32,
    _arguments: *const std::ffi::c_void,
) -> u32 {
    let mut message = String::new();
    if (dw_flags & FORMAT_MESSAGE_FROM_STRING) != 0 {
        if lp_source.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let Some(src) = (unsafe { from_wide_ptr(lp_source.cast::<u16>()) }).ok() else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        message = src;
    } else if (dw_flags & FORMAT_MESSAGE_FROM_SYSTEM) != 0 {
        message = system_message_for_error(dw_message_id);
    } else if dw_message_id != 0 {
        message = system_message_for_error(dw_message_id);
    }

    if message.is_empty() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let wide: Vec<u16> = message.encode_utf16().collect();
    if (dw_flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0 {
        if lp_buffer.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let total_chars = wide.len().saturating_add(1);
        let mem = unsafe { libc::malloc(total_chars * std::mem::size_of::<u16>()) }.cast::<u16>();
        if mem.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), mem, wide.len());
            *mem.add(wide.len()) = 0;
            *lp_buffer.cast::<*mut u16>() = mem;
        }
        set_last_error(0);
        return wide.len() as u32;
    }

    if lp_buffer.is_null() || n_size == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let cap = n_size as usize;
    if cap <= 1 {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let to_copy = wide.len().min(cap - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_buffer, to_copy);
        *lp_buffer.add(to_copy) = 0;
    }

    if to_copy < wide.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
    } else {
        set_last_error(0);
    }
    to_copy as u32
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
