#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! GetStdHandle, WriteConsoleA/W, ReadConsoleA/W, SetConsoleMode.

use crate::nt_kernel::file::nt_write_file;
use crate::utils::handle::{
    Handle, INVALID_HANDLE_VALUE, PSEUDO_STDERR, PSEUDO_STDIN, PSEUDO_STDOUT,
};
use std::ffi::c_void;
use std::sync::RwLock;
use tracing::trace;

pub const STD_INPUT_HANDLE: u32 = 0xffff_fff6;
pub const STD_OUTPUT_HANDLE: u32 = 0xffff_fff5;
pub const STD_ERROR_HANDLE: u32 = 0xffff_fff4;

#[derive(Clone, Copy)]
struct StdHandles {
    stdin: Handle,
    stdout: Handle,
    stderr: Handle,
}

lazy_static::lazy_static! {
    static ref STD_HANDLES: RwLock<StdHandles> = RwLock::new(StdHandles {
        stdin: PSEUDO_STDIN,
        stdout: PSEUDO_STDOUT,
        stderr: PSEUDO_STDERR,
    });
}

/// Retrieves a handle to the specified standard device.
pub extern "win64" fn get_std_handle(std_handle: u32) -> Handle {
    trace!("GetStdHandle({:#x})", std_handle);
    let handles = STD_HANDLES.read().expect("std handles lock poisoned");
    match std_handle {
        STD_INPUT_HANDLE => handles.stdin,
        STD_OUTPUT_HANDLE => handles.stdout,
        STD_ERROR_HANDLE => handles.stderr,
        _ => INVALID_HANDLE_VALUE,
    }
}

pub extern "win64" fn set_std_handle(std_handle: u32, handle: Handle) -> i32 {
    trace!("SetStdHandle({:#x}, {})", std_handle, handle);
    let mut handles = STD_HANDLES.write().expect("std handles lock poisoned");
    match std_handle {
        STD_INPUT_HANDLE => handles.stdin = handle,
        STD_OUTPUT_HANDLE => handles.stdout = handle,
        STD_ERROR_HANDLE => handles.stderr = handle,
        _ => {
            super::error::set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
    }
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn get_console_cp() -> u32 {
    // Use UTF-8 code page for Linux host interoperability.
    65001
}

pub extern "win64" fn get_console_output_cp() -> u32 {
    // The host terminal uses the same UTF-8 encoding for console output.
    65001
}

pub extern "win64" fn get_number_of_console_input_events(
    console_input: Handle,
    event_count: *mut u32,
) -> i32 {
    if console_input != PSEUDO_STDIN || event_count.is_null() {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    // TuxExe currently exposes a non-interactive host-console input queue.
    unsafe { *event_count = 0 };
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn read_console_input_w(
    console_input: Handle,
    _input_records: *mut u8,
    _record_count: u32,
    records_read: *mut u32,
) -> i32 {
    if console_input != PSEUDO_STDIN || records_read.is_null() {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    unsafe { *records_read = 0 };
    // This is a non-blocking, empty headless queue. Callers should first use
    // GetNumberOfConsoleInputEvents, which reports zero.
    super::error::set_last_error(232); // ERROR_NO_DATA
    0
}

pub extern "win64" fn peek_console_input_a(
    console_input: Handle,
    _input_records: *mut u8,
    _record_count: u32,
    records_read: *mut u32,
) -> i32 {
    if console_input != PSEUDO_STDIN || records_read.is_null() {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    unsafe { *records_read = 0 };
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn attach_console(_dw_process_id: u32) -> i32 {
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn alloc_console() -> i32 {
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn free_console() -> i32 {
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn get_console_window() -> usize {
    0
}

pub extern "win64" fn set_console_ctrl_handler(_handler_routine: *const c_void, _add: i32) -> i32 {
    super::error::set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_console_mode(handle: Handle, lp_mode: *mut u32) -> i32 {
    if lp_mode.is_null() {
        super::error::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    if !matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR) {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }

    // Minimal mode bitmask compatible with common runtime checks.
    unsafe {
        *lp_mode = 0x0001;
    }
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn set_console_mode(handle: Handle, _dw_mode: u32) -> i32 {
    if !matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR) {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    super::error::set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn read_console_a(
    console_input: Handle,
    buffer: *mut c_void,
    number_of_chars_to_read: u32,
    number_of_chars_read: *mut u32,
    _reserved: *mut c_void,
) -> i32 {
    if console_input != PSEUDO_STDIN || buffer.is_null() {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }

    // Avoid blocking host stdin in engine startup paths.
    if !number_of_chars_read.is_null() {
        unsafe {
            *number_of_chars_read = 0;
        }
    }

    if number_of_chars_to_read > 0 {
        unsafe {
            *(buffer.cast::<u8>()) = 0;
        }
    }

    super::error::set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn read_console_w(
    console_input: Handle,
    buffer: *mut u16,
    number_of_chars_to_read: u32,
    number_of_chars_read: *mut u32,
    _reserved: *mut c_void,
) -> i32 {
    if console_input != PSEUDO_STDIN || buffer.is_null() {
        super::error::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }

    // Avoid blocking host stdin in engine startup paths.
    if !number_of_chars_read.is_null() {
        unsafe {
            *number_of_chars_read = 0;
        }
    }

    if number_of_chars_to_read > 0 {
        unsafe {
            *buffer = 0;
        }
    }

    super::error::set_last_error(0);
    1
}

/// Simplified WriteConsoleA
pub extern "win64" fn write_console_a(
    console_output: Handle,
    buffer: *const c_void,
    number_of_chars_to_write: u32,
    number_of_chars_written: Option<&mut u32>,
    _reserved: *mut c_void,
) -> i32 {
    trace!("WriteConsoleA(handle={}, len={})", console_output, number_of_chars_to_write);
    let status = nt_write_file(
        console_output,
        buffer,
        number_of_chars_to_write, // Ascii chars = bytes
        number_of_chars_written,
    );
    if status == 0 {
        1
    } else {
        0
    }
}

/// Simplified WriteConsoleW
pub extern "win64" fn write_console_w(
    console_output: Handle,
    buffer: *const u16,
    number_of_chars_to_write: u32,
    number_of_chars_written: Option<&mut u32>,
    _reserved: *mut c_void,
) -> i32 {
    trace!("WriteConsoleW(handle={}, chars={})", console_output, number_of_chars_to_write);
    if number_of_chars_to_write == 0 {
        if let Some(w) = number_of_chars_written {
            *w = 0;
        }
        return 1;
    }

    let slice = unsafe { std::slice::from_raw_parts(buffer, number_of_chars_to_write as usize) };
    let string = String::from_utf16_lossy(slice);

    let status = nt_write_file(
        console_output,
        string.as_ptr() as *const c_void,
        string.len() as u32,
        None, // nt_write_file provides bytes, not chars, so we can't easily map it if different
    );

    if status == 0 {
        if let Some(w) = number_of_chars_written {
            *w = number_of_chars_to_write;
        }
        1
    } else {
        0
    }
}

pub extern "win64" fn set_console_title_a(_lp_console_title: *const std::ffi::c_char) -> i32 {
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn set_console_title_w(_lp_console_title: *const u16) -> i32 {
    super::error::set_last_error(0);
    1
}

pub extern "win64" fn get_console_title_a(lp_console_title: *mut std::ffi::c_char, n_size: u32) -> u32 {
    if !lp_console_title.is_null() && n_size > 0 {
        unsafe { *lp_console_title = 0; }
    }
    super::error::set_last_error(0);
    0
}

pub extern "win64" fn get_console_title_w(lp_console_title: *mut u16, n_size: u32) -> u32 {
    if !lp_console_title.is_null() && n_size > 0 {
        unsafe { *lp_console_title = 0; }
    }
    super::error::set_last_error(0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_std_handle_updates_get_std_handle() {
        let original = get_std_handle(STD_OUTPUT_HANDLE);
        assert_eq!(set_std_handle(STD_OUTPUT_HANDLE, 0x1234_5678), 1);
        assert_eq!(get_std_handle(STD_OUTPUT_HANDLE), 0x1234_5678);

        // Restore default-like prior value for test isolation.
        assert_eq!(set_std_handle(STD_OUTPUT_HANDLE, original), 1);
    }

    #[test]
    fn get_console_mode_for_stdout_succeeds() {
        let mut mode = 0_u32;
        assert_eq!(get_console_mode(PSEUDO_STDOUT, &mut mode), 1);
        assert_eq!(mode, 0x0001);
    }
}
