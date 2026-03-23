//! GetStdHandle, WriteConsoleA/W, ReadConsoleA/W, SetConsoleMode.

use crate::utils::handle::{Handle, INVALID_HANDLE_VALUE, PSEUDO_STDERR, PSEUDO_STDIN, PSEUDO_STDOUT};
use crate::nt_kernel::file::nt_write_file;
use std::ffi::c_void;
use tracing::trace;

pub const STD_INPUT_HANDLE: u32 = 0xffff_fff6;
pub const STD_OUTPUT_HANDLE: u32 = 0xffff_fff5;
pub const STD_ERROR_HANDLE: u32 = 0xffff_fff4;

/// Retrieves a handle to the specified standard device.
pub extern "win64" fn get_std_handle(std_handle: u32) -> Handle {
    trace!("GetStdHandle({:#x})", std_handle);
    match std_handle {
        STD_INPUT_HANDLE => PSEUDO_STDIN,
        STD_OUTPUT_HANDLE => PSEUDO_STDOUT,
        STD_ERROR_HANDLE => PSEUDO_STDERR,
        _ => INVALID_HANDLE_VALUE,
    }
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
    if status == 0 { 1 } else { 0 }
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
