//! WriteFile, ReadFile, CreateFile, SetFilePointer, GetFileType.

use crate::nt_kernel::file::{nt_read_file, nt_write_file};
use crate::utils::handle::Handle;
use std::ffi::c_void;
use tracing::trace;

pub extern "win64" fn write_file(
    handle: Handle,
    buffer: *const c_void,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: Option<&mut u32>,
    _overlapped: *mut c_void,
) -> i32 {
    trace!("WriteFile(handle={}, len={})", handle, number_of_bytes_to_write);
    let status = nt_write_file(handle, buffer, number_of_bytes_to_write, number_of_bytes_written);
    if status == 0 { 1 } else { 0 }
}

pub extern "win64" fn read_file(
    handle: Handle,
    buffer: *mut c_void,
    number_of_bytes_to_read: u32,
    number_of_bytes_read: Option<&mut u32>,
    _overlapped: *mut c_void,
) -> i32 {
    trace!("ReadFile(handle={}, len={})", handle, number_of_bytes_to_read);
    let status = nt_read_file(handle, buffer, number_of_bytes_to_read, number_of_bytes_read);
    if status == 0 { 1 } else { 0 }
}
