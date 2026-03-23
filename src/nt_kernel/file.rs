//! NtCreateFile, NtReadFile, NtWriteFile, NtClose → open/read/write/close.

use crate::utils::handle::{global_table, Handle, StdioHandle};
use std::ffi::c_void;


pub type NtStatus = u32;

pub const STATUS_SUCCESS: NtStatus = 0x00000000;
pub const STATUS_INVALID_HANDLE: NtStatus = 0xC0000008;

/// Thin wrapper for NtWriteFile, simplified for now.
pub fn nt_write_file(
    handle: Handle,
    buffer: *const c_void,
    length: u32,
    bytes_written: Option<&mut u32>,
) -> NtStatus {
    let mut status = STATUS_INVALID_HANDLE;

    global_table().with(handle, |obj| {
        if let Some(stdio) = obj.as_any().downcast_ref::<StdioHandle>() {
            let written = unsafe {
                libc::write(stdio.fd, buffer, length as libc::size_t)
            };
            
            if written >= 0 {
                if let Some(bw) = bytes_written {
                    *bw = written as u32;
                }
                status = STATUS_SUCCESS;
            } else {
                // Should map errno to NTSTATUS here
                status = 0xC0000001; // STATUS_UNSUCCESSFUL
            }
        } else {
            // Other types of handles... (Not implemented yet)
        }
    });

    status
}

/// Thin wrapper for NtReadFile, simplified for now.
pub fn nt_read_file(
    handle: Handle,
    buffer: *mut c_void,
    length: u32,
    bytes_read: Option<&mut u32>,
) -> NtStatus {
    let mut status = STATUS_INVALID_HANDLE;

    global_table().with(handle, |obj| {
        if let Some(stdio) = obj.as_any().downcast_ref::<StdioHandle>() {
            let read_sz = unsafe {
                libc::read(stdio.fd, buffer, length as libc::size_t)
            };
            
            if read_sz >= 0 {
                if let Some(br) = bytes_read {
                    *br = read_sz as u32;
                }
                status = STATUS_SUCCESS;
            } else {
                status = 0xC0000001; // STATUS_UNSUCCESSFUL
            }
        } else {
            // Other types of handles...
        }
    });

    status
}
