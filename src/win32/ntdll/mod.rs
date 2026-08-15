#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use crate::nt_kernel::file::*;
use crate::utils::handle::Handle;

pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

#[repr(C)]
pub struct IoStatusBlock {
    pub status: u32,
    pub information: usize,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

struct DirectoryScanCursor {
    entries: Vec<DirectoryEntryInfo>,
    index: usize,
}

static DIR_SCANS: std::sync::OnceLock<Mutex<HashMap<Handle, DirectoryScanCursor>>> =
    std::sync::OnceLock::new();

fn dir_scans() -> &'static Mutex<HashMap<Handle, DirectoryScanCursor>> {
    DIR_SCANS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub extern "win64" fn NtQueryDirectoryFile(
    file_handle: Handle,
    _event: Handle,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    file_information: *mut u8,
    length: u32,
    file_information_class: u32,
    return_single_entry: u8,
    _file_name: *const UnicodeString,
    restart_scan: u8,
) -> u32 {
    if io_status_block.is_null() || file_information.is_null() || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let mut scans = dir_scans().lock().expect("dir_scans poisoned");
    if restart_scan != 0 || !scans.contains_key(&file_handle) {
        match nt_query_directory_file(file_handle) {
            Ok(entries) => {
                scans.insert(file_handle, DirectoryScanCursor { entries, index: 0 });
            }
            Err(status) => {
                unsafe {
                    (*io_status_block).status = status;
                    (*io_status_block).information = 0;
                }
                return status;
            }
        }
    }

    let cursor = scans.get_mut(&file_handle).unwrap();
    if cursor.index >= cursor.entries.len() {
        unsafe {
            (*io_status_block).status = STATUS_NO_MORE_FILES;
            (*io_status_block).information = 0;
        }
        return STATUS_NO_MORE_FILES;
    }

    let mut written = 0usize;
    let mut prev_offset_ptr: *mut u32 = std::ptr::null_mut();

    while cursor.index < cursor.entries.len() {
        let entry = &cursor.entries[cursor.index];
        let name_utf16: Vec<u16> = entry.file_name.encode_utf16().collect();
        let name_bytes = name_utf16.len() * 2;

        let header_size = match file_information_class {
            1 => 64,   // FileDirectoryInformation
            2 => 72,   // FileFullDirectoryInformation
            3 => 94,   // FileBothDirectoryInformation
            37 => 104, // FileIdBothDirectoryInformation
            12 => 8,   // FileNamesInformation
            _ => 64,
        };

        let total_entry_size = (header_size + name_bytes + 7) & !7;
        if written + total_entry_size > length as usize {
            if written == 0 {
                return 0xC000_0023; // STATUS_BUFFER_TOO_SMALL
            }
            break;
        }

        if !prev_offset_ptr.is_null() {
            unsafe {
                *prev_offset_ptr = (written
                    - (prev_offset_ptr as usize - file_information as usize))
                    as u32;
            }
        }

        let entry_ptr = unsafe { file_information.add(written) };
        unsafe {
            std::ptr::write_bytes(entry_ptr, 0, total_entry_size);
        }

        let next_offset_ptr = entry_ptr as *mut u32;
        prev_offset_ptr = next_offset_ptr;

        let file_attributes: u32 = if entry.is_directory { 0x10 } else { 0x80 };
        let file_size: u64 = entry.file_size;

        unsafe {
            match file_information_class {
                1 => {
                    entry_ptr.add(40).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(48).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(56).cast::<u32>().write_unaligned(file_attributes);
                    entry_ptr.add(60).cast::<u32>().write_unaligned(name_bytes as u32);
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(64),
                        name_bytes,
                    );
                }
                3 | 37 => {
                    entry_ptr.add(40).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(48).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(56).cast::<u32>().write_unaligned(file_attributes);
                    entry_ptr.add(60).cast::<u32>().write_unaligned(name_bytes as u32);
                    let name_offset = if file_information_class == 37 { 104 } else { 94 };
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(name_offset),
                        name_bytes,
                    );
                }
                12 => {
                    entry_ptr.add(4).cast::<u32>().write_unaligned(name_bytes as u32);
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(8),
                        name_bytes,
                    );
                }
                _ => {
                    entry_ptr.add(40).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(48).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(56).cast::<u32>().write_unaligned(file_attributes);
                    entry_ptr.add(60).cast::<u32>().write_unaligned(name_bytes as u32);
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(64),
                        name_bytes,
                    );
                }
            }
        }

        written += total_entry_size;
        cursor.index += 1;

        if return_single_entry != 0 {
            break;
        }
    }

    unsafe {
        (*io_status_block).status = STATUS_SUCCESS;
        (*io_status_block).information = written;
    }

    STATUS_SUCCESS
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("NtQueryDirectoryFile", NtQueryDirectoryFile as usize);
    exports.insert("ZwQueryDirectoryFile", NtQueryDirectoryFile as usize);
    exports
}
