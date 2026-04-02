#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! WriteFile/ReadFile plus core CreateFile/FindFirst/FindNext support.

use crate::nt_kernel::file::{
    nt_create_file, nt_query_directory_file, nt_query_information_by_path,
    nt_query_information_file, nt_read_file, nt_set_file_pointer_ex, nt_set_information_file,
    nt_write_file, CreateDisposition, SetFileInformation, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::utils::{
    handle::{
        global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE, PSEUDO_STDERR,
        PSEUDO_STDIN, PSEUDO_STDOUT,
    },
    wide_string::from_wide_ptr,
};
use std::ffi::{c_void, CStr};
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::trace;

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const FILE_ATTRIBUTE_INVALID: u32 = 0xFFFF_FFFF;

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const GET_FILEEX_INFO_STANDARD: u32 = 0;

const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;

pub const FILE_TYPE_UNKNOWN: u32 = 0;
pub const FILE_TYPE_DISK: u32 = 1;
pub const FILE_TYPE_CHAR: u32 = 2;
pub const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;

fn temp_dir_windows_path() -> String {
    let mut value = std::env::temp_dir().to_string_lossy().replace('/', "\\");
    if !value.ends_with('\\') {
        value.push('\\');
    }
    value
}

fn next_temp_unique() -> u32 {
    static UNIQUE: AtomicUsize = AtomicUsize::new(1);
    UNIQUE.fetch_add(1, Ordering::Relaxed) as u32
}

fn normalize_host_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn disk_space_for_path(path: Option<&str>) -> Result<(u64, u64, u64, u64), u32> {
    let host_path = path.map(normalize_host_path).unwrap_or_else(|| ".".to_string());
    let c_path = std::ffi::CString::new(host_path).map_err(|_| ERROR_INVALID_PARAMETER)?;

    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(ERROR_PATH_NOT_FOUND);
    }

    let block_size = if stat.f_frsize > 0 { stat.f_frsize as u64 } else { stat.f_bsize as u64 };
    if block_size == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }

    let total_bytes =
        (stat.f_blocks as u128).saturating_mul(block_size as u128).min(u64::MAX as u128) as u64;
    let free_bytes_avail =
        (stat.f_bavail as u128).saturating_mul(block_size as u128).min(u64::MAX as u128) as u64;
    let free_bytes_total =
        (stat.f_bfree as u128).saturating_mul(block_size as u128).min(u64::MAX as u128) as u64;

    Ok((block_size, total_bytes, free_bytes_avail, free_bytes_total))
}

#[derive(Debug)]
struct FindFileHandle {
    entries: Vec<String>,
    cursor: AtomicUsize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FileTime {
    dw_low_date_time: u32,
    dw_high_date_time: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Win32FileAttributeData {
    dw_file_attributes: u32,
    ft_creation_time: FileTime,
    ft_last_access_time: FileTime,
    ft_last_write_time: FileTime,
    n_file_size_high: u32,
    n_file_size_low: u32,
}

impl HandleObject for FindFileHandle {
    fn type_name(&self) -> &'static str {
        "FindFileHandle"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn status_to_win_error(status: u32) -> u32 {
    match status {
        0 => ERROR_SUCCESS,
        STATUS_OBJECT_NAME_NOT_FOUND => ERROR_FILE_NOT_FOUND,
        0xC000_003A => ERROR_PATH_NOT_FOUND,
        0xC000_0022 => ERROR_ACCESS_DENIED,
        STATUS_INVALID_HANDLE => ERROR_INVALID_HANDLE,
        STATUS_INVALID_PARAMETER => ERROR_INVALID_PARAMETER,
        STATUS_OBJECT_NAME_COLLISION => ERROR_ALREADY_EXISTS,
        _ => ERROR_INVALID_PARAMETER,
    }
}

fn set_last_error(err: u32) {
    super::error::set_last_error(err);
}

fn unix_seconds_to_filetime(secs: i64) -> FileTime {
    let positive = secs.max(0) as u64;
    let ticks = (positive + 11_644_473_600).saturating_mul(10_000_000);
    FileTime {
        dw_low_date_time: (ticks & 0xFFFF_FFFF) as u32,
        dw_high_date_time: (ticks >> 32) as u32,
    }
}

fn write_attribute_data(
    info: crate::nt_kernel::file::FileInformation,
    lp_file_information: *mut c_void,
) {
    let attributes =
        if info.is_directory { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
    let data = Win32FileAttributeData {
        dw_file_attributes: attributes,
        ft_creation_time: FileTime::default(),
        ft_last_access_time: unix_seconds_to_filetime(info.last_access_time_unix),
        ft_last_write_time: unix_seconds_to_filetime(info.last_write_time_unix),
        n_file_size_high: (info.file_size >> 32) as u32,
        n_file_size_low: (info.file_size & 0xFFFF_FFFF) as u32,
    };

    unsafe {
        *lp_file_information.cast::<Win32FileAttributeData>() = data;
    }
}

unsafe fn c_string(ptr: *const i8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(ToOwned::to_owned)
}

unsafe fn wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    from_wide_ptr(ptr).ok()
}

fn to_disposition(dw_creation_disposition: u32) -> Option<CreateDisposition> {
    match dw_creation_disposition {
        1 => Some(CreateDisposition::CreateNew),        // CREATE_NEW
        2 => Some(CreateDisposition::CreateAlways),     // CREATE_ALWAYS
        3 => Some(CreateDisposition::OpenExisting),     // OPEN_EXISTING
        4 => Some(CreateDisposition::OpenAlways),       // OPEN_ALWAYS
        5 => Some(CreateDisposition::TruncateExisting), // TRUNCATE_EXISTING
        _ => None,
    }
}

fn access_flags(dw_desired_access: u32) -> (bool, bool) {
    let generic_read = 0x8000_0000u32;
    let generic_write = 0x4000_0000u32;
    let read = (dw_desired_access & generic_read) != 0 || dw_desired_access == 0;
    let write = (dw_desired_access & generic_write) != 0;
    (read, write)
}

pub extern "win64" fn write_file(
    handle: Handle,
    buffer: *const c_void,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: Option<&mut u32>,
    _overlapped: *mut c_void,
) -> i32 {
    trace!("WriteFile(handle={}, len={})", handle, number_of_bytes_to_write);
    let status = nt_write_file(handle, buffer, number_of_bytes_to_write, number_of_bytes_written);
    if status == 0 {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(status_to_win_error(status));
        0
    }
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
    if status == 0 {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(status_to_win_error(status));
        0
    }
}

pub extern "win64" fn create_file_a(
    lp_file_name: *const i8,
    dw_desired_access: u32,
    _dw_share_mode: u32,
    _lp_security_attributes: *mut c_void,
    dw_creation_disposition: u32,
    _dw_flags_and_attributes: u32,
    _h_template_file: Handle,
) -> Handle {
    init_global_table();
    let Some(path) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    let Some(disposition) = to_disposition(dw_creation_disposition) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    let (read, write) = access_flags(dw_desired_access);

    match nt_create_file(&path, read, write, disposition) {
        Ok(handle) => {
            set_last_error(ERROR_SUCCESS);
            handle
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            INVALID_HANDLE_VALUE
        }
    }
}

pub extern "win64" fn create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *mut c_void,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: Handle,
) -> Handle {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    let path_c = std::ffi::CString::new(path).ok();
    let Some(path_c) = path_c else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    create_file_a(
        path_c.as_ptr(),
        dw_desired_access,
        dw_share_mode,
        lp_security_attributes,
        dw_creation_disposition,
        dw_flags_and_attributes,
        h_template_file,
    )
}

pub extern "win64" fn create_directory_a(
    lp_path_name: *const i8,
    _lp_security_attributes: *mut c_void,
) -> i32 {
    let Some(path) = (unsafe { c_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let host_path = path.replace('\\', "/");
    match std::fs::create_dir(&host_path) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            set_last_error(ERROR_ALREADY_EXISTS);
            0
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            set_last_error(ERROR_PATH_NOT_FOUND);
            0
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn create_directory_w(
    lp_path_name: *const u16,
    lp_security_attributes: *mut c_void,
) -> i32 {
    let Some(path) = (unsafe { wide_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(path_c) = std::ffi::CString::new(path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    create_directory_a(path_c.as_ptr(), lp_security_attributes)
}

pub extern "win64" fn remove_directory_a(lp_path_name: *const i8) -> i32 {
    let Some(path) = (unsafe { c_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let host_path = normalize_host_path(&path);
    match std::fs::remove_dir(&host_path) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            set_last_error(ERROR_PATH_NOT_FOUND);
            0
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn remove_directory_w(lp_path_name: *const u16) -> i32 {
    let Some(path) = (unsafe { wide_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(path_c) = std::ffi::CString::new(path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    remove_directory_a(path_c.as_ptr())
}

pub extern "win64" fn delete_file_a(lp_file_name: *const i8) -> i32 {
    let Some(path) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    match std::fs::remove_file(&path) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            set_last_error(ERROR_FILE_NOT_FOUND);
            0
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn delete_file_w(lp_file_name: *const u16) -> i32 {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(path_c) = std::ffi::CString::new(path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    delete_file_a(path_c.as_ptr())
}

pub extern "win64" fn copy_file_a(
    lp_existing_file_name: *const i8,
    lp_new_file_name: *const i8,
    b_fail_if_exists: i32,
) -> i32 {
    let Some(src_path) = (unsafe { c_string(lp_existing_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(dst_path) = (unsafe { c_string(lp_new_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let src_host = normalize_host_path(&src_path);
    let dst_host = normalize_host_path(&dst_path);

    if !std::path::Path::new(&src_host).exists() {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    }

    if b_fail_if_exists != 0 && std::path::Path::new(&dst_host).exists() {
        set_last_error(ERROR_FILE_EXISTS);
        return 0;
    }

    match std::fs::copy(&src_host, &dst_host) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            set_last_error(ERROR_PATH_NOT_FOUND);
            0
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn copy_file_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    b_fail_if_exists: i32,
) -> i32 {
    let Some(src_path) = (unsafe { wide_string(lp_existing_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(dst_path) = (unsafe { wide_string(lp_new_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let Some(src_c) = std::ffi::CString::new(src_path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(dst_c) = std::ffi::CString::new(dst_path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    copy_file_a(src_c.as_ptr(), dst_c.as_ptr(), b_fail_if_exists)
}

pub extern "win64" fn move_file_ex_a(
    lp_existing_file_name: *const i8,
    lp_new_file_name: *const i8,
    dw_flags: u32,
) -> i32 {
    let Some(src_path) = (unsafe { c_string(lp_existing_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(dst_path) = (unsafe { c_string(lp_new_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let src_host = normalize_host_path(&src_path);
    let dst_host = normalize_host_path(&dst_path);

    let src = std::path::Path::new(&src_host);
    let dst = std::path::Path::new(&dst_host);

    if !src.exists() {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    }

    if dst.exists() {
        if (dw_flags & MOVEFILE_REPLACE_EXISTING) == 0 {
            set_last_error(ERROR_ALREADY_EXISTS);
            return 0;
        }

        let remove_result =
            if dst.is_dir() { std::fs::remove_dir_all(dst) } else { std::fs::remove_file(dst) };
        if remove_result.is_err() {
            set_last_error(ERROR_ACCESS_DENIED);
            return 0;
        }
    }

    match std::fs::rename(src, dst) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            // Cross-device move fallback for regular files.
            if std::fs::copy(src, dst).is_ok() && std::fs::remove_file(src).is_ok() {
                set_last_error(ERROR_SUCCESS);
                1
            } else {
                set_last_error(ERROR_ACCESS_DENIED);
                0
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            set_last_error(ERROR_PATH_NOT_FOUND);
            0
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn move_file_ex_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    dw_flags: u32,
) -> i32 {
    let Some(src_path) = (unsafe { wide_string(lp_existing_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(dst_path) = (unsafe { wide_string(lp_new_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let Some(src_c) = std::ffi::CString::new(src_path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(dst_c) = std::ffi::CString::new(dst_path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    move_file_ex_a(src_c.as_ptr(), dst_c.as_ptr(), dw_flags)
}

pub extern "win64" fn move_file_a(
    lp_existing_file_name: *const i8,
    lp_new_file_name: *const i8,
) -> i32 {
    move_file_ex_a(lp_existing_file_name, lp_new_file_name, 0)
}

pub extern "win64" fn move_file_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
) -> i32 {
    move_file_ex_w(lp_existing_file_name, lp_new_file_name, 0)
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn replace_file_a(
    lp_replaced_file_name: *const i8,
    lp_replacement_file_name: *const i8,
    lp_backup_file_name: *const i8,
    _dw_replace_flags: u32,
    _lp_exclude: *mut c_void,
    _lp_reserved: *mut c_void,
) -> i32 {
    let Some(replaced_path) = (unsafe { c_string(lp_replaced_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(replacement_path) = (unsafe { c_string(lp_replacement_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let replaced_host = normalize_host_path(&replaced_path);
    let replacement_host = normalize_host_path(&replacement_path);
    let replaced = std::path::Path::new(&replaced_host);
    let replacement = std::path::Path::new(&replacement_host);

    if !replaced.exists() || !replacement.exists() {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    }

    if !lp_backup_file_name.is_null() {
        if let Some(backup_path) = unsafe { c_string(lp_backup_file_name) } {
            let backup_host = normalize_host_path(&backup_path);
            if std::fs::copy(replaced, &backup_host).is_err() {
                set_last_error(ERROR_ACCESS_DENIED);
                return 0;
            }
        }
    }

    if std::fs::remove_file(replaced).is_err() {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }

    match std::fs::rename(replacement, replaced) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            if std::fs::copy(replacement, replaced).is_ok()
                && std::fs::remove_file(replacement).is_ok()
            {
                set_last_error(ERROR_SUCCESS);
                1
            } else {
                set_last_error(ERROR_ACCESS_DENIED);
                0
            }
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn replace_file_w(
    lp_replaced_file_name: *const u16,
    lp_replacement_file_name: *const u16,
    lp_backup_file_name: *const u16,
    dw_replace_flags: u32,
    lp_exclude: *mut c_void,
    lp_reserved: *mut c_void,
) -> i32 {
    let Some(replaced_path) = (unsafe { wide_string(lp_replaced_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(replacement_path) = (unsafe { wide_string(lp_replacement_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let backup_c = if lp_backup_file_name.is_null() {
        None
    } else {
        match unsafe { wide_string(lp_backup_file_name) } {
            Some(path) => std::ffi::CString::new(path).ok(),
            None => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    };

    let Some(replaced_c) = std::ffi::CString::new(replaced_path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(replacement_c) = std::ffi::CString::new(replacement_path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    replace_file_a(
        replaced_c.as_ptr(),
        replacement_c.as_ptr(),
        backup_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        dw_replace_flags,
        lp_exclude,
        lp_reserved,
    )
}

pub extern "win64" fn get_temp_path_w(n_buffer_length: u32, lp_buffer: *mut u16) -> u32 {
    if lp_buffer.is_null() || n_buffer_length == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let path = temp_dir_windows_path();
    let wide: Vec<u16> = path.encode_utf16().collect();
    let required = wide.len() + 1;

    if required > n_buffer_length as usize {
        set_last_error(ERROR_INVALID_PARAMETER);
        return required as u32;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_buffer, wide.len());
        *lp_buffer.add(wide.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    wide.len() as u32
}

pub extern "win64" fn get_temp_path_a(n_buffer_length: u32, lp_buffer: *mut i8) -> u32 {
    if lp_buffer.is_null() || n_buffer_length == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let path = temp_dir_windows_path();
    let bytes = path.as_bytes();
    let required = bytes.len() + 1;
    if required > n_buffer_length as usize {
        set_last_error(ERROR_INVALID_PARAMETER);
        return required as u32;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer.cast::<u8>(), bytes.len());
        *lp_buffer.add(bytes.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    bytes.len() as u32
}

pub extern "win64" fn get_temp_file_name_w(
    lp_path_name: *const u16,
    lp_prefix_string: *const u16,
    u_unique: u32,
    lp_temp_file_name: *mut u16,
) -> u32 {
    if lp_path_name.is_null() || lp_temp_file_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let Some(base_path) = (unsafe { wide_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let prefix = (unsafe { wide_string(lp_prefix_string) }).unwrap_or_else(|| "TMP".to_string());
    let prefix = prefix.chars().take(3).collect::<String>();

    let mut attempt = if u_unique == 0 { next_temp_unique() } else { u_unique };
    let mut generated = None;

    for _ in 0..1024 {
        let file_name = format!("{}{:04X}.tmp", prefix, attempt & 0xFFFF);
        let mut full = base_path.clone();
        if !full.ends_with('\\') && !full.ends_with('/') {
            full.push('\\');
        }
        full.push_str(&file_name);
        let host_path = full.replace('\\', "/");

        match std::fs::OpenOptions::new().write(true).create_new(true).open(&host_path) {
            Ok(_) => {
                generated = Some((attempt, full));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && u_unique == 0 => {
                attempt = attempt.wrapping_add(1);
            }
            Err(_) => {
                set_last_error(ERROR_ACCESS_DENIED);
                return 0;
            }
        }
    }

    let Some((result_unique, full)) = generated else {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    };

    let wide: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_temp_file_name, wide.len());
    }
    set_last_error(ERROR_SUCCESS);
    result_unique
}

pub extern "win64" fn get_temp_file_name_a(
    lp_path_name: *const i8,
    lp_prefix_string: *const i8,
    u_unique: u32,
    lp_temp_file_name: *mut i8,
) -> u32 {
    if lp_path_name.is_null() || lp_temp_file_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let Some(base_path) = (unsafe { c_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let prefix = (unsafe { c_string(lp_prefix_string) }).unwrap_or_else(|| "TMP".to_string());
    let prefix = prefix.chars().take(3).collect::<String>();

    let mut attempt = if u_unique == 0 { next_temp_unique() } else { u_unique };
    let mut generated = None;

    for _ in 0..1024 {
        let file_name = format!("{}{:04X}.tmp", prefix, attempt & 0xFFFF);
        let mut full = base_path.clone();
        if !full.ends_with('\\') && !full.ends_with('/') {
            full.push('\\');
        }
        full.push_str(&file_name);
        let host_path = full.replace('\\', "/");

        match std::fs::OpenOptions::new().write(true).create_new(true).open(&host_path) {
            Ok(_) => {
                generated = Some((attempt, full));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && u_unique == 0 => {
                attempt = attempt.wrapping_add(1);
            }
            Err(_) => {
                set_last_error(ERROR_ACCESS_DENIED);
                return 0;
            }
        }
    }

    let Some((result_unique, full)) = generated else {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    };

    let bytes = full.into_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_temp_file_name.cast::<u8>(), bytes.len());
        *lp_temp_file_name.add(bytes.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    result_unique
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_disk_free_space_ex_w(
    lp_directory_name: *const u16,
    lp_free_bytes_available_to_caller: *mut u64,
    lp_total_number_of_bytes: *mut u64,
    lp_total_number_of_free_bytes: *mut u64,
) -> i32 {
    let path = if lp_directory_name.is_null() {
        None
    } else {
        let Some(path) = (unsafe { wide_string(lp_directory_name) }) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        Some(path)
    };

    match disk_space_for_path(path.as_deref()) {
        Ok((_block_size, total_bytes, free_bytes_avail, free_bytes_total)) => {
            unsafe {
                if !lp_free_bytes_available_to_caller.is_null() {
                    *lp_free_bytes_available_to_caller = free_bytes_avail;
                }
                if !lp_total_number_of_bytes.is_null() {
                    *lp_total_number_of_bytes = total_bytes;
                }
                if !lp_total_number_of_free_bytes.is_null() {
                    *lp_total_number_of_free_bytes = free_bytes_total;
                }
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) => {
            set_last_error(err);
            0
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_disk_free_space_ex_a(
    lp_directory_name: *const i8,
    lp_free_bytes_available_to_caller: *mut u64,
    lp_total_number_of_bytes: *mut u64,
    lp_total_number_of_free_bytes: *mut u64,
) -> i32 {
    let path = if lp_directory_name.is_null() {
        None
    } else {
        let Some(path) = (unsafe { c_string(lp_directory_name) }) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        Some(path)
    };

    match disk_space_for_path(path.as_deref()) {
        Ok((_block_size, total_bytes, free_bytes_avail, free_bytes_total)) => {
            unsafe {
                if !lp_free_bytes_available_to_caller.is_null() {
                    *lp_free_bytes_available_to_caller = free_bytes_avail;
                }
                if !lp_total_number_of_bytes.is_null() {
                    *lp_total_number_of_bytes = total_bytes;
                }
                if !lp_total_number_of_free_bytes.is_null() {
                    *lp_total_number_of_free_bytes = free_bytes_total;
                }
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) => {
            set_last_error(err);
            0
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_disk_free_space_w(
    lp_root_path_name: *const u16,
    lp_sectors_per_cluster: *mut u32,
    lp_bytes_per_sector: *mut u32,
    lp_number_of_free_clusters: *mut u32,
    lp_total_number_of_clusters: *mut u32,
) -> i32 {
    let path = if lp_root_path_name.is_null() {
        None
    } else {
        let Some(path) = (unsafe { wide_string(lp_root_path_name) }) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        Some(path)
    };

    match disk_space_for_path(path.as_deref()) {
        Ok((block_size, total_bytes, free_bytes_avail, _free_bytes_total)) => {
            let bytes_per_sector = 512u64;
            let sectors_per_cluster = (block_size / bytes_per_sector).max(1);
            let cluster_size = sectors_per_cluster.saturating_mul(bytes_per_sector);
            let free_clusters = (free_bytes_avail / cluster_size).min(u32::MAX as u64) as u32;
            let total_clusters = (total_bytes / cluster_size).min(u32::MAX as u64) as u32;

            unsafe {
                if !lp_sectors_per_cluster.is_null() {
                    *lp_sectors_per_cluster = sectors_per_cluster.min(u32::MAX as u64) as u32;
                }
                if !lp_bytes_per_sector.is_null() {
                    *lp_bytes_per_sector = bytes_per_sector as u32;
                }
                if !lp_number_of_free_clusters.is_null() {
                    *lp_number_of_free_clusters = free_clusters;
                }
                if !lp_total_number_of_clusters.is_null() {
                    *lp_total_number_of_clusters = total_clusters;
                }
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) => {
            set_last_error(err);
            0
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_disk_free_space_a(
    lp_root_path_name: *const i8,
    lp_sectors_per_cluster: *mut u32,
    lp_bytes_per_sector: *mut u32,
    lp_number_of_free_clusters: *mut u32,
    lp_total_number_of_clusters: *mut u32,
) -> i32 {
    let path = if lp_root_path_name.is_null() {
        None
    } else {
        let Some(path) = (unsafe { c_string(lp_root_path_name) }) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        Some(path)
    };

    let mut sectors_per_cluster = 0u32;
    let mut bytes_per_sector = 0u32;
    let mut free_clusters = 0u32;
    let mut total_clusters = 0u32;

    let wide_path: Option<Vec<u16>> =
        path.as_deref().map(|p| p.encode_utf16().chain(std::iter::once(0)).collect());

    let ok = get_disk_free_space_w(
        wide_path.as_ref().map_or(std::ptr::null(), |w| w.as_ptr()),
        &mut sectors_per_cluster,
        &mut bytes_per_sector,
        &mut free_clusters,
        &mut total_clusters,
    );

    if ok == 0 {
        return 0;
    }

    unsafe {
        if !lp_sectors_per_cluster.is_null() {
            *lp_sectors_per_cluster = sectors_per_cluster;
        }
        if !lp_bytes_per_sector.is_null() {
            *lp_bytes_per_sector = bytes_per_sector;
        }
        if !lp_number_of_free_clusters.is_null() {
            *lp_number_of_free_clusters = free_clusters;
        }
        if !lp_total_number_of_clusters.is_null() {
            *lp_total_number_of_clusters = total_clusters;
        }
    }
    1
}

pub extern "win64" fn close_handle(handle: Handle) -> i32 {
    init_global_table();
    if global_table().close_handle(handle) {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        0
    }
}

pub extern "win64" fn get_file_type(handle: Handle) -> u32 {
    if matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR) {
        set_last_error(ERROR_SUCCESS);
        return FILE_TYPE_CHAR;
    }

    if handle == INVALID_HANDLE_VALUE || !global_table().is_valid(handle) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }

    set_last_error(ERROR_SUCCESS);
    FILE_TYPE_DISK
}

pub extern "win64" fn get_file_size_ex(handle: Handle, lp_file_size: *mut i64) -> i32 {
    if lp_file_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    match nt_query_information_file(handle) {
        Ok(info) => {
            unsafe {
                *lp_file_size = info.file_size as i64;
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    }
}

pub extern "win64" fn set_file_pointer_ex(
    handle: Handle,
    li_distance_to_move: i64,
    lp_new_file_pointer: *mut i64,
    dw_move_method: u32,
) -> i32 {
    match nt_set_file_pointer_ex(handle, li_distance_to_move, dw_move_method) {
        Ok(new_pos) => {
            if !lp_new_file_pointer.is_null() {
                unsafe {
                    *lp_new_file_pointer = new_pos as i64;
                }
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    }
}

pub extern "win64" fn set_file_pointer(
    handle: Handle,
    l_distance_to_move: i32,
    lp_distance_to_move_high: *mut i32,
    dw_move_method: u32,
) -> u32 {
    let high = if lp_distance_to_move_high.is_null() {
        0i64
    } else {
        unsafe { *lp_distance_to_move_high as i64 }
    };
    let distance = ((high << 32) | (l_distance_to_move as u32 as i64)) as i64;

    match nt_set_file_pointer_ex(handle, distance, dw_move_method) {
        Ok(new_pos) => {
            if !lp_distance_to_move_high.is_null() {
                unsafe {
                    *lp_distance_to_move_high = ((new_pos >> 32) & 0xFFFF_FFFF) as i32;
                }
            }
            set_last_error(ERROR_SUCCESS);
            (new_pos & 0xFFFF_FFFF) as u32
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            INVALID_SET_FILE_POINTER
        }
    }
}

pub extern "win64" fn flush_file_buffers(handle: Handle) -> i32 {
    if matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR) {
        set_last_error(ERROR_SUCCESS);
        return 1;
    }

    let mut result = None;
    global_table().with(handle, |obj| {
        if let Some(file) = obj.as_any().downcast_ref::<crate::nt_kernel::file::FileHandle>() {
            let rc = unsafe { libc::fsync(file.fd) };
            result = Some(rc == 0);
        }
    });

    match result {
        Some(true) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Some(false) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

pub extern "win64" fn set_end_of_file(handle: Handle) -> i32 {
    let current = match nt_set_file_pointer_ex(handle, 0, 1) {
        Ok(pos) => pos,
        Err(status) => {
            set_last_error(status_to_win_error(status));
            return 0;
        }
    };

    let status = nt_set_information_file(handle, SetFileInformation::SetEndOfFile(current));
    if status == 0 {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(status_to_win_error(status));
        0
    }
}

pub extern "win64" fn set_file_time(
    handle: Handle,
    _lp_creation_time: *const c_void,
    _lp_last_access_time: *const c_void,
    _lp_last_write_time: *const c_void,
) -> i32 {
    match nt_query_information_file(handle) {
        Ok(_) => {
            // Compatibility shim: validate handle and report success.
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    }
}

pub extern "win64" fn get_file_attributes_a(lp_file_name: *const i8) -> u32 {
    let Some(path) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FILE_ATTRIBUTE_INVALID;
    };

    match nt_query_information_by_path(&path) {
        Ok(info) => {
            set_last_error(ERROR_SUCCESS);
            if info.is_directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            }
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            FILE_ATTRIBUTE_INVALID
        }
    }
}

pub extern "win64" fn get_file_attributes_w(lp_file_name: *const u16) -> u32 {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FILE_ATTRIBUTE_INVALID;
    };
    let path_c = std::ffi::CString::new(path).ok();
    let Some(path_c) = path_c else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FILE_ATTRIBUTE_INVALID;
    };
    get_file_attributes_a(path_c.as_ptr())
}

pub extern "win64" fn set_file_attributes_a(
    lp_file_name: *const i8,
    _dw_file_attributes: u32,
) -> i32 {
    let Some(path) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    match nt_query_information_by_path(&path) {
        Ok(_) => {
            // Most callers only need this to succeed; attribute persistence can be added later.
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    }
}

pub extern "win64" fn set_file_attributes_w(
    lp_file_name: *const u16,
    dw_file_attributes: u32,
) -> i32 {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(path_c) = std::ffi::CString::new(path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    set_file_attributes_a(path_c.as_ptr(), dw_file_attributes)
}

pub extern "win64" fn get_file_attributes_ex_a(
    lp_file_name: *const i8,
    f_info_level_id: u32,
    lp_file_information: *mut c_void,
) -> i32 {
    if lp_file_information.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if f_info_level_id != GET_FILEEX_INFO_STANDARD {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let Some(path) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    match nt_query_information_by_path(&path) {
        Ok(info) => {
            write_attribute_data(info, lp_file_information);
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    }
}

pub extern "win64" fn get_file_attributes_ex_w(
    lp_file_name: *const u16,
    f_info_level_id: u32,
    lp_file_information: *mut c_void,
) -> i32 {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Some(path_c) = std::ffi::CString::new(path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    get_file_attributes_ex_a(path_c.as_ptr(), f_info_level_id, lp_file_information)
}

pub extern "win64" fn find_first_file_a(
    lp_file_name: *const i8,
    lp_find_file_data: *mut c_void,
) -> Handle {
    if lp_find_file_data.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    let Some(path) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };

    let directory = path.trim_end_matches(['\\', '/']);
    let Ok(entries) = nt_create_file(directory, true, false, CreateDisposition::OpenExisting)
        .and_then(nt_query_directory_file)
    else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };

    let mut names: Vec<String> = entries.into_iter().map(|e| e.file_name).collect();
    names.sort();
    if names.is_empty() {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    let first = names[0].clone();
    let bytes = first.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_find_file_data as *mut u8, bytes.len());
        *((lp_find_file_data as *mut u8).add(bytes.len())) = 0;
    }

    let handle = global_table()
        .alloc(Box::new(FindFileHandle { entries: names, cursor: AtomicUsize::new(1) }));
    set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn find_first_file_w(
    lp_file_name: *const u16,
    lp_find_file_data: *mut c_void,
) -> Handle {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };

    let Some(path_c) = std::ffi::CString::new(path).ok() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };

    find_first_file_a(path_c.as_ptr(), lp_find_file_data)
}

pub extern "win64" fn find_next_file_a(handle: Handle, lp_find_file_data: *mut c_void) -> i32 {
    if lp_find_file_data.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut output: Option<Result<String, u32>> = None;
    global_table().with(handle, |obj| {
        if let Some(find) = obj.as_any().downcast_ref::<FindFileHandle>() {
            let idx = find.cursor.load(Ordering::Relaxed);
            if idx >= find.entries.len() {
                output = Some(Err(ERROR_NO_MORE_FILES));
            } else {
                output = Some(Ok(find.entries[idx].clone()));
                find.cursor.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            output = Some(Err(ERROR_INVALID_HANDLE));
        }
    });

    match output {
        Some(Ok(name)) => {
            let bytes = name.as_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    lp_find_file_data as *mut u8,
                    bytes.len(),
                );
                *((lp_find_file_data as *mut u8).add(bytes.len())) = 0;
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        Some(Err(err)) => {
            set_last_error(err);
            0
        }
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

pub extern "win64" fn find_next_file_w(handle: Handle, lp_find_file_data: *mut c_void) -> i32 {
    find_next_file_a(handle, lp_find_file_data)
}

pub extern "win64" fn find_close(handle: Handle) -> i32 {
    close_handle(handle)
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn find_first_file_ex_w(
    lp_file_name: *const u16,
    _f_info_level_id: i32,
    lp_find_file_data: *mut c_void,
    _f_search_op: i32,
    _lp_search_filter: *mut c_void,
    _dw_additional_flags: u32,
) -> Handle {
    find_first_file_w(lp_file_name, lp_find_file_data)
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn find_first_file_ex_a(
    lp_file_name: *const i8,
    _f_info_level_id: i32,
    lp_find_file_data: *mut c_void,
    _f_search_op: i32,
    _lp_search_filter: *mut c_void,
    _dw_additional_flags: u32,
) -> Handle {
    find_first_file_a(lp_file_name, lp_find_file_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn create_file_and_get_size() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let p = temp.path().join("k32_size.txt");
        std::fs::write(&p, b"abcd").expect("seed");
        let c = std::ffi::CString::new(p.to_string_lossy().to_string()).expect("cstring");

        let handle = create_file_a(c.as_ptr(), 0x8000_0000, 0, std::ptr::null_mut(), 3, 0, 0);
        assert_ne!(handle, INVALID_HANDLE_VALUE);

        let mut size = 0i64;
        assert_eq!(get_file_size_ex(handle, &mut size as *mut i64), 1);
        assert_eq!(size, 4);
        assert_eq!(close_handle(handle), 1);
    }

    #[test]
    fn get_file_attributes_for_file_and_dir() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("dir1");
        let file = temp.path().join("file1.txt");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(&file, b"x").expect("write");

        let dir_c = std::ffi::CString::new(dir.to_string_lossy().to_string()).expect("cstring");
        let file_c = std::ffi::CString::new(file.to_string_lossy().to_string()).expect("cstring");

        assert_eq!(get_file_attributes_a(dir_c.as_ptr()), FILE_ATTRIBUTE_DIRECTORY);
        assert_eq!(get_file_attributes_a(file_c.as_ptr()), FILE_ATTRIBUTE_NORMAL);
    }

    #[test]
    fn find_first_and_next_enumerate_entries() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("a.txt"), b"a").expect("a");
        std::fs::write(temp.path().join("b.txt"), b"b").expect("b");
        let dir_c =
            std::ffi::CString::new(temp.path().to_string_lossy().to_string()).expect("cstring");

        let mut buf = [0u8; 260];
        let handle = find_first_file_a(dir_c.as_ptr(), buf.as_mut_ptr() as *mut c_void);
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let first = std::ffi::CStr::from_bytes_until_nul(&buf)
            .expect("first nul")
            .to_str()
            .expect("utf8")
            .to_string();
        assert!(!first.is_empty());

        let mut buf2 = [0u8; 260];
        let next_ok = find_next_file_a(handle, buf2.as_mut_ptr() as *mut c_void);
        assert_eq!(next_ok, 1);
        assert_eq!(find_close(handle), 1);
    }

    #[test]
    fn get_file_type_reports_char_for_std_and_unknown_for_invalid() {
        assert_eq!(get_file_type(PSEUDO_STDOUT), FILE_TYPE_CHAR);
        assert_eq!(get_file_type(INVALID_HANDLE_VALUE), FILE_TYPE_UNKNOWN);
    }

    #[test]
    fn flush_file_buffers_on_stdio_is_success() {
        assert_eq!(flush_file_buffers(PSEUDO_STDOUT), 1);
    }

    #[test]
    fn set_end_of_file_truncates_to_current_pointer() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let p = temp.path().join("k32_set_eof.bin");
        std::fs::write(&p, b"abcdef").expect("seed file");
        let c = std::ffi::CString::new(p.to_string_lossy().to_string()).expect("cstring");

        let handle = create_file_a(c.as_ptr(), 0xC000_0000, 0, std::ptr::null_mut(), 3, 0, 0);
        assert_ne!(handle, INVALID_HANDLE_VALUE);

        let mut new_pos = 0i64;
        assert_eq!(set_file_pointer_ex(handle, 3, &mut new_pos as *mut i64, 0), 1);
        assert_eq!(set_end_of_file(handle), 1);
        assert_eq!(close_handle(handle), 1);

        let bytes = std::fs::read(&p).expect("read truncated file");
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn set_file_pointer_moves_and_reports_position() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let p = temp.path().join("k32_set_file_pointer.bin");
        std::fs::write(&p, b"abcdef").expect("seed file");
        let c = std::ffi::CString::new(p.to_string_lossy().to_string()).expect("cstring");

        let handle = create_file_a(c.as_ptr(), 0x8000_0000, 0, std::ptr::null_mut(), 3, 0, 0);
        assert_ne!(handle, INVALID_HANDLE_VALUE);

        let pos = set_file_pointer(handle, 2, std::ptr::null_mut(), 0);
        assert_eq!(pos, 2);

        assert_eq!(close_handle(handle), 1);
    }

    #[test]
    fn set_file_time_accepts_valid_handle() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let p = temp.path().join("k32_set_file_time.bin");
        std::fs::write(&p, b"x").expect("seed file");
        let c = std::ffi::CString::new(p.to_string_lossy().to_string()).expect("cstring");

        let handle = create_file_a(c.as_ptr(), 0x8000_0000, 0, std::ptr::null_mut(), 3, 0, 0);
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(set_file_time(handle, std::ptr::null(), std::ptr::null(), std::ptr::null()), 1);
        assert_eq!(close_handle(handle), 1);
    }

    #[test]
    fn delete_file_w_removes_existing_file() {
        let file_path = std::env::temp_dir().join("tuxexe-delete-file-w.tmp");
        std::fs::write(&file_path, b"temp").expect("create temp file");

        let wide: Vec<u16> =
            file_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(delete_file_w(wide.as_ptr()), 1);
        assert!(!file_path.exists());
    }

    #[test]
    fn create_directory_w_creates_new_directory() {
        let dir_path = std::env::temp_dir().join("tuxexe-create-directory-w");
        let _ = std::fs::remove_dir_all(&dir_path);

        let wide: Vec<u16> =
            dir_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(create_directory_w(wide.as_ptr(), std::ptr::null_mut()), 1);
        assert!(dir_path.exists());

        std::fs::remove_dir_all(&dir_path).expect("cleanup temp directory");
    }

    #[test]
    fn remove_directory_w_removes_empty_directory() {
        let dir_path = std::env::temp_dir().join("tuxexe-remove-directory-w");
        let _ = std::fs::remove_dir_all(&dir_path);
        std::fs::create_dir_all(&dir_path).expect("create temp directory");

        let wide: Vec<u16> =
            dir_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(remove_directory_w(wide.as_ptr()), 1);
        assert!(!dir_path.exists());
    }

    #[test]
    fn get_temp_file_name_w_creates_file() {
        let base = std::env::temp_dir();
        let base_w: Vec<u16> = base
            .to_string_lossy()
            .replace('/', "\\")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let prefix_w: Vec<u16> = "TUX".encode_utf16().chain(std::iter::once(0)).collect();
        let mut out = vec![0u16; 512];

        let unique = get_temp_file_name_w(base_w.as_ptr(), prefix_w.as_ptr(), 0, out.as_mut_ptr());
        assert_ne!(unique, 0);

        let path = unsafe { from_wide_ptr(out.as_ptr()).expect("temp path") };
        assert!(std::path::Path::new(&path.replace('\\', "/")).exists());
    }

    #[test]
    fn get_file_attributes_ex_w_populates_size() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("attrs-ex.txt");
        std::fs::write(&file, b"abcdef").expect("write attrs-ex");

        let path_w: Vec<u16> =
            file.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let mut data = Win32FileAttributeData::default();

        assert_eq!(
            get_file_attributes_ex_w(
                path_w.as_ptr(),
                GET_FILEEX_INFO_STANDARD,
                (&mut data as *mut Win32FileAttributeData).cast::<c_void>()
            ),
            1
        );
        assert_eq!(data.dw_file_attributes, FILE_ATTRIBUTE_NORMAL);
        let size = ((data.n_file_size_high as u64) << 32) | (data.n_file_size_low as u64);
        assert_eq!(size, 6);
    }

    #[test]
    fn set_file_attributes_w_succeeds_for_existing_file() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("set-attrs.txt");
        std::fs::write(&file, b"x").expect("write");

        let path_w: Vec<u16> =
            file.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(set_file_attributes_w(path_w.as_ptr(), FILE_ATTRIBUTE_NORMAL), 1);
    }

    #[test]
    fn get_disk_free_space_ex_w_reports_positive_totals() {
        let base = std::env::temp_dir();
        let base_w: Vec<u16> = base
            .to_string_lossy()
            .replace('/', "\\")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut free_avail = 0u64;
        let mut total = 0u64;
        let mut free_total = 0u64;
        assert_eq!(
            get_disk_free_space_ex_w(base_w.as_ptr(), &mut free_avail, &mut total, &mut free_total),
            1
        );
        assert!(total > 0);
        assert!(free_avail > 0);
        assert!(free_total > 0);
    }

    #[test]
    fn copy_file_w_copies_contents() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("copy-src.txt");
        let dst = temp.path().join("copy-dst.txt");
        std::fs::write(&src, b"copy-me").expect("write source");

        let src_w: Vec<u16> =
            src.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let dst_w: Vec<u16> =
            dst.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

        assert_eq!(copy_file_w(src_w.as_ptr(), dst_w.as_ptr(), 0), 1);
        assert_eq!(std::fs::read(&dst).expect("read copied file"), b"copy-me");
    }

    #[test]
    fn copy_file_w_fail_if_exists_returns_error() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("copy-src-existing.txt");
        let dst = temp.path().join("copy-dst-existing.txt");
        std::fs::write(&src, b"source").expect("write source");
        std::fs::write(&dst, b"dest").expect("write destination");

        let src_w: Vec<u16> =
            src.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let dst_w: Vec<u16> =
            dst.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

        assert_eq!(copy_file_w(src_w.as_ptr(), dst_w.as_ptr(), 1), 0);
        assert_eq!(super::super::error::get_last_error(), ERROR_FILE_EXISTS);
    }

    #[test]
    fn move_file_ex_w_renames_file() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("move-src.txt");
        let dst = temp.path().join("move-dst.txt");
        std::fs::write(&src, b"move-me").expect("write source");

        let src_w: Vec<u16> =
            src.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let dst_w: Vec<u16> =
            dst.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

        assert_eq!(move_file_ex_w(src_w.as_ptr(), dst_w.as_ptr(), 0), 1);
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dst).expect("read moved file"), b"move-me");
    }

    #[test]
    fn move_file_ex_w_replace_existing_obeys_flag() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("move-src-replace.txt");
        let dst = temp.path().join("move-dst-replace.txt");
        std::fs::write(&src, b"new").expect("write source");
        std::fs::write(&dst, b"old").expect("write destination");

        let src_w: Vec<u16> =
            src.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let dst_w: Vec<u16> =
            dst.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

        assert_eq!(move_file_ex_w(src_w.as_ptr(), dst_w.as_ptr(), 0), 0);
        assert_eq!(super::super::error::get_last_error(), ERROR_ALREADY_EXISTS);
        assert_eq!(std::fs::read(&dst).expect("read destination"), b"old");

        assert_eq!(move_file_ex_w(src_w.as_ptr(), dst_w.as_ptr(), MOVEFILE_REPLACE_EXISTING), 1);
        assert_eq!(std::fs::read(&dst).expect("read replaced destination"), b"new");
    }

    #[test]
    fn replace_file_w_swaps_contents_and_optionally_writes_backup() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let replaced = temp.path().join("replace-target.txt");
        let replacement = temp.path().join("replace-source.txt");
        let backup = temp.path().join("replace-backup.txt");

        std::fs::write(&replaced, b"old").expect("write target");
        std::fs::write(&replacement, b"new").expect("write replacement");

        let replaced_w: Vec<u16> =
            replaced.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let replacement_w: Vec<u16> =
            replacement.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let backup_w: Vec<u16> =
            backup.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

        assert_eq!(
            replace_file_w(
                replaced_w.as_ptr(),
                replacement_w.as_ptr(),
                backup_w.as_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            1
        );

        assert_eq!(std::fs::read(&replaced).expect("read replaced file"), b"new");
        assert_eq!(std::fs::read(&backup).expect("read backup file"), b"old");
        assert!(!replacement.exists());
    }
}
