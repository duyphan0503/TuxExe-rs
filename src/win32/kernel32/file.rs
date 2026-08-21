#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! WriteFile/ReadFile plus core CreateFile/FindFirst/FindNext support.

use crate::nt_kernel::file::{
    nt_create_file, nt_query_directory_file, nt_query_information_by_path,
    nt_query_information_file, nt_read_file, nt_read_file_at, nt_set_file_pointer_ex,
    nt_set_information_file, nt_write_file, CreateDisposition, FileHandle, SetFileInformation,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::nt_kernel::sync as nt_sync;
use crate::utils::{
    handle::{
        global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE, PSEUDO_STDERR,
        PSEUDO_STDIN, PSEUDO_STDOUT,
    },
    wide_string::from_wide_ptr,
};
use std::ffi::{c_void, CStr};
use std::path::PathBuf;
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
pub const ERROR_IO_INCOMPLETE: u32 = 996;
pub const ERROR_IO_PENDING: u32 = 997;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_LOCK_VIOLATION: u32 = 33;
pub const ERROR_NOT_FOUND: u32 = 1168;
pub const GET_FILEEX_INFO_STANDARD: u32 = 0;

const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;

pub const FILE_TYPE_UNKNOWN: u32 = 0;
pub const FILE_TYPE_DISK: u32 = 1;
pub const FILE_TYPE_CHAR: u32 = 2;
pub const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;

pub extern "win64" fn DeviceIoControl(
    _h_device: usize,
    _dw_io_control_code: u32,
    _lp_in_buffer: *const c_void,
    _n_in_buffer_size: u32,
    _lp_out_buffer: *mut c_void,
    _n_out_buffer_size: u32,
    lp_bytes_returned: *mut u32,
    _lp_overlapped: *const c_void,
) -> i32 {
    if !lp_bytes_returned.is_null() {
        unsafe {
            *lp_bytes_returned = 0;
        }
    }
    set_last_error(ERROR_SUCCESS);
    1
}

const DRIVE_UNKNOWN: u32 = 0;
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

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
    static DRIVES_AND_FOLDERS: std::sync::OnceLock<(
        crate::filesystem::drives::DriveMap,
        crate::filesystem::path::SpecialFolders,
    )> = std::sync::OnceLock::new();
    let (drives, special) = DRIVES_AND_FOLDERS.get_or_init(|| {
        (
            crate::filesystem::drives::DriveMap::default(),
            crate::filesystem::path::SpecialFolders::from_host_env(),
        )
    });
    crate::filesystem::path::windows_to_host(path, drives, special)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.replace('\\', "/"))
}

pub(crate) fn resolve_host_path_for_read(path: &str) -> Option<PathBuf> {
    let host_str = normalize_host_path(path);
    let p = PathBuf::from(host_str);
    if p.exists() {
        return Some(p);
    }
    crate::filesystem::case_fold::resolve_case_insensitive(&p)
}

pub(crate) fn resolve_host_path_for_write(path: &str) -> PathBuf {
    let host_str = normalize_host_path(path);
    let p = PathBuf::from(host_str);
    if p.exists() {
        return p;
    }
    if let Some(resolved) = crate::filesystem::case_fold::resolve_case_insensitive(&p) {
        return resolved;
    }
    if let Some(parent) = p.parent() {
        if let Some(actual_parent) = crate::filesystem::case_fold::resolve_case_insensitive(parent)
        {
            if let Some(file_name) = p.file_name() {
                return actual_parent.join(file_name);
            }
        }
    }
    p
}

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with("\\\\")
        || (bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
}

fn to_full_windows_path(path: &str) -> Option<String> {
    if is_windows_absolute_path(path) {
        return Some(path.replace('/', "\\"));
    }

    let normalized = path.replace('\\', "/");
    let input_path = PathBuf::from(&normalized);

    let candidate = if input_path.is_absolute() {
        input_path
    } else {
        std::env::current_dir().ok()?.join(input_path)
    };

    let resolved = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    Some(resolved.to_string_lossy().replace('/', "\\"))
}

fn file_part_index(path: &str) -> usize {
    let mut index = 0usize;
    for (i, b) in path.as_bytes().iter().enumerate() {
        if *b == b'\\' || *b == b'/' {
            index = i + 1;
        }
    }
    index
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

fn change_file_lock(handle: Handle, offset: u64, length: u64, lock_type: libc::c_short) -> i32 {
    let fd = global_table()
        .with(handle, |object| object.as_any().downcast_ref::<FileHandle>().map(|file| file.fd))
        .flatten();
    let Some(fd) = fd else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    let Ok(offset) = libc::off_t::try_from(offset) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Ok(length) = libc::off_t::try_from(length) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = lock_type;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = offset;
    lock.l_len = length;
    if unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) } == 0 {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(ERROR_LOCK_VIOLATION);
        0
    }
}

pub extern "win64" fn lock_file(
    handle: Handle,
    offset_low: u32,
    offset_high: u32,
    length_low: u32,
    length_high: u32,
) -> i32 {
    let offset = ((offset_high as u64) << 32) | offset_low as u64;
    let length = ((length_high as u64) << 32) | length_low as u64;
    change_file_lock(handle, offset, length, libc::F_WRLCK as libc::c_short)
}

pub extern "win64" fn unlock_file(
    handle: Handle,
    offset_low: u32,
    offset_high: u32,
    length_low: u32,
    length_high: u32,
) -> i32 {
    let offset = ((offset_high as u64) << 32) | offset_low as u64;
    let length = ((length_high as u64) << 32) | length_low as u64;
    change_file_lock(handle, offset, length, libc::F_UNLCK as libc::c_short)
}

fn classify_drive(path: Option<&str>) -> u32 {
    let Some(raw) = path.map(str::trim).filter(|p| !p.is_empty()) else {
        return DRIVE_FIXED;
    };

    let normalized = raw.replace('/', "\\");
    if normalized.starts_with("\\\\") {
        return DRIVE_REMOTE;
    }

    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return DRIVE_FIXED;
    }

    DRIVE_NO_ROOT_DIR
}

fn write_optional_wide(buffer: *mut u16, capacity: u32, value: &str) -> Result<(), u32> {
    if buffer.is_null() {
        return if capacity == 0 { Ok(()) } else { Err(ERROR_INVALID_PARAMETER) };
    }
    let wide: Vec<u16> = value.encode_utf16().collect();
    if capacity == 0 || wide.len() + 1 > capacity as usize {
        return Err(ERROR_MORE_DATA);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), buffer, wide.len());
        *buffer.add(wide.len()) = 0;
    }
    Ok(())
}

pub extern "win64" fn get_logical_drives() -> u32 {
    1 << 2 // C:
}

pub extern "win64" fn get_logical_drive_strings_w(buffer_length: u32, buffer: *mut u16) -> u32 {
    // Windows uses a sequence of NUL-terminated roots followed by an extra
    // NUL. TuxExe currently exposes its virtual C: root.
    const DRIVES: [u16; 5] = [b'C' as u16, b':' as u16, b'\\' as u16, 0, 0];
    if buffer_length == 0 || buffer.is_null() {
        return DRIVES.len() as u32;
    }
    if (buffer_length as usize) < DRIVES.len() {
        return DRIVES.len() as u32;
    }
    unsafe { std::ptr::copy_nonoverlapping(DRIVES.as_ptr(), buffer, DRIVES.len()) };
    // Return excludes only the final multi-string terminator.
    (DRIVES.len() - 1) as u32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_volume_information_w(
    root_path_name: *const u16,
    volume_name_buffer: *mut u16,
    volume_name_size: u32,
    volume_serial_number: *mut u32,
    maximum_component_length: *mut u32,
    file_system_flags: *mut u32,
    file_system_name_buffer: *mut u16,
    file_system_name_size: u32,
) -> i32 {
    let root = if root_path_name.is_null() {
        ".".to_string()
    } else {
        match unsafe { from_wide_ptr(root_path_name) } {
            Ok(path) if is_windows_absolute_path(&path) => ".".to_string(),
            Ok(path) => normalize_host_path(&path),
            Err(_) => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    };
    let Ok(root_c) = std::ffi::CString::new(root) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(root_c.as_ptr(), &mut metadata) } != 0 {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    }
    if write_optional_wide(volume_name_buffer, volume_name_size, "TuxExe").is_err()
        || write_optional_wide(file_system_name_buffer, file_system_name_size, "TuxExeFS").is_err()
    {
        set_last_error(ERROR_MORE_DATA);
        return 0;
    }
    if !volume_serial_number.is_null() {
        unsafe { *volume_serial_number = (metadata.st_dev as u64 ^ metadata.st_ino as u64) as u32 };
    }
    if !maximum_component_length.is_null() {
        unsafe { *maximum_component_length = 255 };
    }
    if !file_system_flags.is_null() {
        // FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK.
        unsafe { *file_system_flags = 0x0000_0002 | 0x0000_0004 };
    }
    set_last_error(ERROR_SUCCESS);
    1
}

#[derive(Debug, Clone)]
struct FindEntry {
    file_name: String,
    is_dir: bool,
    file_size: u64,
    modified_unix: i64,
}

#[derive(Debug)]
struct FindFileHandle {
    entries: Vec<FindEntry>,
    cursor: AtomicUsize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Win32FindDataA {
    dw_file_attributes: u32,
    ft_creation_time: FileTime,
    ft_last_access_time: FileTime,
    ft_last_write_time: FileTime,
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u8; 260],
    c_alternate_file_name: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Win32FindDataW {
    dw_file_attributes: u32,
    ft_creation_time: FileTime,
    ft_last_access_time: FileTime,
    ft_last_write_time: FileTime,
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u16; 260],
    c_alternate_file_name: [u16; 14],
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ByHandleFileInformation {
    dw_file_attributes: u32,
    ft_creation_time: FileTime,
    ft_last_access_time: FileTime,
    ft_last_write_time: FileTime,
    dw_volume_serial_number: u32,
    n_file_size_high: u32,
    n_file_size_low: u32,
    n_number_of_links: u32,
    n_file_index_high: u32,
    n_file_index_low: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: Handle,
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
        0xC000_0022 | 0xC000_00BA => ERROR_ACCESS_DENIED,
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
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_APPEND_DATA: u32 = 0x0004;
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

    let read = (dw_desired_access
        & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA | FILE_GENERIC_READ | FILE_ALL_ACCESS))
        != 0
        || dw_desired_access == 0;
    let write = (dw_desired_access
        & (GENERIC_WRITE
            | GENERIC_ALL
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_GENERIC_WRITE
            | FILE_ALL_ACCESS))
        != 0;
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
    number_of_bytes_read: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let mut completed = 0u32;
    let status = if overlapped.is_null() {
        nt_read_file(handle, buffer, number_of_bytes_to_read, Some(&mut completed))
    } else {
        // Windows uses Offset/OffsetHigh as an absolute 64-bit position for
        // overlapped file I/O.  This runtime completes file reads immediately,
        // but must still publish completion data before returning.
        let overlapped = unsafe { &mut *overlapped.cast::<Overlapped>() };
        let offset = u64::from(overlapped.offset) | (u64::from(overlapped.offset_high) << 32);
        let status =
            nt_read_file_at(handle, buffer, number_of_bytes_to_read, offset, Some(&mut completed));
        overlapped.internal = status as usize;
        overlapped.internal_high = completed as usize;
        if overlapped.h_event != 0 {
            // The low bit merely suppresses completion-port notification; it
            // is not part of the event HANDLE itself.
            nt_sync::set_event(overlapped.h_event & !1usize);
        }
        status
    };
    if !number_of_bytes_read.is_null() {
        unsafe {
            *number_of_bytes_read = completed;
        }
    }
    if status == 0 {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(status_to_win_error(status));
        0
    }
}

pub extern "win64" fn get_overlapped_result(
    handle: Handle,
    lp_overlapped: *mut c_void,
    lp_number_of_bytes_transferred: *mut u32,
    b_wait: i32,
) -> i32 {
    if lp_overlapped.is_null() || lp_number_of_bytes_transferred.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let valid_handle = matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR)
        || (handle != INVALID_HANDLE_VALUE && global_table().is_valid(handle));
    if !valid_handle {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let overlapped = lp_overlapped.cast::<Overlapped>();
    let mut internal = unsafe { (*overlapped).internal as u32 };
    if internal == ERROR_IO_PENDING && b_wait != 0 {
        let event = unsafe { (*overlapped).h_event };
        if event != 0 {
            let wait_result = nt_sync::wait_for_single_object(event, nt_sync::INFINITE);
            if wait_result != nt_sync::WAIT_OBJECT_0 {
                set_last_error(ERROR_IO_INCOMPLETE);
                return 0;
            }
        } else {
            let start = std::time::Instant::now();
            loop {
                internal = unsafe { (*overlapped).internal as u32 };
                if internal != ERROR_IO_PENDING {
                    break;
                }
                if start.elapsed() >= std::time::Duration::from_secs(30) {
                    set_last_error(ERROR_IO_INCOMPLETE);
                    return 0;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        internal = unsafe { (*overlapped).internal as u32 };
    }

    if internal == ERROR_IO_PENDING {
        set_last_error(ERROR_IO_INCOMPLETE);
        return 0;
    }
    if internal != ERROR_SUCCESS {
        set_last_error(internal);
        return 0;
    }

    unsafe {
        *lp_number_of_bytes_transferred = (*overlapped).internal_high as u32;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn cancel_io(handle: Handle) -> i32 {
    let valid_handle = matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR)
        || (handle != INVALID_HANDLE_VALUE && global_table().is_valid(handle));
    if !valid_handle {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    // Current runtime performs synchronous host I/O, so there is no pending async IRP to cancel.
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn cancel_io_ex(handle: Handle, _overlapped: *mut c_void) -> i32 {
    let valid_handle = matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR)
        || (handle != INVALID_HANDLE_VALUE && global_table().is_valid(handle));
    if !valid_handle {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // File I/O currently completes synchronously before returning to guest
    // code, so no OVERLAPPED request can remain cancellable.
    set_last_error(ERROR_NOT_FOUND);
    0
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
    tracing::trace!(path = %path, ?read, ?write, "CreateFileA");

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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn create_pipe(
    h_read_pipe: *mut Handle,
    h_write_pipe: *mut Handle,
    _lp_pipe_attributes: *mut c_void,
    _n_size: u32,
) -> i32 {
    if h_read_pipe.is_null() || h_write_pipe.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    init_global_table();

    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }

    let read_handle = global_table().alloc(Box::new(FileHandle {
        fd: fds[0],
        host_path: PathBuf::from("<anonymous-pipe-read>"),
    }));
    let write_handle = global_table().alloc(Box::new(FileHandle {
        fd: fds[1],
        host_path: PathBuf::from("<anonymous-pipe-write>"),
    }));

    unsafe {
        *h_read_pipe = read_handle;
        *h_write_pipe = write_handle;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn create_directory_a(
    lp_path_name: *const i8,
    _lp_security_attributes: *mut c_void,
) -> i32 {
    let Some(path) = (unsafe { c_string(lp_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let host_path = normalize_host_path(&path);
    let host_path_buf = PathBuf::from(&host_path);
    let target = if let Some(parent) = host_path_buf.parent() {
        if let Some(actual_parent) = crate::filesystem::case_fold::resolve_case_insensitive(parent)
        {
            if let Some(name) = host_path_buf.file_name() {
                actual_parent.join(name)
            } else {
                host_path_buf
            }
        } else {
            host_path_buf
        }
    } else {
        host_path_buf
    };
    match std::fs::create_dir(&target) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            set_last_error(ERROR_ALREADY_EXISTS);
            0
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if std::fs::create_dir_all(&target).is_ok() {
                set_last_error(ERROR_SUCCESS);
                return 1;
            }
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

    let Some(host_path) = resolve_host_path_for_read(&path) else {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    match std::fs::remove_file(&host_path) {
        Ok(_) => {
            crate::filesystem::case_fold::record_file_deleted(&host_path);
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

    let Some(src_host) = resolve_host_path_for_read(&src_path) else {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    let dst_host = resolve_host_path_for_write(&dst_path);

    if b_fail_if_exists != 0 && dst_host.exists() {
        set_last_error(ERROR_FILE_EXISTS);
        return 0;
    }

    match std::fs::copy(&src_host, &dst_host) {
        Ok(_) => {
            crate::filesystem::case_fold::record_file_created(&dst_host);
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

pub extern "win64" fn copy_file_ex_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    _lp_progress_routine: usize,
    _lp_data: usize,
    _pb_cancel: *const i32,
    dw_copy_flags: u32,
) -> i32 {
    let fail_if_exists = (dw_copy_flags & 0x0000_0001) != 0;
    copy_file_w(lp_existing_file_name, lp_new_file_name, if fail_if_exists { 1 } else { 0 })
}

pub extern "win64" fn copy_file_ex_a(
    lp_existing_file_name: *const i8,
    lp_new_file_name: *const i8,
    _lp_progress_routine: usize,
    _lp_data: usize,
    _pb_cancel: *const i32,
    dw_copy_flags: u32,
) -> i32 {
    let fail_if_exists = (dw_copy_flags & 0x0000_0001) != 0;
    copy_file_a(lp_existing_file_name, lp_new_file_name, if fail_if_exists { 1 } else { 0 })
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

    let Some(src) = resolve_host_path_for_read(&src_path) else {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    let dst = resolve_host_path_for_write(&dst_path);

    if dst.exists() {
        if (dw_flags & MOVEFILE_REPLACE_EXISTING) == 0 {
            set_last_error(ERROR_ALREADY_EXISTS);
            return 0;
        }

        let remove_result =
            if dst.is_dir() { std::fs::remove_dir_all(&dst) } else { std::fs::remove_file(&dst) };
        if remove_result.is_err() {
            set_last_error(ERROR_ACCESS_DENIED);
            return 0;
        }
        crate::filesystem::case_fold::record_file_deleted(&dst);
    }

    match std::fs::rename(&src, &dst) {
        Ok(_) => {
            crate::filesystem::case_fold::record_file_deleted(&src);
            crate::filesystem::case_fold::record_file_created(&dst);
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            // Cross-device move fallback for regular files.
            if std::fs::copy(&src, &dst).is_ok() && std::fs::remove_file(&src).is_ok() {
                crate::filesystem::case_fold::record_file_deleted(&src);
                crate::filesystem::case_fold::record_file_created(&dst);
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

    let Some(replaced) = resolve_host_path_for_read(&replaced_path) else {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    let Some(replacement) = resolve_host_path_for_read(&replacement_path) else {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };

    if !lp_backup_file_name.is_null() {
        if let Some(backup_path) = unsafe { c_string(lp_backup_file_name) } {
            let backup_host = resolve_host_path_for_write(&backup_path);
            if std::fs::copy(&replaced, &backup_host).is_err() {
                set_last_error(ERROR_ACCESS_DENIED);
                return 0;
            }
            crate::filesystem::case_fold::record_file_created(&backup_host);
        }
    }

    if std::fs::remove_file(&replaced).is_err() {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }

    match std::fs::rename(&replacement, &replaced) {
        Ok(_) => {
            crate::filesystem::case_fold::record_file_deleted(&replacement);
            crate::filesystem::case_fold::record_file_created(&replaced);
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            if std::fs::copy(&replacement, &replaced).is_ok()
                && std::fs::remove_file(&replacement).is_ok()
            {
                crate::filesystem::case_fold::record_file_deleted(&replacement);
                crate::filesystem::case_fold::record_file_created(&replaced);
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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_full_path_name_w(
    lp_file_name: *const u16,
    n_buffer_length: u32,
    lp_buffer: *mut u16,
    lp_file_part: *mut *mut u16,
) -> u32 {
    let Some(input) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let Some(full_path) = to_full_windows_path(&input) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let index = file_part_index(&full_path);
    let wide: Vec<u16> = full_path.encode_utf16().collect();
    let required_with_nul = wide.len() + 1;

    if lp_buffer.is_null() || n_buffer_length == 0 {
        if !lp_file_part.is_null() {
            unsafe {
                *lp_file_part = std::ptr::null_mut();
            }
        }
        set_last_error(ERROR_SUCCESS);
        return required_with_nul as u32;
    }

    if n_buffer_length as usize <= wide.len() {
        if !lp_file_part.is_null() {
            unsafe {
                *lp_file_part = std::ptr::null_mut();
            }
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return required_with_nul as u32;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_buffer, wide.len());
        *lp_buffer.add(wide.len()) = 0;
        if !lp_file_part.is_null() {
            *lp_file_part = lp_buffer.add(index.min(wide.len()));
        }
    }
    set_last_error(ERROR_SUCCESS);
    wide.len() as u32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_full_path_name_a(
    lp_file_name: *const i8,
    n_buffer_length: u32,
    lp_buffer: *mut i8,
    lp_file_part: *mut *mut i8,
) -> u32 {
    let Some(input) = (unsafe { c_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let Some(full_path) = to_full_windows_path(&input) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let index = file_part_index(&full_path);
    let bytes = full_path.as_bytes();
    let required_with_nul = bytes.len() + 1;

    if lp_buffer.is_null() || n_buffer_length == 0 {
        if !lp_file_part.is_null() {
            unsafe {
                *lp_file_part = std::ptr::null_mut();
            }
        }
        set_last_error(ERROR_SUCCESS);
        return required_with_nul as u32;
    }

    if n_buffer_length as usize <= bytes.len() {
        if !lp_file_part.is_null() {
            unsafe {
                *lp_file_part = std::ptr::null_mut();
            }
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return required_with_nul as u32;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer.cast::<u8>(), bytes.len());
        *lp_buffer.add(bytes.len()) = 0;
        if !lp_file_part.is_null() {
            *lp_file_part = lp_buffer.add(index.min(bytes.len()));
        }
    }
    set_last_error(ERROR_SUCCESS);
    bytes.len() as u32
}

pub extern "win64" fn get_long_path_name_w(
    lpsz_short_path: *const u16,
    lpsz_long_path: *mut u16,
    cch_buffer: u32,
) -> u32 {
    if lpsz_short_path.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(path) = (unsafe { wide_string(lpsz_short_path) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let needed = wide.len() as u32;
    if cch_buffer == 0 || lpsz_long_path.is_null() {
        return needed;
    }
    if cch_buffer < needed {
        return needed;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lpsz_long_path, wide.len());
    }
    needed - 1
}

pub extern "win64" fn get_long_path_name_a(
    lpsz_short_path: *const i8,
    lpsz_long_path: *mut i8,
    cch_buffer: u32,
) -> u32 {
    if lpsz_short_path.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(path) = (unsafe { c_string(lpsz_short_path) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let bytes = path.as_bytes();
    let needed = (bytes.len() + 1) as u32;
    if cch_buffer == 0 || lpsz_long_path.is_null() {
        return needed;
    }
    if cch_buffer < needed {
        return needed;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lpsz_long_path as *mut u8, bytes.len());
        *lpsz_long_path.add(bytes.len()) = 0;
    }
    needed - 1
}

pub extern "win64" fn get_short_path_name_w(
    lpsz_long_path: *const u16,
    lpsz_short_path: *mut u16,
    cch_buffer: u32,
) -> u32 {
    get_long_path_name_w(lpsz_long_path, lpsz_short_path, cch_buffer)
}

pub extern "win64" fn get_volume_path_name_w(
    lpsz_file_name: *const u16,
    lpsz_volume_path_name: *mut u16,
    cch_buffer: u32,
) -> i32 {
    if lpsz_file_name.is_null() || lpsz_volume_path_name.is_null() || cch_buffer < 4 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let root = [b'Z' as u16, b':' as u16, b'\\' as u16, 0u16];
    unsafe {
        std::ptr::copy_nonoverlapping(root.as_ptr(), lpsz_volume_path_name, 4);
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn get_final_path_name_by_handle_w(
    h_file: Handle,
    lpsz_file_path: *mut u16,
    cch_file_path: u32,
    _dw_flags: u32,
) -> u32 {
    let mut resolved_path: Option<String> = None;
    global_table().with(h_file, |obj| {
        if let Some(file) = obj.as_any().downcast_ref::<FileHandle>() {
            let win_path = format!("\\\\?\\Z:{}", file.host_path.display()).replace('/', "\\");
            resolved_path = Some(win_path);
        }
    });

    let Some(path) = resolved_path else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let needed = wide.len() as u32;
    if cch_file_path == 0 || lpsz_file_path.is_null() {
        return needed;
    }
    if cch_file_path < needed {
        return needed;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lpsz_file_path, wide.len());
    }
    needed - 1
}

pub extern "win64" fn path_cch_combine_ex(
    psz_path_out: *mut u16,
    cch_path_out: usize,
    psz_path_in: *const u16,
    psz_more: *const u16,
    _dw_flags: u32,
) -> i32 {
    if psz_path_out.is_null() || cch_path_out == 0 {
        return -2147024809;
    }
    let path_in = if !psz_path_in.is_null() {
        unsafe { wide_string(psz_path_in) }.unwrap_or_default()
    } else {
        String::new()
    };
    let more = if !psz_more.is_null() {
        unsafe { wide_string(psz_more) }.unwrap_or_default()
    } else {
        String::new()
    };
    let combined = if path_in.is_empty() {
        more.clone()
    } else if more.is_empty() {
        path_in.clone()
    } else {
        let trimmed_in = path_in.trim_end_matches(['\\', '/']);
        let trimmed_more = more.trim_start_matches(['\\', '/']);
        format!("{}\\{}", trimmed_in, trimmed_more)
    };
    tracing::trace!(%path_in, %more, %combined, "PathCchCombineEx");
    let wide: Vec<u16> = combined.encode_utf16().chain(std::iter::once(0)).collect();
    if wide.len() > cch_path_out {
        return -2147024774;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), psz_path_out, wide.len());
    }
    0
}

pub extern "win64" fn path_cch_skip_root(
    psz_path: *const u16,
    ppsz_root_end: *mut *const u16,
) -> i32 {
    if psz_path.is_null() || ppsz_root_end.is_null() {
        return -2147024809;
    }
    let path = unsafe { wide_string(psz_path) }.unwrap_or_default();
    let mut offset = 0;
    if path.starts_with("\\\\?\\") || path.starts_with("\\\\.\\") {
        offset = 4;
    }
    let rest = &path[offset..];
    let mut found_root = false;
    if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
        offset += 2;
        found_root = true;
        if rest.len() >= 3 && (rest.as_bytes()[2] == b'\\' || rest.as_bytes()[2] == b'/') {
            offset += 1;
        }
    } else if rest.starts_with('\\') || rest.starts_with('/') {
        offset += 1;
        found_root = true;
    }

    unsafe {
        *ppsz_root_end = psz_path.add(offset);
    }
    tracing::trace!(%path, offset, found_root, "PathCchSkipRoot");
    if found_root {
        0
    } else {
        -2147024809 // E_INVALIDARG when no root
    }
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

pub extern "win64" fn get_drive_type_w(lp_root_path_name: *const u16) -> u32 {
    if lp_root_path_name.is_null() {
        return DRIVE_FIXED;
    }

    let Some(path) = (unsafe { wide_string(lp_root_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return DRIVE_UNKNOWN;
    };

    let classification = classify_drive(Some(path.as_str()));
    if classification == DRIVE_NO_ROOT_DIR {
        set_last_error(ERROR_PATH_NOT_FOUND);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    classification
}

pub extern "win64" fn get_drive_type_a(lp_root_path_name: *const i8) -> u32 {
    if lp_root_path_name.is_null() {
        return DRIVE_FIXED;
    }

    let Some(path) = (unsafe { c_string(lp_root_path_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return DRIVE_UNKNOWN;
    };

    let classification = classify_drive(Some(path.as_str()));
    if classification == DRIVE_NO_ROOT_DIR {
        set_last_error(ERROR_PATH_NOT_FOUND);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    classification
}

pub extern "win64" fn close_handle(handle: Handle) -> i32 {
    if handle == crate::nt_kernel::sync::DXVK_FRAME_LATENCY_HANDLE {
        set_last_error(ERROR_SUCCESS);
        return 1;
    }
    init_global_table();
    if global_table().close_handle(handle) {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        0
    }
}

pub extern "win64" fn set_handle_information(
    h_object: Handle,
    _dw_mask: u32,
    _dw_flags: u32,
) -> i32 {
    let valid = matches!(h_object, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR)
        || (h_object != INVALID_HANDLE_VALUE && global_table().is_valid(h_object));

    if !valid {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    // Compatibility shim: handle flag persistence can be layered in later.
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_handle_information(h_object: Handle, lpdw_flags: *mut u32) -> i32 {
    if lpdw_flags.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let valid = matches!(h_object, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR)
        || (h_object != INVALID_HANDLE_VALUE && global_table().is_valid(h_object));

    if !valid {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    unsafe {
        *lpdw_flags = 0;
    }
    set_last_error(ERROR_SUCCESS);
    1
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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn peek_named_pipe(
    _h_named_pipe: Handle,
    _lp_buffer: *mut c_void,
    _n_buffer_size: u32,
    lp_bytes_read: *mut u32,
    lp_total_bytes_avail: *mut u32,
    lp_bytes_left_this_message: *mut u32,
) -> i32 {
    unsafe {
        if !lp_bytes_read.is_null() {
            *lp_bytes_read = 0;
        }
        if !lp_total_bytes_avail.is_null() {
            *lp_total_bytes_avail = 0;
        }
        if !lp_bytes_left_this_message.is_null() {
            *lp_bytes_left_this_message = 0;
        }
    }

    set_last_error(ERROR_INVALID_HANDLE);
    0
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

pub extern "win64" fn get_file_size(handle: Handle, lp_file_size_high: *mut u32) -> u32 {
    let mut size: i64 = 0;
    if get_file_size_ex(handle, &mut size as *mut i64) == 0 {
        return u32::MAX;
    }

    if !lp_file_size_high.is_null() {
        unsafe {
            *lp_file_size_high = ((size as u64 >> 32) & 0xFFFF_FFFF) as u32;
        }
    }

    (size as u64 & 0xFFFF_FFFF) as u32
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
    let distance = if lp_distance_to_move_high.is_null() {
        l_distance_to_move as i64
    } else {
        let high = unsafe { *lp_distance_to_move_high as i64 };
        ((high << 32) | (l_distance_to_move as u32 as i64)) as i64
    };

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

    let is_valid = global_table()
        .with(handle, |obj| {
            obj.as_any().is::<crate::nt_kernel::file::FileHandle>()
                || obj.as_any().is::<crate::utils::handle::StdioHandle>()
        })
        .unwrap_or(false);

    if is_valid {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        0
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
    tracing::trace!(path = %path, "GetFileAttributesA");

    let res = match nt_query_information_by_path(&path) {
        Ok(info) => {
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
    };
    tracing::trace!(path = %path, ?res, "GetFileAttributes");
    res
}

pub extern "win64" fn get_file_attributes_w(lp_file_name: *const u16) -> u32 {
    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
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
    match nt_query_information_by_path(&path) {
        Ok(_) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    }
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

    let res = match nt_query_information_by_path(&path) {
        Ok(info) => {
            write_attribute_data(info, lp_file_information);
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    };
    tracing::trace!(path = %path, ?res, "GetFileAttributesEx");
    res
}

pub extern "win64" fn get_file_attributes_ex_w(
    lp_file_name: *const u16,
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

    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let res = match nt_query_information_by_path(&path) {
        Ok(info) => {
            write_attribute_data(info, lp_file_information);
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(status) => {
            set_last_error(status_to_win_error(status));
            0
        }
    };
    tracing::trace!(path = %path, ?res, "GetFileAttributesEx");
    res
}

pub extern "win64" fn get_file_information_by_handle(
    h_file: Handle,
    lp_file_information: *mut c_void,
) -> i32 {
    if lp_file_information.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    match nt_query_information_file(h_file) {
        Ok(info) => {
            let attributes =
                if info.is_directory { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };

            let out = ByHandleFileInformation {
                dw_file_attributes: attributes,
                ft_creation_time: FileTime::default(),
                ft_last_access_time: unix_seconds_to_filetime(info.last_access_time_unix),
                ft_last_write_time: unix_seconds_to_filetime(info.last_write_time_unix),
                dw_volume_serial_number: 0,
                n_file_size_high: (info.file_size >> 32) as u32,
                n_file_size_low: (info.file_size & 0xFFFF_FFFF) as u32,
                n_number_of_links: 1,
                n_file_index_high: 0,
                n_file_index_low: 0,
            };

            unsafe {
                *lp_file_information.cast::<ByHandleFileInformation>() = out;
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

#[repr(C)]
struct FileBasicInfo {
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    change_time: FileTime,
    file_attributes: u32,
}

#[repr(C)]
struct FileStandardInfo {
    allocation_size: u64,
    end_of_file: u64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

#[repr(C)]
struct FileAttributeTagInfo {
    file_attributes: u32,
    reparse_tag: u32,
}

#[repr(C)]
struct FileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

pub extern "win64" fn get_file_information_by_handle_ex(
    h_file: Handle,
    info_class: u32,
    lp_file_information: *mut c_void,
    dw_buffer_size: u32,
) -> i32 {
    if lp_file_information.is_null() || dw_buffer_size == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let mut file_path: Option<PathBuf> = None;
    let mut got_stat = false;

    global_table().with(h_file, |obj| {
        if let Some(file) = obj.as_any().downcast_ref::<FileHandle>() {
            let rc = unsafe { libc::fstat(file.fd, &mut stat_buf) };
            if rc == 0 {
                got_stat = true;
                file_path = Some(file.host_path.clone());
            }
        }
    });

    if !got_stat {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let is_dir = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let attributes = if is_dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
    let mtime = unix_seconds_to_filetime(stat_buf.st_mtime);
    let atime = unix_seconds_to_filetime(stat_buf.st_atime);

    let res = match info_class {
        // FileBasicInfo = 0
        0 => {
            if dw_buffer_size < std::mem::size_of::<FileBasicInfo>() as u32 {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                0
            } else {
                let info = FileBasicInfo {
                    creation_time: mtime,
                    last_access_time: atime,
                    last_write_time: mtime,
                    change_time: mtime,
                    file_attributes: attributes,
                };
                unsafe {
                    *lp_file_information.cast::<FileBasicInfo>() = info;
                }
                set_last_error(ERROR_SUCCESS);
                1
            }
        }
        // FileStandardInfo = 1
        1 => {
            if dw_buffer_size < std::mem::size_of::<FileStandardInfo>() as u32 {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                0
            } else {
                let info = FileStandardInfo {
                    allocation_size: stat_buf.st_size as u64,
                    end_of_file: stat_buf.st_size as u64,
                    number_of_links: stat_buf.st_nlink as u32,
                    delete_pending: 0,
                    directory: if is_dir { 1 } else { 0 },
                };
                unsafe {
                    *lp_file_information.cast::<FileStandardInfo>() = info;
                }
                set_last_error(ERROR_SUCCESS);
                1
            }
        }
        // FileNameInfo = 2
        2 => {
            let win_path = file_path
                .map(|p| format!("\\{}", p.to_string_lossy()).replace('/', "\\"))
                .unwrap_or_default();
            let wide: Vec<u16> = win_path.encode_utf16().collect();
            let byte_len = (wide.len() * 2) as u32;
            if dw_buffer_size < 4 {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                0
            } else {
                unsafe {
                    *lp_file_information.cast::<u32>() = byte_len;
                    let copy_bytes = (dw_buffer_size - 4).min(byte_len) as usize;
                    std::ptr::copy_nonoverlapping(
                        wide.as_ptr() as *const u8,
                        lp_file_information.add(4).cast::<u8>(),
                        copy_bytes,
                    );
                }
                set_last_error(ERROR_SUCCESS);
                1
            }
        }
        // FileAttributeTagInfo = 9
        9 => {
            if dw_buffer_size < std::mem::size_of::<FileAttributeTagInfo>() as u32 {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                0
            } else {
                let info = FileAttributeTagInfo { file_attributes: attributes, reparse_tag: 0 };
                unsafe {
                    *lp_file_information.cast::<FileAttributeTagInfo>() = info;
                }
                set_last_error(ERROR_SUCCESS);
                1
            }
        }
        // FileIdInfo = 18
        18 => {
            if dw_buffer_size < std::mem::size_of::<FileIdInfo>() as u32 {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                0
            } else {
                let mut file_id = [0u8; 16];
                file_id[..8].copy_from_slice(&(stat_buf.st_ino as u64).to_le_bytes());
                file_id[8..12].copy_from_slice(&(stat_buf.st_dev as u32).to_le_bytes());
                let info = FileIdInfo { volume_serial_number: 0x12345678, file_id };
                unsafe {
                    *lp_file_information.cast::<FileIdInfo>() = info;
                }
                set_last_error(ERROR_SUCCESS);
                1
            }
        }
        _ => {
            tracing::warn!(info_class, "GetFileInformationByHandleEx unhandled class");
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    };
    tracing::info!(h_file, info_class, ?res, "GetFileInformationByHandleEx");
    res
}

fn match_wildcard(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    let n = name.to_ascii_lowercase();
    let p = pattern.to_ascii_lowercase();
    wildcard_match_recursive(n.as_bytes(), p.as_bytes())
}

fn wildcard_match_recursive(name: &[u8], pattern: &[u8]) -> bool {
    let mut n_idx = 0;
    let mut p_idx = 0;
    let mut n_star = None;
    let mut p_star = None;

    while n_idx < name.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == b'?' || pattern[p_idx] == name[n_idx]) {
            n_idx += 1;
            p_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == b'*' {
            p_star = Some(p_idx);
            p_idx += 1;
            n_star = Some(n_idx);
        } else if let Some(p_back) = p_star {
            p_idx = p_back + 1;
            let n_back = n_star.unwrap();
            n_star = Some(n_back + 1);
            n_idx = n_back + 1;
        } else {
            return false;
        }
    }

    while p_idx < pattern.len() && pattern[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == pattern.len()
}

fn enumerate_find_entries(path_str: &str) -> Result<Vec<FindEntry>, u32> {
    let norm = path_str.replace('\\', "/");
    let has_wildcard = path_str.contains('*') || path_str.contains('?');
    if !has_wildcard {
        let trimmed = path_str.trim_end_matches(['\\', '/']);
        let host_trimmed = normalize_host_path(trimmed);
        let host_trimmed_buf = PathBuf::from(&host_trimmed);
        let resolved = if host_trimmed_buf.exists() {
            Some(host_trimmed_buf)
        } else {
            crate::filesystem::case_fold::resolve_case_insensitive(&host_trimmed_buf)
        };
        if let Some(p) = resolved {
            if let Ok(metadata) = std::fs::metadata(&p) {
                if !metadata.is_dir() {
                    let file_name =
                        p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    let modified = metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    return Ok(vec![FindEntry {
                        file_name,
                        is_dir: false,
                        file_size: metadata.len(),
                        modified_unix: modified,
                    }]);
                }
            }
        }
    }

    let host_full = normalize_host_path(path_str);
    let host_full_buf = PathBuf::from(&host_full);
    let resolved_full = if host_full_buf.exists() {
        Some(host_full_buf)
    } else {
        crate::filesystem::case_fold::resolve_case_insensitive(&host_full_buf)
    };

    let (dir_part, pattern): (&str, &str) = if let Some(ref rf) = resolved_full {
        if rf.is_dir() {
            (path_str, "*")
        } else if let Some(idx) = norm.rfind('/') {
            let (d, p) = norm.split_at(idx);
            (if d.is_empty() { "/" } else { d }, &p[1..])
        } else {
            (".", path_str)
        }
    } else if let Some(idx) = norm.rfind('/') {
        let (d, p) = norm.split_at(idx);
        (if d.is_empty() { "/" } else { d }, &p[1..])
    } else {
        (".", path_str)
    };

    let pattern = if pattern.is_empty() { "*" } else { pattern };

    let host_dir = normalize_host_path(dir_part);
    let host_path_buf = PathBuf::from(&host_dir);
    let resolved_dir = if host_path_buf.exists() {
        host_path_buf
    } else if let Some(resolved) =
        crate::filesystem::case_fold::resolve_case_insensitive(&host_path_buf)
    {
        resolved
    } else {
        return Err(ERROR_PATH_NOT_FOUND);
    };

    if !resolved_dir.is_dir() {
        if resolved_dir.is_file() {
            let metadata = std::fs::metadata(&resolved_dir).map_err(|_| ERROR_FILE_NOT_FOUND)?;
            let file_name = resolved_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            return Ok(vec![FindEntry {
                file_name,
                is_dir: false,
                file_size: metadata.len(),
                modified_unix: modified,
            }]);
        }
        return Err(ERROR_PATH_NOT_FOUND);
    }

    let dir_entries = std::fs::read_dir(&resolved_dir).map_err(|_| ERROR_PATH_NOT_FOUND)?;
    let mut results = Vec::new();

    if pattern == "*" || pattern == "*.*" {
        results.push(FindEntry {
            file_name: ".".to_string(),
            is_dir: true,
            file_size: 0,
            modified_unix: 0,
        });
        results.push(FindEntry {
            file_name: "..".to_string(),
            is_dir: true,
            file_size: 0,
            modified_unix: 0,
        });
    }

    for entry in dir_entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if match_wildcard(&name, pattern) {
            if let Ok(metadata) = entry.metadata() {
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                results.push(FindEntry {
                    file_name: name,
                    is_dir: metadata.is_dir(),
                    file_size: metadata.len(),
                    modified_unix: modified,
                });
            }
        }
    }

    if results.is_empty() {
        return Err(ERROR_FILE_NOT_FOUND);
    }

    Ok(results)
}

fn write_find_data_w(entry: &FindEntry, lp_find_file_data: *mut c_void) {
    if lp_find_file_data.is_null() {
        return;
    }
    let data_ptr = lp_find_file_data as *mut Win32FindDataW;
    let attrs = if entry.is_dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
    let time = unix_seconds_to_filetime(entry.modified_unix);
    let mut c_file_name = [0u16; 260];
    let wide: Vec<u16> = entry.file_name.encode_utf16().collect();
    let len = wide.len().min(259);
    c_file_name[..len].copy_from_slice(&wide[..len]);
    c_file_name[len] = 0;

    let data = Win32FindDataW {
        dw_file_attributes: attrs,
        ft_creation_time: time,
        ft_last_access_time: time,
        ft_last_write_time: time,
        n_file_size_high: (entry.file_size >> 32) as u32,
        n_file_size_low: (entry.file_size & 0xFFFF_FFFF) as u32,
        dw_reserved0: 0,
        dw_reserved1: 0,
        c_file_name,
        c_alternate_file_name: [0u16; 14],
    };
    unsafe {
        std::ptr::write_unaligned(data_ptr, data);
    }
}

fn write_find_data_a(entry: &FindEntry, lp_find_file_data: *mut c_void) {
    if lp_find_file_data.is_null() {
        return;
    }
    let data_ptr = lp_find_file_data as *mut Win32FindDataA;
    let attrs = if entry.is_dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
    let time = unix_seconds_to_filetime(entry.modified_unix);
    let mut c_file_name = [0u8; 260];
    let bytes = entry.file_name.as_bytes();
    let len = bytes.len().min(259);
    c_file_name[..len].copy_from_slice(&bytes[..len]);
    c_file_name[len] = 0;

    let data = Win32FindDataA {
        dw_file_attributes: attrs,
        ft_creation_time: time,
        ft_last_access_time: time,
        ft_last_write_time: time,
        n_file_size_high: (entry.file_size >> 32) as u32,
        n_file_size_low: (entry.file_size & 0xFFFF_FFFF) as u32,
        dw_reserved0: 0,
        dw_reserved1: 0,
        c_file_name,
        c_alternate_file_name: [0u8; 14],
    };
    unsafe {
        std::ptr::write_unaligned(data_ptr, data);
    }
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

    match enumerate_find_entries(&path) {
        Ok(entries) => {
            if entries.is_empty() {
                set_last_error(ERROR_FILE_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            write_find_data_a(&entries[0], lp_find_file_data);
            let handle = global_table()
                .alloc(Box::new(FindFileHandle { entries, cursor: AtomicUsize::new(1) }));
            set_last_error(ERROR_SUCCESS);
            handle
        }
        Err(err) => {
            set_last_error(err);
            INVALID_HANDLE_VALUE
        }
    }
}

pub extern "win64" fn find_first_file_w(
    lp_file_name: *const u16,
    lp_find_file_data: *mut c_void,
) -> Handle {
    if lp_find_file_data.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    let Some(path) = (unsafe { wide_string(lp_file_name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };

    let res = match enumerate_find_entries(&path) {
        Ok(entries) => {
            if entries.is_empty() {
                set_last_error(ERROR_FILE_NOT_FOUND);
                INVALID_HANDLE_VALUE
            } else {
                write_find_data_w(&entries[0], lp_find_file_data);
                let handle = global_table()
                    .alloc(Box::new(FindFileHandle { entries, cursor: AtomicUsize::new(1) }));
                set_last_error(ERROR_SUCCESS);
                handle
            }
        }
        Err(err) => {
            set_last_error(err);
            INVALID_HANDLE_VALUE
        }
    };
    tracing::trace!(path = %path, ?res, "FindFirstFileW");
    res
}

pub extern "win64" fn find_next_file_a(handle: Handle, lp_find_file_data: *mut c_void) -> i32 {
    if lp_find_file_data.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut output: Option<Result<FindEntry, u32>> = None;
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
        Some(Ok(entry)) => {
            write_find_data_a(&entry, lp_find_file_data);
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
    if lp_find_file_data.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut output: Option<Result<FindEntry, u32>> = None;
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
        Some(Ok(entry)) => {
            write_find_data_w(&entry, lp_find_file_data);
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
    fn overlapped_read_uses_its_offset_without_moving_file_pointer() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let p = temp.path().join("k32_overlapped.bin");
        std::fs::write(&p, b"abcdef").expect("seed");
        let c = std::ffi::CString::new(p.to_string_lossy().to_string()).expect("cstring");
        let handle = create_file_a(c.as_ptr(), 0x8000_0000, 0, std::ptr::null_mut(), 3, 0, 0);
        assert_ne!(handle, INVALID_HANDLE_VALUE);

        let mut ordinary = [0u8; 1];
        let mut bytes = 0u32;
        assert_eq!(
            read_file(
                handle,
                ordinary.as_mut_ptr().cast(),
                1,
                &mut bytes as *mut u32,
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(ordinary, *b"a");

        let mut overlapped = Overlapped { offset: 4, ..Default::default() };
        let mut positioned = [0u8; 2];
        assert_eq!(
            read_file(
                handle,
                positioned.as_mut_ptr().cast(),
                2,
                &mut bytes as *mut u32,
                (&raw mut overlapped).cast(),
            ),
            1
        );
        assert_eq!(positioned, *b"ef");
        assert_eq!(overlapped.internal, 0);
        assert_eq!(overlapped.internal_high, 2);

        let mut after = [0u8; 1];
        assert_eq!(
            read_file(
                handle,
                after.as_mut_ptr().cast(),
                1,
                &mut bytes as *mut u32,
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(after, *b"b");
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

        let mut data = unsafe { std::mem::zeroed::<Win32FindDataA>() };
        let handle = find_first_file_a(dir_c.as_ptr(), (&mut data as *mut Win32FindDataA).cast());
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let first = unsafe { std::ffi::CStr::from_ptr(data.c_file_name.as_ptr().cast()) }
            .to_str()
            .expect("utf8")
            .to_string();
        assert!(!first.is_empty());

        let mut data2 = unsafe { std::mem::zeroed::<Win32FindDataA>() };
        let next_ok = find_next_file_a(handle, (&mut data2 as *mut Win32FindDataA).cast());
        assert_eq!(next_ok, 1);
        let second = unsafe { std::ffi::CStr::from_ptr(data2.c_file_name.as_ptr().cast()) }
            .to_str()
            .expect("utf8")
            .to_string();
        assert!(!second.is_empty());
        assert_eq!(find_close(handle), 1);
    }

    #[test]
    fn get_file_type_reports_char_for_std_and_unknown_for_invalid() {
        assert_eq!(get_file_type(PSEUDO_STDOUT), FILE_TYPE_CHAR);
        assert_eq!(get_file_type(INVALID_HANDLE_VALUE), FILE_TYPE_UNKNOWN);
    }

    #[test]
    fn set_handle_information_validates_handle() {
        assert_eq!(set_handle_information(PSEUDO_STDOUT, 0, 0), 1);
        assert_eq!(set_handle_information(INVALID_HANDLE_VALUE, 0, 0), 0);
    }

    #[test]
    fn get_handle_information_returns_zero_flags_for_known_handles() {
        let mut flags = u32::MAX;
        assert_eq!(get_handle_information(PSEUDO_STDOUT, &mut flags as *mut u32), 1);
        assert_eq!(flags, 0);
    }

    #[test]
    fn create_pipe_roundtrip_with_read_write_file() {
        let mut read_handle = INVALID_HANDLE_VALUE;
        let mut write_handle = INVALID_HANDLE_VALUE;

        assert_eq!(
            create_pipe(
                &mut read_handle as *mut Handle,
                &mut write_handle as *mut Handle,
                std::ptr::null_mut(),
                0,
            ),
            1
        );

        let payload = b"pipe-roundtrip";
        let mut written = 0u32;
        assert_eq!(
            write_file(
                write_handle,
                payload.as_ptr().cast::<c_void>(),
                payload.len() as u32,
                Some(&mut written),
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(written as usize, payload.len());

        let mut buffer = [0u8; 32];
        let mut read = 0u32;
        assert_eq!(
            read_file(
                read_handle,
                buffer.as_mut_ptr().cast::<c_void>(),
                payload.len() as u32,
                &mut read as *mut u32,
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(read as usize, payload.len());
        assert_eq!(&buffer[..payload.len()], payload);

        assert_eq!(close_handle(read_handle), 1);
        assert_eq!(close_handle(write_handle), 1);
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
    fn get_overlapped_result_completed_returns_bytes() {
        let mut overlapped = Overlapped {
            internal: ERROR_SUCCESS as usize,
            internal_high: 123,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        };
        let mut transferred = 0u32;
        assert_eq!(
            get_overlapped_result(
                PSEUDO_STDOUT,
                (&mut overlapped as *mut Overlapped).cast::<c_void>(),
                &mut transferred as *mut u32,
                0,
            ),
            1
        );
        assert_eq!(transferred, 123);
    }

    #[test]
    fn get_overlapped_result_pending_without_wait_reports_incomplete() {
        let mut overlapped = Overlapped {
            internal: ERROR_IO_PENDING as usize,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        };
        let mut transferred = 0u32;
        assert_eq!(
            get_overlapped_result(
                PSEUDO_STDOUT,
                (&mut overlapped as *mut Overlapped).cast::<c_void>(),
                &mut transferred as *mut u32,
                0,
            ),
            0
        );
        assert_eq!(super::super::error::get_last_error(), ERROR_IO_INCOMPLETE);
    }

    #[test]
    fn cancel_io_rejects_invalid_handle() {
        assert_eq!(cancel_io(INVALID_HANDLE_VALUE), 0);
        assert_eq!(super::super::error::get_last_error(), ERROR_INVALID_HANDLE);
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
    fn get_full_path_name_w_returns_required_and_file_part() {
        let _guard = serial_guard();
        let input: Vec<u16> = "./Cargo.toml".encode_utf16().chain(std::iter::once(0)).collect();

        let required =
            get_full_path_name_w(input.as_ptr(), 0, std::ptr::null_mut(), std::ptr::null_mut());
        assert!(required > 1);

        let mut buffer = vec![0u16; required as usize];
        let mut file_part: *mut u16 = std::ptr::null_mut();
        let written = get_full_path_name_w(
            input.as_ptr(),
            buffer.len() as u32,
            buffer.as_mut_ptr(),
            &mut file_part,
        );
        assert!(written > 0);
        assert!(!file_part.is_null());

        let full = unsafe { from_wide_ptr(buffer.as_ptr()).expect("full path") };
        let part = unsafe { from_wide_ptr(file_part).expect("file part") };
        assert!(full.ends_with("Cargo.toml"));
        assert_eq!(part, "Cargo.toml");
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
