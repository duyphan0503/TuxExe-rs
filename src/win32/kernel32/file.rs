#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! WriteFile/ReadFile plus core CreateFile/FindFirst/FindNext support.

use crate::nt_kernel::file::{
    nt_create_file, nt_query_directory_file, nt_query_information_by_path,
    nt_query_information_file, nt_read_file, nt_set_file_pointer_ex, nt_write_file,
    CreateDisposition, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::utils::{
    handle::{global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE},
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

#[derive(Debug)]
struct FindFileHandle {
    entries: Vec<String>,
    cursor: AtomicUsize,
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

pub extern "win64" fn find_close(handle: Handle) -> i32 {
    close_handle(handle)
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
}
