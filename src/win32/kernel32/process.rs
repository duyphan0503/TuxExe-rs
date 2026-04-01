#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! ExitProcess, GetModuleHandleA/W, GetCommandLineA/W, GetCurrentProcessId.

use std::ffi::{c_void, CStr, CString};
use tracing::trace;

use crate::dll_manager::{free_library, get_loaded_module_handle, load_library, resolve_export};
use crate::utils::wide_string::from_wide_ptr;

pub extern "win64" fn exit_process(exit_code: u32) {
    trace!("ExitProcess({})", exit_code);
    std::process::exit(exit_code as i32);
}

// Global variable for the main image base
static mut MAIN_IMAGE_BASE: usize = 0x0040_0000; // Will be set during PE loading

pub fn set_main_image_base(base: usize) {
    unsafe {
        MAIN_IMAGE_BASE = base;
    }
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;

fn set_last_error(err: u32) {
    super::error::set_last_error(err);
}

pub extern "win64" fn get_module_handle_a(module_name: *const i8) -> *mut c_void {
    if module_name.is_null() {
        set_last_error(ERROR_SUCCESS);
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        let name = unsafe { CStr::from_ptr(module_name) };
        match name.to_str().ok().and_then(get_loaded_module_handle) {
            Some(handle) => {
                set_last_error(ERROR_SUCCESS);
                handle as *mut c_void
            }
            None => {
                set_last_error(ERROR_MOD_NOT_FOUND);
                std::ptr::null_mut()
            }
        }
    }
}

pub extern "win64" fn get_module_handle_w(module_name: *const u16) -> *mut c_void {
    if module_name.is_null() {
        set_last_error(ERROR_SUCCESS);
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        match unsafe { from_wide_ptr(module_name).ok() }.and_then(|s| get_loaded_module_handle(&s))
        {
            Some(handle) => {
                set_last_error(ERROR_SUCCESS);
                handle as *mut c_void
            }
            None => {
                set_last_error(ERROR_MOD_NOT_FOUND);
                std::ptr::null_mut()
            }
        }
    }
}

pub extern "win64" fn load_library_a(lp_lib_file_name: *const i8) -> *mut c_void {
    if lp_lib_file_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    let Ok(name) = (unsafe { CStr::from_ptr(lp_lib_file_name).to_str() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    match load_library(name) {
        Ok(handle) => {
            set_last_error(ERROR_SUCCESS);
            handle as *mut c_void
        }
        Err(_) => {
            set_last_error(ERROR_MOD_NOT_FOUND);
            std::ptr::null_mut()
        }
    }
}

pub extern "win64" fn load_library_w(lp_lib_file_name: *const u16) -> *mut c_void {
    if lp_lib_file_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }
    let Some(name) = (unsafe { from_wide_ptr(lp_lib_file_name).ok() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    let c_name = CString::new(name).unwrap_or_else(|_| CString::new("").expect("empty cstr"));
    load_library_a(c_name.as_ptr())
}

pub extern "win64" fn get_proc_address(
    h_module: *mut c_void,
    lp_proc_name: *const i8,
) -> *mut c_void {
    if h_module.is_null() || lp_proc_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    // Ordinal form is MAKEINTRESOURCEA(ordinal) where pointer value is <= 0xFFFF.
    let proc_raw = lp_proc_name as usize;
    if proc_raw <= 0xFFFF {
        set_last_error(ERROR_PROC_NOT_FOUND);
        return std::ptr::null_mut();
    }

    let Ok(proc_name) = (unsafe { CStr::from_ptr(lp_proc_name).to_str() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    let handle = h_module as usize;
    match resolve_export(handle, proc_name) {
        Some(addr) => {
            set_last_error(ERROR_SUCCESS);
            addr as *mut c_void
        }
        None => {
            if handle == 0 {
                set_last_error(ERROR_INVALID_HANDLE);
            } else {
                set_last_error(ERROR_PROC_NOT_FOUND);
            }
            std::ptr::null_mut()
        }
    }
}

pub extern "win64" fn free_library_api(h_lib_module: *mut c_void) -> i32 {
    if h_lib_module.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    match free_library(h_lib_module as usize) {
        Ok(()) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

lazy_static::lazy_static! {
    static ref CMD_LINE_A: CString = {
        let args: Vec<String> = std::env::args().collect();
        // Quote arguments if they contain spaces
        let cmd = args.iter().map(|arg| {
            if arg.contains(' ') {
                format!("\"{}\"", arg)
            } else {
                arg.clone()
            }
        }).collect::<Vec<String>>().join(" ");
        CString::new(cmd).unwrap_or_else(|_| CString::new("").unwrap())
    };

    static ref CMD_LINE_W: Vec<u16> = {
        let args: Vec<String> = std::env::args().collect();
        let cmd = args.iter().map(|arg| {
            if arg.contains(' ') {
                format!("\"{}\"", arg)
            } else {
                arg.clone()
            }
        }).collect::<Vec<String>>().join(" ");
        let mut utf16: Vec<u16> = cmd.encode_utf16().collect();
        utf16.push(0);
        utf16
    };
}

pub extern "win64" fn get_command_line_a() -> *const i8 {
    trace!("GetCommandLineA()");
    CMD_LINE_A.as_ptr()
}

pub extern "win64" fn get_command_line_w() -> *const u16 {
    trace!("GetCommandLineW()");
    CMD_LINE_W.as_ptr()
}

pub extern "win64" fn get_startup_info_a(lp_startup_info: *mut u8) {
    trace!("GetStartupInfoA()");
    if !lp_startup_info.is_null() {
        unsafe {
            // STARTUPINFOA is at least 68 bytes
            std::ptr::write_bytes(lp_startup_info, 0, 68);
            // cb (size) is the firstDWORD
            *(lp_startup_info as *mut u32) = 68;
        }
    }
}

pub extern "win64" fn get_startup_info_w(lp_startup_info: *mut u8) {
    trace!("GetStartupInfoW()");
    if !lp_startup_info.is_null() {
        unsafe {
            // STARTUPINFOW is at least 68 bytes
            std::ptr::write_bytes(lp_startup_info, 0, 68);
            // cb (size) is the first DWORD
            *(lp_startup_info as *mut u32) = 68;
        }
    }
}

pub extern "win64" fn get_current_process_id() -> u32 {
    let pid = std::process::id();
    trace!("GetCurrentProcessId() -> {}", pid);
    pid
}

pub extern "win64" fn get_current_thread_id() -> u32 {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    trace!("GetCurrentThreadId() -> {}", tid);
    tid
}

pub extern "win64" fn is_processor_feature_present(processor_feature: u32) -> u32 {
    trace!("IsProcessorFeaturePresent({})", processor_feature);
    // Hardcode common features (e.g., SSE2 = 10, etc.)
    match processor_feature {
        10 => 1, // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_manager::loader::reset_registry_for_tests;
    use crate::utils::wide_string::to_wide_null;

    #[test]
    fn load_library_a_and_get_module_handle_a_work_for_reimplemented_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let name = CString::new("kernel32.dll").expect("cstring");
        let handle = load_library_a(name.as_ptr());
        assert!(!handle.is_null());

        let queried = get_module_handle_a(name.as_ptr());
        assert_eq!(queried, handle);
    }

    #[test]
    fn load_library_w_and_get_module_handle_w_work_for_reimplemented_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let wide = to_wide_null("msvcrt.dll");
        let handle = load_library_w(wide.as_ptr());
        assert!(!handle.is_null());

        let queried = get_module_handle_w(wide.as_ptr());
        assert_eq!(queried, handle);
    }

    #[test]
    fn get_proc_address_resolves_reimplemented_export() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let dll = CString::new("kernel32.dll").expect("dll");
        let proc = CString::new("LoadLibraryA").expect("proc");
        let module = load_library_a(dll.as_ptr());
        assert!(!module.is_null());

        let fn_ptr = get_proc_address(module, proc.as_ptr());
        assert!(!fn_ptr.is_null());
    }

    #[test]
    fn free_library_unloads_after_last_reference() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let dll = CString::new("kernel32.dll").expect("dll");
        let m1 = load_library_a(dll.as_ptr());
        let m2 = load_library_a(dll.as_ptr());
        assert_eq!(m1, m2);

        assert_eq!(free_library_api(m1), 1);
        assert!(!get_module_handle_a(dll.as_ptr()).is_null());

        assert_eq!(free_library_api(m1), 1);
        assert!(get_module_handle_a(dll.as_ptr()).is_null());
    }
}
