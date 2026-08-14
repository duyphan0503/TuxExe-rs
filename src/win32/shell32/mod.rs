#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! shell32.dll stubs.

use std::collections::HashMap;
use tracing::trace;

const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

extern "win64" fn ShellExecuteW(
    _hwnd: usize,
    _lpOperation: *const u16,
    _lpFile: *const u16,
    _lpParameters: *const u16,
    _lpDirectory: *const u16,
    _nShowCmd: i32,
) -> usize {
    trace!("ShellExecuteW — stub");
    32 // SE_ERR_DLLNOTFOUND placeholder
}

#[repr(C)]
struct ShellExecuteInfoW {
    cb_size: u32,
    f_mask: u32,
    hwnd: usize,
    lp_verb: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show: i32,
    h_inst_app: usize,
    lp_id_list: *mut u8,
    lp_class: *const u16,
    hkey_class: usize,
    dw_hot_key: u32,
    h_icon_or_monitor: usize,
    h_process: usize,
}

/// Native-only policy deliberately does not delegate shell verbs to host
/// applications. Report the standard unsupported-operation failure instead
/// of spawning Wine, xdg-open, or an arbitrary process.
extern "win64" fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32 {
    if info.is_null()
        || unsafe { (*info).cb_size } < std::mem::size_of::<ShellExecuteInfoW>() as u32
    {
        crate::win32::kernel32::error::set_last_error(87);
        return 0;
    }
    unsafe {
        (*info).h_process = 0;
        (*info).h_inst_app = 0;
    }
    crate::win32::kernel32::error::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    0
}

fn csidl_to_win_path(csidl: i32) -> &'static str {
    match csidl & 0xFF {
        0x001a => r"C:\users\User\AppData\Roaming", // CSIDL_APPDATA
        0x001c => r"C:\users\User\AppData\Local",   // CSIDL_LOCAL_APPDATA
        0x0023 => r"C:\ProgramData",                // CSIDL_COMMON_APPDATA
        0x0005 => r"C:\users\User\Documents",      // CSIDL_MYDOCUMENTS / CSIDL_PERSONAL
        0x0028 => r"C:\users\User",                // CSIDL_PROFILE
        0x0024 => r"C:\Windows",                   // CSIDL_WINDOWS
        0x0025 => r"C:\Windows\System32",          // CSIDL_SYSTEM
        0x0026 => r"C:\Program Files",             // CSIDL_PROGRAM_FILES
        _ => r"C:\users\User\AppData\LocalLow",
    }
}

fn ensure_host_dir_for_csidl(csidl: i32) {
    if let Ok(home) = std::env::var("HOME") {
        let sub = match csidl & 0xFF {
            0x001a => ".tuxexe/drive_c/users/User/AppData/Roaming",
            0x001c => ".tuxexe/drive_c/users/User/AppData/Local",
            0x0023 => ".tuxexe/drive_c/ProgramData",
            0x0005 => ".tuxexe/drive_c/users/User/Documents",
            0x0028 => ".tuxexe/drive_c/users/User",
            0x0024 => ".tuxexe/drive_c/Windows",
            0x0025 => ".tuxexe/drive_c/Windows/System32",
            0x0026 => ".tuxexe/drive_c/Program Files",
            _ => ".tuxexe/drive_c/users/User/AppData/LocalLow",
        };
        let _ = std::fs::create_dir_all(format!("{home}/{sub}"));
    }
}

extern "win64" fn SHGetFolderPathW(
    _hwnd: usize,
    csidl: i32,
    _hToken: usize,
    _dwFlags: u32,
    pszPath: *mut u16,
) -> i32 {
    trace!("SHGetFolderPathW csidl={} — implementing", csidl);
    if pszPath.is_null() {
        return -2147024809; // E_INVALIDARG
    }
    ensure_host_dir_for_csidl(csidl);
    let path_str = csidl_to_win_path(csidl);
    let wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), pszPath, wide.len());
    }
    0 // S_OK
}

extern "win64" fn SHGetFolderPathA(
    _hwnd: usize,
    csidl: i32,
    _hToken: usize,
    _dwFlags: u32,
    pszPath: *mut std::ffi::c_char,
) -> i32 {
    trace!("SHGetFolderPathA csidl={} — implementing", csidl);
    if pszPath.is_null() {
        return -2147024809; // E_INVALIDARG
    }
    ensure_host_dir_for_csidl(csidl);
    let path_str = csidl_to_win_path(csidl);
    let bytes: Vec<u8> = path_str.bytes().chain(std::iter::once(0)).collect();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const std::ffi::c_char, pszPath, bytes.len());
    }
    0 // S_OK
}

extern "win64" fn SHGetSpecialFolderPathW(
    hwnd: usize,
    pszPath: *mut u16,
    csidl: i32,
    fCreate: i32,
) -> i32 {
    let _ = fCreate;
    let res = SHGetFolderPathW(hwnd, csidl, 0, 0, pszPath);
    if res == 0 { 1 } else { 0 }
}

extern "win64" fn SHGetSpecialFolderPathA(
    hwnd: usize,
    pszPath: *mut std::ffi::c_char,
    csidl: i32,
    fCreate: i32,
) -> i32 {
    let _ = fCreate;
    let res = SHGetFolderPathA(hwnd, csidl, 0, 0, pszPath);
    if res == 0 { 1 } else { 0 }
}

extern "win64" fn SHGetKnownFolderPath(
    _rfid: *const u8,
    _dwFlags: u32,
    _hToken: usize,
    ppszPath: *mut *mut u16,
) -> i32 {
    trace!("SHGetKnownFolderPath — implementing");
    if ppszPath.is_null() {
        return -2147024809; // E_INVALIDARG
    }
    ensure_host_dir_for_csidl(0);
    let path_str = r"C:\users\User\AppData\LocalLow";
    let wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
    let ptr = unsafe { libc::malloc(wide.len() * 2) as *mut u16 };
    if ptr.is_null() {
        return -2147024882; // E_OUTOFMEMORY
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        *ppszPath = ptr;
    }
    0 // S_OK
}

extern "win64" fn CommandLineToArgvW(lpCmdLine: *const u16, pNumArgs: *mut i32) -> *mut *mut u16 {
    trace!("CommandLineToArgvW — implementation");
    if lpCmdLine.is_null() || pNumArgs.is_null() {
        return std::ptr::null_mut();
    }

    // Parse the command line into argv
    let cmd_line = unsafe {
        let mut len = 0;
        while !lpCmdLine.is_null() && len < 10000 {
            if *lpCmdLine.add(len) == 0 {
                break;
            }
            len += 1;
        }
        std::slice::from_raw_parts(lpCmdLine, len)
    };

    // Simple parsing: split by spaces (handles quotes properly)
    let cmd_str = String::from_utf16_lossy(cmd_line);
    let args: Vec<String> = parse_command_line(&cmd_str);
    let argc = args.len() as i32;

    unsafe {
        *pNumArgs = argc;
    }

    // Allocate argv array (argc + 1 for NULL terminator)
    let argv_size = (argc as usize + 1) * std::mem::size_of::<*mut u16>();
    let argv = unsafe { libc::malloc(argv_size) as *mut *mut u16 };
    if argv.is_null() {
        return std::ptr::null_mut();
    }

    // Copy each argument
    for (i, arg) in args.iter().enumerate() {
        let wide: Vec<u16> = arg.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_ptr = unsafe { libc::malloc(wide.len() * 2) as *mut u16 };
        if wide_ptr.is_null() {
            return std::ptr::null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), wide_ptr, wide.len());
            *argv.add(i) = wide_ptr;
        }
    }

    // NULL terminator
    unsafe {
        *argv.add(argc as usize) = std::ptr::null_mut();
    }

    argv
}

fn parse_command_line(cmd_line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = cmd_line.chars().peekable();

    // Skip leading whitespace
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }

    while let Some(c) = chars.next() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                args.push(current.clone());
                current.clear();
            }
            // Skip consecutive whitespace
            while let Some(&next_c) = chars.peek() {
                if next_c.is_whitespace() && !in_quotes {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        args.push(String::new());
    }

    args
}

extern "win64" fn SHBrowseForFolderW(_lpbi: *mut u8) -> *mut u8 {
    trace!("SHBrowseForFolderW — stub");
    std::ptr::null_mut()
}

#[repr(C)]
pub struct SHFILEOPSTRUCTW {
    pub hwnd: usize,
    pub wFunc: u32,
    pub pFrom: *const u16,
    pub pTo: *const u16,
    pub fFlags: u16,
    pub fAnyOperationsAborted: i32,
    pub hNameMappings: *mut u8,
    pub lpszProgressTitle: *const u16,
}

extern "win64" fn SHFileOperationW(lpFileOp: *const SHFILEOPSTRUCTW) -> i32 {
    trace!("SHFileOperationW — stub");
    if lpFileOp.is_null() {
        return -2147467263; // E_FAIL
    }
    0 // ERROR_SUCCESS (stub - always succeeds)
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("ShellExecuteW", ShellExecuteW as usize);
    exports.insert("ShellExecuteExW", ShellExecuteExW as usize);
    exports.insert("SHGetFolderPathW", SHGetFolderPathW as usize);
    exports.insert("SHGetFolderPathA", SHGetFolderPathA as usize);
    exports.insert("SHGetSpecialFolderPathW", SHGetSpecialFolderPathW as usize);
    exports.insert("SHGetSpecialFolderPathA", SHGetSpecialFolderPathA as usize);
    exports.insert("SHGetKnownFolderPath", SHGetKnownFolderPath as usize);
    exports.insert("CommandLineToArgvW", CommandLineToArgvW as usize);
    exports.insert("SHBrowseForFolderW", SHBrowseForFolderW as usize);
    exports.insert("SHFileOperationW", SHFileOperationW as usize);
    exports
}
