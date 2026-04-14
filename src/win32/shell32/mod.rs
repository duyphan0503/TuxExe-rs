#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! shell32.dll stubs.

use std::collections::HashMap;
use tracing::trace;

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

extern "win64" fn SHGetFolderPathW(
    _hwnd: usize,
    _csidl: i32,
    _hToken: usize,
    _dwFlags: u32,
    _pszPath: *mut u16,
) -> i32 {
    trace!("SHGetFolderPathW — stub");
    -2147467263 // E_NOTIMPL
}

extern "win64" fn SHGetKnownFolderPath(
    _rfid: *const u8,
    _dwFlags: u32,
    _hToken: usize,
    _ppszPath: *mut *mut u16,
) -> i32 {
    trace!("SHGetKnownFolderPath — stub");
    -2147467263
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
    exports.insert("SHGetFolderPathW", SHGetFolderPathW as usize);
    exports.insert("SHGetKnownFolderPath", SHGetKnownFolderPath as usize);
    exports.insert("CommandLineToArgvW", CommandLineToArgvW as usize);
    exports.insert("SHBrowseForFolderW", SHBrowseForFolderW as usize);
    exports.insert("SHFileOperationW", SHFileOperationW as usize);
    exports
}
