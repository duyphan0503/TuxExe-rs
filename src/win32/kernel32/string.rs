#![allow(non_snake_case)]

// use std::ffi::c_void;
use tracing::trace;

pub extern "win64" fn IsDBCSLeadByteEx(_code_page: u32, _test_char: u8) -> i32 {
    0 // False
}

pub extern "win64" fn MultiByteToWideChar(
    _code_page: u32,
    _flags: u32,
    _mb_str: *const u8,
    _mb_len: i32,
    _wide_str: *mut u16,
    _wide_len: i32,
) -> i32 {
    trace!("MultiByteToWideChar Stub");
    0 // No bytes written
}

pub extern "win64" fn WideCharToMultiByte(
    _code_page: u32,
    _flags: u32,
    _wide_str: *const u16,
    _wide_len: i32,
    _mb_str: *mut u8,
    _mb_len: i32,
    _default_char: *const u8,
    _used_default: *mut i32,
) -> i32 {
    trace!("WideCharToMultiByte Stub");
    0 // No bytes written
}
