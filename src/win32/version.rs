//! VERSION.dll implementation

use std::collections::HashMap;

extern "win64" fn GetFileVersionInfoSizeA(_filename: *const u8, handle: *mut u32) -> u32 {
    if !handle.is_null() {
        unsafe {
            *handle = 0;
        }
    }
    0
}

extern "win64" fn GetFileVersionInfoSizeW(_filename: *const u16, handle: *mut u32) -> u32 {
    if !handle.is_null() {
        unsafe {
            *handle = 0;
        }
    }
    0
}

extern "win64" fn GetFileVersionInfoA(
    _filename: *const u8,
    _handle: u32,
    _len: u32,
    _data: *mut u8,
) -> u32 {
    0
}

extern "win64" fn GetFileVersionInfoW(
    _filename: *const u16,
    _handle: u32,
    _len: u32,
    _data: *mut u8,
) -> u32 {
    0
}

extern "win64" fn VerQueryValueA(
    _block: *const u8,
    _sub_block: *const u8,
    _buffer: *mut *mut u8,
    _len: *mut u32,
) -> u32 {
    0
}

extern "win64" fn VerQueryValueW(
    _block: *const u8,
    _sub_block: *const u16,
    _buffer: *mut *mut u8,
    _len: *mut u32,
) -> u32 {
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("GetFileVersionInfoSizeA", GetFileVersionInfoSizeA as usize);
    exports.insert("GetFileVersionInfoSizeW", GetFileVersionInfoSizeW as usize);
    exports.insert("GetFileVersionInfoA", GetFileVersionInfoA as usize);
    exports.insert("GetFileVersionInfoW", GetFileVersionInfoW as usize);
    exports.insert("VerQueryValueA", VerQueryValueA as usize);
    exports.insert("VerQueryValueW", VerQueryValueW as usize);
    exports
}
