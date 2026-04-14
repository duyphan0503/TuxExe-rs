#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! shlwapi.dll stubs.

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn PathFindFileNameW(pszPath: *const u16) -> *const u16 {
    trace!("PathFindFileNameW — stub");
    if pszPath.is_null() {
        return pszPath;
    }
    let mut ptr = pszPath;
    let mut last = ptr;
    unsafe {
        while *ptr != 0 {
            if *ptr == b'\\' as u16 || *ptr == b'/' as u16 {
                last = ptr.offset(1);
            }
            ptr = ptr.offset(1);
        }
    }
    last
}

extern "win64" fn PathIsDirectoryW(_pszPath: *const u16) -> i32 {
    trace!("PathIsDirectoryW — stub");
    1 // TRUE
}

extern "win64" fn PathFileExistsW(_pszPath: *const u16) -> i32 {
    trace!("PathFileExistsW — stub");
    1
}

extern "win64" fn PathCanonicalizeW(lpszDst: *mut u16, lpszSrc: *const u16) -> i32 {
    trace!("PathCanonicalizeW — stub");
    if lpszDst.is_null() || lpszSrc.is_null() {
        return 0;
    }
    // Just copy the source as-is (stub)
    let mut i = 0;
    unsafe {
        while *lpszSrc.offset(i) != 0 && i < 260 {
            *lpszDst.offset(i) = *lpszSrc.offset(i);
            i += 1;
        }
        *lpszDst.offset(i) = 0;
    }
    1
}

extern "win64" fn SHDeleteKeyW(_hKey: usize, _pszSubKey: *const u16) -> i32 {
    trace!("SHDeleteKeyW — stub");
    0 // ERROR_SUCCESS
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("PathFindFileNameW", PathFindFileNameW as usize);
    exports.insert("PathIsDirectoryW", PathIsDirectoryW as usize);
    exports.insert("PathFileExistsW", PathFileExistsW as usize);
    exports.insert("PathCanonicalizeW", PathCanonicalizeW as usize);
    exports.insert("SHDeleteKeyW", SHDeleteKeyW as usize);
    exports
}
