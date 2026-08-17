//! COMDLG32.dll implementation

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn ChooseColorA(_lpcc: *mut u8) -> i32 {
    trace!("ChooseColorA stub called");
    0
}

extern "win64" fn ChooseColorW(_lpcc: *mut u8) -> i32 {
    trace!("ChooseColorW stub called");
    0
}

extern "win64" fn GetOpenFileNameA(_lpofn: *mut u8) -> i32 {
    trace!("GetOpenFileNameA stub called");
    0
}

extern "win64" fn GetOpenFileNameW(_lpofn: *mut u8) -> i32 {
    trace!("GetOpenFileNameW stub called");
    0
}

extern "win64" fn GetSaveFileNameA(_lpofn: *mut u8) -> i32 {
    trace!("GetSaveFileNameA stub called");
    0
}

extern "win64" fn GetSaveFileNameW(_lpofn: *mut u8) -> i32 {
    trace!("GetSaveFileNameW stub called");
    0
}

extern "win64" fn ChooseFontA(_lpcf: *mut u8) -> i32 {
    trace!("ChooseFontA stub called");
    0
}

extern "win64" fn ChooseFontW(_lpcf: *mut u8) -> i32 {
    trace!("ChooseFontW stub called");
    0
}

extern "win64" fn PrintDlgA(_lppd: *mut u8) -> i32 {
    trace!("PrintDlgA stub called");
    0
}

extern "win64" fn PrintDlgW(_lppd: *mut u8) -> i32 {
    trace!("PrintDlgW stub called");
    0
}

extern "win64" fn CommDlgExtendedError() -> u32 {
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("ChooseColorA", ChooseColorA as usize);
    exports.insert("ChooseColorW", ChooseColorW as usize);
    exports.insert("GetOpenFileNameA", GetOpenFileNameA as usize);
    exports.insert("GetOpenFileNameW", GetOpenFileNameW as usize);
    exports.insert("GetSaveFileNameA", GetSaveFileNameA as usize);
    exports.insert("GetSaveFileNameW", GetSaveFileNameW as usize);
    exports.insert("ChooseFontA", ChooseFontA as usize);
    exports.insert("ChooseFontW", ChooseFontW as usize);
    exports.insert("PrintDlgA", PrintDlgA as usize);
    exports.insert("PrintDlgW", PrintDlgW as usize);
    exports.insert("CommDlgExtendedError", CommDlgExtendedError as usize);
    exports
}
