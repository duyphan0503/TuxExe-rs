#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! dwmapi.dll stubs.

use std::collections::HashMap;
use std::ffi::c_void;
use tracing::trace;

extern "win64" fn DwmIsCompositionEnabled(pfEnabled: *mut i32) -> i32 {
    trace!("DwmIsCompositionEnabled — stub");
    if !pfEnabled.is_null() {
        unsafe {
            *pfEnabled = 0;
        }
    }
    -2147024809
}

extern "win64" fn DwmEnableBlurBehindWindow(_hwnd: usize, _pBlurBehind: *mut u8) -> i32 {
    trace!("DwmEnableBlurBehindWindow — stub");
    -2147024809
}

extern "win64" fn DwmGetWindowAttribute(_hwnd: usize, _dwAttribute: u32, _pvAttribute: *mut c_void, _cbAttribute: u32) -> i32 {
    trace!("DwmGetWindowAttribute — stub");
    -2147024809 // E_FAIL
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("DwmIsCompositionEnabled", DwmIsCompositionEnabled as usize);
    exports.insert("DwmEnableBlurBehindWindow", DwmEnableBlurBehindWindow as usize);
    exports.insert("DwmGetWindowAttribute", DwmGetWindowAttribute as usize);
    exports
}
