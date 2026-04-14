#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! imm32.dll stubs.

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn ImmGetContext(_hwnd: usize) -> usize {
    trace!("ImmGetContext — stub");
    0
}

extern "win64" fn ImmReleaseContext(_hwnd: usize, _himc: usize) -> i32 {
    trace!("ImmReleaseContext — stub");
    0
}

extern "win64" fn ImmSetCompositionWindow(_himc: usize, _lpcf: *mut u8) -> i32 {
    trace!("ImmSetCompositionWindow — stub");
    0
}

extern "win64" fn ImmGetCompositionWindow(_himc: usize, _lpcf: *mut u8) -> i32 {
    trace!("ImmGetCompositionWindow — stub");
    0
}

extern "win64" fn ImmSetCompositionFontW(_himc: usize, _lplf: *mut u8) -> i32 {
    trace!("ImmSetCompositionFontW — stub");
    0
}

extern "win64" fn ImmGetCompositionFontW(_himc: usize, _lplf: *mut u8) -> i32 {
    trace!("ImmGetCompositionFontW — stub");
    0
}

extern "win64" fn ImmNotifyIME(_himc: usize, _dwAction: u32, _dwIndex: u32, _dwValue: u32) -> i32 {
    trace!("ImmNotifyIME — stub");
    0
}

extern "win64" fn ImmAssociateContext(_hwnd: usize, _himc: usize) -> usize {
    trace!("ImmAssociateContext — stub");
    0
}

extern "win64" fn ImmSetCompositionStringW(
    _himc: usize,
    _dwIndex: u32,
    _lpComp: *const u8,
    _dwCompLen: u32,
    _lpRead: *const u8,
    _dwReadLen: u32,
) -> i32 {
    trace!("ImmSetCompositionStringW — stub");
    0
}

extern "win64" fn ImmGetCompositionStringW(
    _himc: usize,
    _dwIndex: u32,
    _lpBuf: *mut u8,
    _dwBufLen: u32,
) -> i32 {
    trace!("ImmGetCompositionStringW — stub");
    0
}

extern "win64" fn ImmAssociateContextEx(_hwnd: usize, _himc: usize, _dwFlags: u32) -> i32 {
    trace!("ImmAssociateContextEx — stub");
    0
}

extern "win64" fn ImmGetConversionStatus(_himc: usize, _lpfdwConversion: *mut u32, _lpfdwSentence: *mut u32) -> i32 {
    trace!("ImmGetConversionStatus — stub");
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("ImmGetContext", ImmGetContext as usize);
    exports.insert("ImmReleaseContext", ImmReleaseContext as usize);
    exports.insert("ImmSetCompositionWindow", ImmSetCompositionWindow as usize);
    exports.insert("ImmGetCompositionWindow", ImmGetCompositionWindow as usize);
    exports.insert("ImmSetCompositionFontW", ImmSetCompositionFontW as usize);
    exports.insert("ImmGetCompositionFontW", ImmGetCompositionFontW as usize);
    exports.insert("ImmNotifyIME", ImmNotifyIME as usize);
    exports.insert("ImmAssociateContext", ImmAssociateContext as usize);
    exports.insert("ImmSetCompositionStringW", ImmSetCompositionStringW as usize);
    exports.insert("ImmGetCompositionStringW", ImmGetCompositionStringW as usize);
    exports.insert("ImmAssociateContextEx", ImmAssociateContextEx as usize);
    exports.insert("ImmGetConversionStatus", ImmGetConversionStatus as usize);
    exports
}
