#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! oleaut32.dll stubs.

use std::collections::HashMap;
use tracing::trace;

type BStr = *mut u16;

fn bstr_len_chars(bstr: BStr) -> u32 {
    if bstr.is_null() {
        return 0;
    }
    unsafe {
        let prefix = (bstr as *mut u8).sub(4).cast::<u32>();
        (*prefix) / 2
    }
}

extern "win64" fn SysAllocString(src: *const u16) -> *mut u8 {
    trace!("SysAllocString — stub");
    if src.is_null() {
        return std::ptr::null_mut();
    }

    let mut len = 0usize;
    unsafe {
        while *src.add(len) != 0 {
            len += 1;
        }
    }

    SysAllocStringLen(src, len as u32)
}

extern "win64" fn SysAllocStringLen(src: *const u16, len: u32) -> *mut u8 {
    trace!("SysAllocStringLen(len={}) — stub", len);
    let chars = len as usize;
    let total_bytes = 4usize.saturating_add((chars + 1).saturating_mul(2));
    let raw = unsafe { libc::malloc(total_bytes) as *mut u8 };
    if raw.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        *(raw.cast::<u32>()) = (chars as u32) * 2;
        let bstr = raw.add(4).cast::<u16>();
        if !src.is_null() && chars > 0 {
            std::ptr::copy_nonoverlapping(src, bstr, chars);
        } else if chars > 0 {
            std::ptr::write_bytes(bstr, 0, chars);
        }
        *bstr.add(chars) = 0;
        bstr.cast::<u8>()
    }
}

extern "win64" fn SysReAllocStringLen(pbstr: *mut BStr, src: *const u16, len: u32) -> i32 {
    trace!("SysReAllocStringLen(len={}) — stub", len);
    if pbstr.is_null() {
        return 0;
    }

    let new_bstr = SysAllocStringLen(src, len).cast::<u16>();
    if new_bstr.is_null() && len != 0 {
        return 0;
    }

    unsafe {
        let old = *pbstr;
        *pbstr = new_bstr;
        if !old.is_null() {
            libc::free((old as *mut u8).sub(4).cast());
        }
    }

    1
}

extern "win64" fn SysFreeString(bstr: *mut u8) {
    trace!("SysFreeString — stub");
    if bstr.is_null() {
        return;
    }
    unsafe {
        libc::free(bstr.sub(4).cast());
    }
}

extern "win64" fn SysStringLen(bstr: *mut u8) -> u32 {
    trace!("SysStringLen — stub");
    bstr_len_chars(bstr.cast::<u16>())
}

extern "win64" fn VariantInit(pvarg: *mut u8) -> i32 {
    trace!("VariantInit — stub");
    if !pvarg.is_null() {
        unsafe {
            std::ptr::write_bytes(pvarg, 0, 16);
        }
    }
    0
}

extern "win64" fn VariantClear(_pvarg: *mut u8) -> i32 {
    trace!("VariantClear — stub");
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    // Named exports
    exports.insert("SysAllocString", SysAllocString as usize);
    exports.insert("SysFreeString", SysFreeString as usize);
    exports.insert("SysAllocStringLen", SysAllocStringLen as usize);
    exports.insert("SysReAllocStringLen", SysReAllocStringLen as usize);
    exports.insert("SysStringLen", SysStringLen as usize);
    exports.insert("VariantInit", VariantInit as usize);
    exports.insert("VariantClear", VariantClear as usize);
    // Ordinal exports (oleaut32 uses ordinal-based exports heavily)
    exports.insert("#2", SysAllocString as usize);
    exports.insert("#6", SysFreeString as usize);
    exports.insert("#9", SysAllocStringLen as usize);
    exports.insert("#8", SysReAllocStringLen as usize);
    exports.insert("#12", SysStringLen as usize);
    exports.insert("#144", VariantInit as usize);
    exports.insert("#145", VariantClear as usize);
    exports
}

