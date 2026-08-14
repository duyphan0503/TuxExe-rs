//! ole32.dll implementation

use std::collections::HashMap;

extern "win64" fn CoInitialize(_pvReserved: *mut u8) -> i32 {
    0 // S_OK
}

extern "win64" fn CoInitializeEx(_pvReserved: *mut u8, _dwCoInit: u32) -> i32 {
    0 // S_OK
}

extern "win64" fn CoUninitialize() {}

extern "win64" fn CoCreateInstance(
    _rclsid: *const u8,
    _pUnkOuter: *mut u8,
    _dwClsContext: u32,
    _riid: *const u8,
    ppv: *mut *mut u8,
) -> i32 {
    if !ppv.is_null() {
        unsafe {
            *ppv = std::ptr::null_mut();
        }
    }
    -2147467263 // E_NOTIMPL (0x80004001)
}

extern "win64" fn CoTaskMemFree(pv: *mut u8) {
    if !pv.is_null() {
        unsafe {
            libc::free(pv.cast());
        }
    }
}

extern "win64" fn CoTaskMemAlloc(cb: usize) -> *mut u8 {
    unsafe { libc::malloc(cb.max(1)).cast() }
}

extern "win64" fn CoTaskMemRealloc(pv: *mut u8, cb: usize) -> *mut u8 {
    // The COM task allocator accepts NULL as allocation and follows the
    // process allocator ownership model used by CoTaskMemAlloc/Free.
    unsafe { libc::realloc(pv.cast(), cb.max(1)).cast() }
}

extern "win64" fn CoCreateGuid(_pguid: *mut u8) -> i32 {
    tracing::trace!("CoCreateGuid — stub");
    if !_pguid.is_null() {
        unsafe {
            std::ptr::write_bytes(_pguid, 0, 16);
        }
    }
    -2147024809 // E_NOTIMPL
}

extern "win64" fn CoSetProxyBlanket(
    _pProxy: *mut u8,
    _dwAuthnSvc: u32,
    _dwAuthzSvc: u32,
    _pServerPrincName: *mut u8,
    _dwAuthnLevel: u32,
    _dwImpLevel: u32,
    _pAuthInfo: *mut u8,
    _dwCapabilities: u32,
) -> i32 {
    tracing::trace!("CoSetProxyBlanket — stub");
    0 // S_OK
}

extern "win64" fn CoCreateFreeThreadedMarshaler(_pUnkOuter: *mut u8, _ppunk: *mut *mut u8) -> i32 {
    tracing::trace!("CoCreateFreeThreadedMarshaler — stub");
    if !_ppunk.is_null() {
        unsafe {
            *_ppunk = std::ptr::null_mut();
        }
    }
    -2147467263 // E_NOTIMPL
}

extern "win64" fn PropVariantCopy(_pvarDest: *mut u8, _pvarSrc: *const u8) -> i32 {
    tracing::trace!("PropVariantCopy — stub");
    -2147467263 // E_NOTIMPL
}

extern "win64" fn PropVariantClear(pvar: *mut u8) -> i32 {
    tracing::trace!("PropVariantClear — stub");
    if !pvar.is_null() {
        unsafe {
            std::ptr::write_bytes(pvar, 0, 16);
        }
    }
    0 // S_OK
}

extern "win64" fn StringFromGUID2(rguid: *const u8, lpsz: *mut u16, cchMax: i32) -> i32 {
    tracing::trace!("StringFromGUID2 — stub");
    if rguid.is_null() || lpsz.is_null() || cchMax < 39 {
        return 0;
    }
    // Write a placeholder GUID string: {00000000-0000-0000-0000-000000000000}
    let guid_str: Vec<u16> = "{00000000-0000-0000-0000-000000000000}\0".encode_utf16().collect();
    unsafe {
        std::ptr::copy_nonoverlapping(guid_str.as_ptr(), lpsz, guid_str.len());
    }
    guid_str.len() as i32 - 1
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("CoInitialize", CoInitialize as usize);
    exports.insert("CoInitializeEx", CoInitializeEx as usize);
    exports.insert("CoUninitialize", CoUninitialize as usize);
    exports.insert("CoCreateInstance", CoCreateInstance as usize);
    exports.insert("CoTaskMemFree", CoTaskMemFree as usize);
    exports.insert("CoTaskMemAlloc", CoTaskMemAlloc as usize);
    exports.insert("CoTaskMemRealloc", CoTaskMemRealloc as usize);
    exports.insert("CoCreateGuid", CoCreateGuid as usize);
    exports.insert("CoSetProxyBlanket", CoSetProxyBlanket as usize);
    exports.insert("CoCreateFreeThreadedMarshaler", CoCreateFreeThreadedMarshaler as usize);
    exports.insert("PropVariantCopy", PropVariantCopy as usize);
    exports.insert("PropVariantClear", PropVariantClear as usize);
    exports.insert("StringFromGUID2", StringFromGUID2 as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::{CoTaskMemAlloc, CoTaskMemFree, CoTaskMemRealloc};

    #[test]
    fn task_allocator_reallocates_and_frees_memory() {
        let initial = CoTaskMemAlloc(4);
        assert!(!initial.is_null());
        unsafe {
            initial.copy_from_nonoverlapping([1u8, 2, 3, 4].as_ptr(), 4);
        }

        let grown = CoTaskMemRealloc(initial, 8);
        assert!(!grown.is_null());
        assert_eq!(unsafe { std::slice::from_raw_parts(grown, 4) }, [1, 2, 3, 4]);
        CoTaskMemFree(grown);
    }
}
