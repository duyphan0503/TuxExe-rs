#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! oleaut32.dll stubs.

use std::{collections::HashMap, ffi::c_void, mem::size_of, ptr};
use tracing::trace;

type BStr = *mut u16;

const S_OK: i32 = 0;
const E_INVALIDARG: i32 = 0x8007_0057_u32 as i32;
const E_OUTOFMEMORY: i32 = 0x8007_000E_u32 as i32;
const DISP_E_BADINDEX: i32 = 0x8002_000B_u32 as i32;
const DISP_E_TYPEMISMATCH: i32 = 0x8002_0005_u32 as i32;

const VT_EMPTY: u16 = 0;
const VT_I2: u16 = 2;
const VT_I4: u16 = 3;
const VT_R4: u16 = 4;
const VT_R8: u16 = 5;
const VT_BSTR: u16 = 8;
const VT_BOOL: u16 = 11;
const VT_UI1: u16 = 17;
const VT_UI2: u16 = 18;
const VT_UI4: u16 = 19;
const VT_I8: u16 = 20;
const VT_UI8: u16 = 21;
const VT_INT: u16 = 22;
const VT_UINT: u16 = 23;

#[repr(C, align(8))]
struct Variant {
    vt: u16,
    reserved1: u16,
    reserved2: u16,
    reserved3: u16,
    data: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SafeArrayBound {
    c_elements: u32,
    l_bound: i32,
}

/// The Windows SAFEARRAY header. Bounds immediately follow `pv_data`.
#[repr(C)]
struct SafeArray {
    c_dims: u16,
    f_features: u16,
    cb_elements: u32,
    c_locks: u32,
    pv_data: *mut c_void,
}

/// Private prefix for arrays created by this module. It lets destruction retain
/// the VARTYPE without changing the ABI-visible SAFEARRAY layout.
#[repr(C)]
struct SafeArrayPrefix {
    vt: u16,
    _reserved: u16,
    _padding: u32,
}

fn safe_array_bounds(array: *mut SafeArray) -> *mut SafeArrayBound {
    unsafe { (array.cast::<u8>()).add(size_of::<SafeArray>()).cast() }
}

fn safe_array_element_size(vt: u16) -> Option<usize> {
    match vt {
        0 | 1 => Some(0),
        2 | 11 | 18 => Some(2),
        3 | 4 | 10 | 19 | 22 | 23 => Some(4),
        5 | 6 | 7 | 8 | 9 | 13 | 20 | 21 => Some(8),
        12 | 14 => Some(16),
        16 | 17 => Some(1),
        _ => None,
    }
}

fn safe_array_element_offset(array: *mut SafeArray, indices: *const i32) -> Result<usize, i32> {
    if array.is_null() || indices.is_null() {
        return Err(E_INVALIDARG);
    }

    let dimensions = unsafe { (*array).c_dims as usize };
    if dimensions == 0 {
        return Err(E_INVALIDARG);
    }

    let bounds = safe_array_bounds(array);
    let mut stride = 1usize;
    let mut offset = 0usize;
    for dimension in 0..dimensions {
        let bound = unsafe { *bounds.add(dimension) };
        let index = unsafe { *indices.add(dimension) };
        let relative = index.checked_sub(bound.l_bound).ok_or(DISP_E_BADINDEX)? as u32;
        if relative >= bound.c_elements {
            return Err(DISP_E_BADINDEX);
        }
        offset = offset
            .checked_add((relative as usize).checked_mul(stride).ok_or(E_INVALIDARG)?)
            .ok_or(E_INVALIDARG)?;
        stride = stride.checked_mul(bound.c_elements as usize).ok_or(E_INVALIDARG)?;
    }
    Ok(offset)
}

fn safe_array_element_count(array: *mut SafeArray) -> Option<usize> {
    if array.is_null() || unsafe { (*array).c_dims } == 0 {
        return None;
    }
    let mut count = 1usize;
    for dimension in 0..unsafe { (*array).c_dims as usize } {
        count = count.checked_mul(unsafe {
            (*safe_array_bounds(array).add(dimension)).c_elements as usize
        })?;
    }
    Some(count)
}

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

extern "win64" fn VariantInit(pvarg: *mut Variant) -> i32 {
    trace!("VariantInit — stub");
    if !pvarg.is_null() {
        unsafe {
            ptr::write_bytes(pvarg, 0, 1);
        }
    }
    0
}

extern "win64" fn VariantClear(pvarg: *mut Variant) -> i32 {
    trace!("VariantClear — stub");
    if pvarg.is_null() {
        return E_INVALIDARG;
    }
    unsafe {
        if (*pvarg).vt == VT_BSTR {
            SysFreeString(*(std::ptr::addr_of!((*pvarg).data).cast::<*mut u8>()));
        }
        ptr::write_bytes(pvarg, 0, 1);
    }
    0
}

fn variant_number(value: &Variant) -> Option<f64> {
    unsafe {
        match value.vt {
            VT_I2 => Some(*(value.data.as_ptr().cast::<i16>()) as f64),
            VT_I4 | VT_INT => Some(*(value.data.as_ptr().cast::<i32>()) as f64),
            VT_R4 => Some(*(value.data.as_ptr().cast::<f32>()) as f64),
            VT_R8 => Some(*(value.data.as_ptr().cast::<f64>())),
            VT_BOOL => Some((*(value.data.as_ptr().cast::<i16>()) != 0) as u8 as f64),
            VT_UI1 => Some(*(value.data.as_ptr()) as f64),
            VT_UI2 => Some(*(value.data.as_ptr().cast::<u16>()) as f64),
            VT_UI4 | VT_UINT => Some(*(value.data.as_ptr().cast::<u32>()) as f64),
            VT_I8 => Some(*(value.data.as_ptr().cast::<i64>()) as f64),
            VT_UI8 => Some(*(value.data.as_ptr().cast::<u64>()) as f64),
            _ => None,
        }
    }
}

fn write_variant_number(destination: &mut Variant, vt: u16, value: f64) -> Result<(), i32> {
    destination.vt = vt;
    unsafe {
        match vt {
            VT_I2 => *(destination.data.as_mut_ptr().cast::<i16>()) = value as i16,
            VT_I4 | VT_INT => *(destination.data.as_mut_ptr().cast::<i32>()) = value as i32,
            VT_R4 => *(destination.data.as_mut_ptr().cast::<f32>()) = value as f32,
            VT_R8 => *(destination.data.as_mut_ptr().cast::<f64>()) = value,
            VT_BOOL => {
                *(destination.data.as_mut_ptr().cast::<i16>()) = if value == 0.0 { 0 } else { -1 }
            }
            VT_UI1 => *destination.data.as_mut_ptr() = value as u8,
            VT_UI2 => *(destination.data.as_mut_ptr().cast::<u16>()) = value as u16,
            VT_UI4 | VT_UINT => *(destination.data.as_mut_ptr().cast::<u32>()) = value as u32,
            VT_I8 => *(destination.data.as_mut_ptr().cast::<i64>()) = value as i64,
            VT_UI8 => *(destination.data.as_mut_ptr().cast::<u64>()) = value as u64,
            _ => return Err(DISP_E_TYPEMISMATCH),
        }
    }
    Ok(())
}

extern "win64" fn VariantChangeType(
    destination: *mut Variant,
    source: *const Variant,
    _flags: u16,
    target_vt: u16,
) -> i32 {
    if destination.is_null() || source.is_null() {
        return E_INVALIDARG;
    }
    let source = unsafe { &*source };
    let mut converted: Variant = unsafe { std::mem::zeroed() };

    if target_vt == VT_EMPTY {
        converted.vt = VT_EMPTY;
    } else if target_vt == source.vt {
        converted.vt = target_vt;
        if target_vt == VT_BSTR {
            let bstr = unsafe { *(source.data.as_ptr().cast::<*mut u8>()) };
            let copy = if bstr.is_null() {
                ptr::null_mut()
            } else {
                SysAllocStringLen(bstr.cast(), SysStringLen(bstr))
            };
            if !bstr.is_null() && copy.is_null() {
                return E_OUTOFMEMORY;
            }
            unsafe { *(converted.data.as_mut_ptr().cast::<*mut u8>()) = copy };
        } else {
            converted.data.copy_from_slice(&source.data);
        }
    } else if target_vt == VT_BSTR {
        let Some(number) = variant_number(source) else {
            return DISP_E_TYPEMISMATCH;
        };
        let text = number.to_string();
        let wide: Vec<u16> = text.encode_utf16().collect();
        let bstr = SysAllocStringLen(wide.as_ptr(), wide.len() as u32);
        if bstr.is_null() {
            return E_OUTOFMEMORY;
        }
        converted.vt = VT_BSTR;
        unsafe { *(converted.data.as_mut_ptr().cast::<*mut u8>()) = bstr };
    } else {
        let number = if source.vt == VT_BSTR {
            let bstr = unsafe { *(source.data.as_ptr().cast::<*mut u8>()) };
            if bstr.is_null() {
                return DISP_E_TYPEMISMATCH;
            }
            let chars = unsafe {
                std::slice::from_raw_parts(bstr.cast::<u16>(), SysStringLen(bstr) as usize)
            };
            let text = String::from_utf16_lossy(chars);
            match text.trim().parse::<f64>() {
                Ok(number) => number,
                Err(_) => return DISP_E_TYPEMISMATCH,
            }
        } else if let Some(number) = variant_number(source) {
            number
        } else {
            return DISP_E_TYPEMISMATCH;
        };
        if let Err(error) = write_variant_number(&mut converted, target_vt, number) {
            return error;
        }
    }

    unsafe { ptr::write(destination, converted) };
    S_OK
}

extern "win64" fn SafeArrayCreate(
    vt: u16,
    c_dims: u32,
    bounds: *const SafeArrayBound,
) -> *mut SafeArray {
    trace!(vt, c_dims, "SafeArrayCreate");
    let dimensions = c_dims as usize;
    let Some(element_size) = safe_array_element_size(vt) else {
        return ptr::null_mut();
    };
    if dimensions == 0 || bounds.is_null() {
        return ptr::null_mut();
    }

    let mut element_count = 1usize;
    for dimension in 0..dimensions {
        let bound = unsafe { *bounds.add(dimension) };
        element_count = match element_count.checked_mul(bound.c_elements as usize) {
            Some(value) => value,
            None => return ptr::null_mut(),
        };
    }
    let data_bytes = match element_count.checked_mul(element_size) {
        Some(value) => value,
        None => return ptr::null_mut(),
    };
    let array_bytes = match size_of::<SafeArray>()
        .checked_add(dimensions.saturating_mul(size_of::<SafeArrayBound>()))
    {
        Some(value) => value,
        None => return ptr::null_mut(),
    };
    let total_bytes = match size_of::<SafeArrayPrefix>()
        .checked_add(array_bytes)
        .and_then(|value| value.checked_add(data_bytes.max(1)))
    {
        Some(value) => value,
        None => return ptr::null_mut(),
    };

    let raw = unsafe { libc::calloc(1, total_bytes).cast::<u8>() };
    if raw.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let prefix = raw.cast::<SafeArrayPrefix>();
        (*prefix).vt = vt;
        let array = raw.add(size_of::<SafeArrayPrefix>()).cast::<SafeArray>();
        (*array).c_dims = c_dims as u16;
        (*array).cb_elements = element_size as u32;
        (*array).pv_data = raw.add(size_of::<SafeArrayPrefix>() + array_bytes).cast();
        ptr::copy_nonoverlapping(bounds, safe_array_bounds(array), dimensions);
        array
    }
}

extern "win64" fn SafeArrayDestroy(array: *mut SafeArray) -> i32 {
    trace!(array = ?array, "SafeArrayDestroy");
    if array.is_null() {
        return E_INVALIDARG;
    }
    if unsafe { (*array).c_locks } != 0 {
        return E_INVALIDARG;
    }

    let prefix =
        unsafe { (array.cast::<u8>()).sub(size_of::<SafeArrayPrefix>()).cast::<SafeArrayPrefix>() };
    if unsafe { (*prefix).vt } == VT_BSTR {
        let count = safe_array_element_count(array).unwrap_or(0);
        let values = unsafe { (*array).pv_data.cast::<*mut u8>() };
        for index in 0..count {
            unsafe { SysFreeString(*values.add(index)) };
        }
    }
    unsafe { libc::free(prefix.cast()) };
    S_OK
}

extern "win64" fn SafeArrayPtrOfIndex(
    array: *mut SafeArray,
    indices: *const i32,
    result: *mut *mut c_void,
) -> i32 {
    if result.is_null() {
        return E_INVALIDARG;
    }
    let offset = match safe_array_element_offset(array, indices) {
        Ok(offset) => offset,
        Err(error) => return error,
    };
    unsafe {
        *result =
            ((*array).pv_data.cast::<u8>()).add(offset * (*array).cb_elements as usize).cast();
    }
    S_OK
}

extern "win64" fn SafeArrayGetDim(array: *mut SafeArray) -> u32 {
    if array.is_null() {
        0
    } else {
        unsafe { (*array).c_dims as u32 }
    }
}

extern "win64" fn SafeArrayGetLBound(
    array: *mut SafeArray,
    dimension: u32,
    result: *mut i32,
) -> i32 {
    if array.is_null()
        || result.is_null()
        || dimension == 0
        || dimension > unsafe { (*array).c_dims as u32 }
    {
        return E_INVALIDARG;
    }
    unsafe { *result = (*safe_array_bounds(array).add((dimension - 1) as usize)).l_bound };
    S_OK
}

extern "win64" fn SafeArrayGetUBound(
    array: *mut SafeArray,
    dimension: u32,
    result: *mut i32,
) -> i32 {
    if array.is_null()
        || result.is_null()
        || dimension == 0
        || dimension > unsafe { (*array).c_dims as u32 }
    {
        return E_INVALIDARG;
    }
    let bound = unsafe { *safe_array_bounds(array).add((dimension - 1) as usize) };
    match bound.l_bound.checked_add(bound.c_elements as i32).and_then(|value| value.checked_sub(1))
    {
        Some(value) => {
            unsafe { *result = value };
            S_OK
        }
        None => E_INVALIDARG,
    }
}

extern "win64" fn SafeArrayPutElement(
    array: *mut SafeArray,
    indices: *const i32,
    value: *const c_void,
) -> i32 {
    if value.is_null() {
        return E_INVALIDARG;
    }
    let offset = match safe_array_element_offset(array, indices) {
        Ok(offset) => offset,
        Err(error) => return error,
    };
    let element_size = unsafe { (*array).cb_elements as usize };
    let destination = unsafe { ((*array).pv_data.cast::<u8>()).add(offset * element_size) };
    if unsafe {
        (*(array.cast::<u8>()).sub(size_of::<SafeArrayPrefix>()).cast::<SafeArrayPrefix>()).vt
    } == VT_BSTR
    {
        let source = unsafe { *(value.cast::<*mut u8>()) };
        let copy = if source.is_null() {
            ptr::null_mut()
        } else {
            SysAllocStringLen(source.cast(), SysStringLen(source))
        };
        if !source.is_null() && copy.is_null() {
            return E_OUTOFMEMORY;
        }
        unsafe { *(destination.cast::<*mut u8>()) = copy };
    } else {
        unsafe { ptr::copy_nonoverlapping(value.cast::<u8>(), destination, element_size) };
    }
    S_OK
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
    exports.insert("VariantChangeType", VariantChangeType as usize);
    // Ordinal exports (oleaut32 uses ordinal-based exports heavily)
    exports.insert("#2", SysAllocString as usize);
    exports.insert("#4", SysAllocStringLen as usize);
    exports.insert("#6", SysFreeString as usize);
    exports.insert("#7", SysStringLen as usize);
    exports.insert("#8", VariantInit as usize);
    exports.insert("#9", VariantClear as usize);
    exports.insert("#12", VariantChangeType as usize);
    exports.insert("#15", SafeArrayCreate as usize);
    exports.insert("#16", SafeArrayDestroy as usize);
    exports.insert("#17", SafeArrayGetDim as usize);
    exports.insert("#19", SafeArrayGetUBound as usize);
    exports.insert("#20", SafeArrayGetLBound as usize);
    exports.insert("#26", SafeArrayPutElement as usize);
    exports.insert("#148", SafeArrayPtrOfIndex as usize);
    exports
}
