#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! dxgi.dll — Reimplemented DXGI API stubs for Unity graphics initialization.

use std::collections::HashMap;
use std::ffi::c_void;
use tracing::info;

const S_OK: i32 = 0;

#[repr(C)]
struct IUnknownVtbl {
    query_interface: extern "win64" fn(*mut c_void, *const c_void, *mut *mut c_void) -> i32,
    add_ref: extern "win64" fn(*mut c_void) -> u32,
    release: extern "win64" fn(*mut c_void) -> u32,
    slot3: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot4: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot5: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot6: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot7: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot8: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot9: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot10: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot11: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot12: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot13: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot14: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot15: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot16: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot17: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot18: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot19: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
    slot20: extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32,
}

extern "win64" fn dummy_query_interface(
    this_ptr: *mut c_void,
    _riid: *const c_void,
    ppv_object: *mut *mut c_void,
) -> i32 {
    if !ppv_object.is_null() {
        unsafe {
            *ppv_object = this_ptr;
        }
    }
    S_OK
}

extern "win64" fn dummy_add_ref(_this_ptr: *mut c_void) -> u32 {
    1
}

extern "win64" fn dummy_release(_this_ptr: *mut c_void) -> u32 {
    1
}

extern "win64" fn dummy_method(
    _this_ptr: *mut c_void,
    _a: *mut c_void,
    _b: *mut c_void,
    _c: *mut c_void,
) -> i32 {
    S_OK
}

static DUMMY_VTBL: IUnknownVtbl = IUnknownVtbl {
    query_interface: dummy_query_interface,
    add_ref: dummy_add_ref,
    release: dummy_release,
    slot3: dummy_method,
    slot4: dummy_method,
    slot5: dummy_method,
    slot6: dummy_method,
    slot7: dummy_method,
    slot8: dummy_method,
    slot9: dummy_method,
    slot10: dummy_method,
    slot11: dummy_method,
    slot12: dummy_method,
    slot13: dummy_method,
    slot14: dummy_method,
    slot15: dummy_method,
    slot16: dummy_method,
    slot17: dummy_method,
    slot18: dummy_method,
    slot19: dummy_method,
    slot20: dummy_method,
};

#[repr(C)]
struct DummyObject {
    vtbl: &'static IUnknownVtbl,
}

static DUMMY_OBJECT: DummyObject = DummyObject { vtbl: &DUMMY_VTBL };

pub extern "win64" fn CreateDXGIFactory(_riid: *const c_void, ppFactory: *mut *mut c_void) -> i32 {
    if let Some(address) = crate::dxvk::runtime::export(crate::dxvk::runtime::Library::Dxgi, "CreateDXGIFactory") {
        type Native = unsafe extern "win64" fn(*const c_void, *mut *mut c_void) -> i32;
        let native: Native = unsafe { std::mem::transmute(address) };
        let result = unsafe { native(_riid, ppFactory) };
        info!(result, factory = ?unsafe { ppFactory.as_ref().copied() }, "DXVK CreateDXGIFactory returned");
        return result;
    }
    info!("CreateDXGIFactory called");
    if !ppFactory.is_null() {
        unsafe {
            *ppFactory = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    S_OK
}

pub extern "win64" fn CreateDXGIFactory1(_riid: *const c_void, ppFactory: *mut *mut c_void) -> i32 {
    if let Some(address) = crate::dxvk::runtime::export(crate::dxvk::runtime::Library::Dxgi, "CreateDXGIFactory1") {
        type Native = unsafe extern "win64" fn(*const c_void, *mut *mut c_void) -> i32;
        let native: Native = unsafe { std::mem::transmute(address) };
        let result = unsafe { native(_riid, ppFactory) };
        info!(result, factory = ?unsafe { ppFactory.as_ref().copied() }, "DXVK CreateDXGIFactory1 returned");
        return result;
    }
    info!("CreateDXGIFactory1 called");
    if !ppFactory.is_null() {
        unsafe {
            *ppFactory = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    S_OK
}

pub extern "win64" fn CreateDXGIFactory2(
    _Flags: u32,
    _riid: *const c_void,
    ppFactory: *mut *mut c_void,
) -> i32 {
    if let Some(address) = crate::dxvk::runtime::export(crate::dxvk::runtime::Library::Dxgi, "CreateDXGIFactory2") {
        type Native = unsafe extern "win64" fn(u32, *const c_void, *mut *mut c_void) -> i32;
        let native: Native = unsafe { std::mem::transmute(address) };
        let result = unsafe { native(_Flags, _riid, ppFactory) };
        info!(result, factory = ?unsafe { ppFactory.as_ref().copied() }, "DXVK CreateDXGIFactory2 returned");
        return result;
    }
    info!("CreateDXGIFactory2 called");
    if !ppFactory.is_null() {
        unsafe {
            *ppFactory = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    S_OK
}

pub extern "win64" fn DXGIGetDebugInterface1(
    _Flags: u32,
    _riid: *const c_void,
    ppDebug: *mut *mut c_void,
) -> i32 {
    info!("DXGIGetDebugInterface1 called");
    if !ppDebug.is_null() {
        unsafe {
            *ppDebug = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    S_OK
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("CreateDXGIFactory", CreateDXGIFactory as usize);
    exports.insert("CreateDXGIFactory1", CreateDXGIFactory1 as usize);
    exports.insert("CreateDXGIFactory2", CreateDXGIFactory2 as usize);
    exports.insert("DXGIGetDebugInterface1", DXGIGetDebugInterface1 as usize);
    exports
}
