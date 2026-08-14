#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! d3d11.dll — Reimplemented Direct3D 11 API stubs for Unity graphics initialization.

use std::collections::HashMap;
use std::ffi::c_void;
use tracing::info;

const S_OK: i32 = 0;
const D3D_FEATURE_LEVEL_11_0: u32 = 0xb000;
const D3D_FEATURE_LEVEL_11_1: u32 = 0xb100;

#[repr(C)]
struct IUnknownVtbl {
    query_interface: extern "win64" fn(*mut c_void, *const c_void, *mut *mut c_void) -> i32,
    add_ref: extern "win64" fn(*mut c_void) -> u32,
    release: extern "win64" fn(*mut c_void) -> u32,
    // Add extra generic method slots so method calls like GetFeatureLevel or CreateTexture2D hit valid function pointers
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

pub extern "win64" fn D3D11CreateDevice(
    pAdapter: *mut c_void,
    driver_type: u32,
    software: usize,
    flags: u32,
    feature_levels: *const u32,
    feature_level_count: u32,
    sdk_version: u32,
    ppDevice: *mut *mut c_void,
    pFeatureLevel: *mut u32,
    ppImmediateContext: *mut *mut c_void,
) -> i32 {
    if let Some(address) = crate::dxvk::runtime::export(
        crate::dxvk::runtime::Library::D3d11,
        "D3D11CreateDevice",
    ) {
        type Native = unsafe extern "win64" fn(
            *mut c_void,
            u32,
            usize,
            u32,
            *const u32,
            u32,
            u32,
            *mut *mut c_void,
            *mut u32,
            *mut *mut c_void,
        ) -> i32;
        let native: Native = unsafe { std::mem::transmute(address) };
        let result = unsafe {
            native(
                pAdapter,
                driver_type,
                software,
                flags,
                feature_levels,
                feature_level_count,
                sdk_version,
                ppDevice,
                pFeatureLevel,
                ppImmediateContext,
            )
        };
        info!(result, device = ?unsafe { ppDevice.as_ref().copied() }, "DXVK D3D11CreateDevice returned");
        return result;
    }
    info!("D3D11CreateDevice called");
    if !ppDevice.is_null() {
        unsafe {
            *ppDevice = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    if !ppImmediateContext.is_null() {
        unsafe {
            *ppImmediateContext = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    if !pFeatureLevel.is_null() {
        unsafe {
            *pFeatureLevel = D3D_FEATURE_LEVEL_11_1;
        }
    }
    S_OK
}

pub extern "win64" fn D3D11CreateDeviceAndSwapChain(
    pAdapter: *mut c_void,
    driver_type: u32,
    software: usize,
    flags: u32,
    feature_levels: *const u32,
    feature_level_count: u32,
    sdk_version: u32,
    swap_chain_desc: *const c_void,
    ppSwapChain: *mut *mut c_void,
    ppDevice: *mut *mut c_void,
    pFeatureLevel: *mut u32,
    ppImmediateContext: *mut *mut c_void,
) -> i32 {
    if let Some(address) = crate::dxvk::runtime::export(
        crate::dxvk::runtime::Library::D3d11,
        "D3D11CreateDeviceAndSwapChain",
    ) {
        type Native = unsafe extern "win64" fn(
            *mut c_void,
            u32,
            usize,
            u32,
            *const u32,
            u32,
            u32,
            *const c_void,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut u32,
            *mut *mut c_void,
        ) -> i32;
        let native: Native = unsafe { std::mem::transmute(address) };
        let result = unsafe {
            native(
                pAdapter,
                driver_type,
                software,
                flags,
                feature_levels,
                feature_level_count,
                sdk_version,
                swap_chain_desc,
                ppSwapChain,
                ppDevice,
                pFeatureLevel,
                ppImmediateContext,
            )
        };
        info!(result, device = ?unsafe { ppDevice.as_ref().copied() }, swapchain = ?unsafe { ppSwapChain.as_ref().copied() }, "DXVK D3D11CreateDeviceAndSwapChain returned");
        return result;
    }
    info!("D3D11CreateDeviceAndSwapChain called");
    if !ppSwapChain.is_null() {
        unsafe {
            *ppSwapChain = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    if !ppDevice.is_null() {
        unsafe {
            *ppDevice = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    if !ppImmediateContext.is_null() {
        unsafe {
            *ppImmediateContext = (&DUMMY_OBJECT as *const DummyObject as *mut DummyObject).cast();
        }
    }
    if !pFeatureLevel.is_null() {
        unsafe {
            *pFeatureLevel = D3D_FEATURE_LEVEL_11_1;
        }
    }
    S_OK
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("D3D11CreateDevice", D3D11CreateDevice as usize);
    exports.insert("D3D11CreateDeviceAndSwapChain", D3D11CreateDeviceAndSwapChain as usize);
    exports
}
