#![allow(non_snake_case)]

use std::ffi::c_void;

use crate::{
    memory::{
        heap,
        virtual_alloc::{self, MemoryBasicInformation},
    },
    utils::handle::Handle,
};

pub extern "win64" fn VirtualAlloc(
    lpAddress: *mut c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut c_void {
    virtual_alloc::virtual_alloc(lpAddress, dwSize, flAllocationType, flProtect)
}

pub extern "win64" fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32 {
    virtual_alloc::virtual_free(lpAddress, dwSize, dwFreeType)
}

pub extern "win64" fn VirtualProtect(
    lpAddress: *mut c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> i32 {
    virtual_alloc::virtual_protect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
}

pub extern "win64" fn VirtualQuery(
    lpAddress: *const c_void,
    lpBuffer: *mut c_void,
    dwLength: usize,
) -> usize {
    virtual_alloc::virtual_query(lpAddress, lpBuffer.cast::<MemoryBasicInformation>(), dwLength)
}

pub extern "win64" fn HeapCreate(
    flOptions: u32,
    dwInitialSize: usize,
    dwMaximumSize: usize,
) -> Handle {
    heap::heap_create(flOptions, dwInitialSize, dwMaximumSize)
}

pub extern "win64" fn HeapAlloc(hHeap: Handle, dwFlags: u32, dwBytes: usize) -> *mut c_void {
    heap::heap_alloc(hHeap, dwFlags, dwBytes)
}

pub extern "win64" fn HeapFree(hHeap: Handle, dwFlags: u32, lpMem: *mut c_void) -> i32 {
    heap::heap_free(hHeap, dwFlags, lpMem)
}

pub extern "win64" fn HeapDestroy(hHeap: Handle) -> i32 {
    heap::heap_destroy(hHeap)
}

pub extern "win64" fn GetProcessHeap() -> Handle {
    heap::get_process_heap()
}
