#![allow(non_snake_case)]

use std::ffi::c_void;

use crate::{nt_kernel::thread as nt_thread, threading::tls, utils::handle::Handle};

pub extern "win64" fn TlsAlloc() -> u32 {
    tls::tls_alloc()
}

pub extern "win64" fn TlsFree(dwTlsIndex: u32) -> i32 {
    tls::tls_free(dwTlsIndex) as i32
}

pub extern "win64" fn TlsSetValue(dwTlsIndex: u32, lpTlsValue: *mut c_void) -> i32 {
    tls::tls_set_value(dwTlsIndex, lpTlsValue) as i32
}

pub extern "win64" fn TlsGetValue(dwTlsIndex: u32) -> *mut c_void {
    tls::tls_get_value(dwTlsIndex)
}

pub extern "win64" fn CreateThread(
    lpThreadAttributes: *const c_void,
    dwStackSize: usize,
    lpStartAddress: *const c_void,
    lpParameter: *mut c_void,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> Handle {
    nt_thread::create_thread(
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
    )
}

pub extern "win64" fn ExitThread(dwExitCode: u32) -> ! {
    nt_thread::exit_thread(dwExitCode)
}

pub extern "win64" fn GetCurrentThread() -> Handle {
    nt_thread::current_thread_pseudo_handle()
}

pub extern "win64" fn SuspendThread(hThread: Handle) -> u32 {
    nt_thread::suspend_thread(hThread)
}

pub extern "win64" fn ResumeThread(hThread: Handle) -> u32 {
    nt_thread::resume_thread(hThread)
}
