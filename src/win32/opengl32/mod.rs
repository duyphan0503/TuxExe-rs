#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! opengl32.dll — OpenGL stubs that delegate to real GL via GLX.

use std::collections::HashMap;
use std::ffi::c_void;
use tracing::trace;

use crate::platform::x11;

extern "win64" fn wglCreateContext(_hDc: usize) -> usize {
    trace!("wglCreateContext — creating real GLX context");
    if let Some(hglrc) = x11::create_gl_context() {
        return hglrc;
    }
    trace!("wglCreateContext — fallback to stub");
    0
}

extern "win64" fn wglDeleteContext(_hglrc: usize) -> i32 {
    trace!("wglDeleteContext — stub");
    1
}

extern "win64" fn wglMakeCurrent(_hDc: usize, hglrc: usize) -> i32 {
    trace!("wglMakeCurrent(hglrc=0x{:x})", hglrc);
    if x11::make_gl_context_current(hglrc) {
        return 1;
    }
    trace!("wglMakeCurrent — fallback success");
    1
}

extern "win64" fn wglGetProcAddress(_lpszProc: *const u8) -> usize {
    if _lpszProc.is_null() {
        return 0;
    }

    // Use GLX to get real GL function address
    extern "C" {
        fn glXGetProcAddressARB(proc_name: *const u8) -> *const c_void;
    }

    unsafe {
        let proc_addr = glXGetProcAddressARB(_lpszProc);
        if !proc_addr.is_null() {
            return proc_addr as usize;
        }
    }

    trace!("wglGetProcAddress — fallback (null)");
    0
}

extern "win64" fn wglGetCurrentContext() -> usize {
    trace!("wglGetCurrentContext — stub");
    0
}

extern "win64" fn wglGetCurrentDC() -> usize {
    trace!("wglGetCurrentDC — stub");
    0
}

extern "win64" fn wglShareLists(_hglrc1: usize, _hglrc2: usize) -> i32 {
    trace!("wglShareLists — stub");
    1
}

extern "win64" fn wglCopyContext(_hglrcSrc: usize, _hglrcDst: usize, _mask: u32) -> i32 {
    trace!("wglCopyContext — stub");
    1
}

pub extern "win64" fn SwapBuffers(_hdc: usize) -> i32 {
    trace!("SwapBuffers — calling glXSwapBuffers on current drawable");
    extern "C" {
        fn glXGetCurrentDrawable() -> u64;
        fn glXSwapBuffers(dpy: *mut c_void, drawable: u64);
    }

    if let Some(display) = x11::x11_display() {
        unsafe {
            let drawable = glXGetCurrentDrawable();
            if drawable != 0 {
                glXSwapBuffers(display as *mut c_void, drawable);
                return 1;
            }
        }
    }
    1
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("wglCreateContext", wglCreateContext as usize);
    exports.insert("wglDeleteContext", wglDeleteContext as usize);
    exports.insert("wglMakeCurrent", wglMakeCurrent as usize);
    exports.insert("wglGetProcAddress", wglGetProcAddress as usize);
    exports.insert("wglGetCurrentContext", wglGetCurrentContext as usize);
    exports.insert("wglGetCurrentDC", wglGetCurrentDC as usize);
    exports.insert("wglShareLists", wglShareLists as usize);
    exports.insert("wglCopyContext", wglCopyContext as usize);
    exports.insert("SwapBuffers", SwapBuffers as usize);
    exports
}
