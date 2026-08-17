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

extern "win64" fn wglMakeCurrent(hDc: usize, hglrc: usize) -> i32 {
    let target_hwnd = crate::win32::user32::window::hdc_to_hwnd(hDc)
        .or_else(|| {
            let active = crate::win32::user32::window::GetActiveWindow();
            if active != 0 { Some(active) } else { None }
        });
    trace!(hDc, hglrc, ?target_hwnd, "wglMakeCurrent");
    if x11::make_gl_context_current_for_window(hglrc, target_hwnd) {
        return 1;
    }
    trace!("wglMakeCurrent — fallback success");
    1
}

static WGL_EXTENSIONS: &[u8] = b"WGL_ARB_extensions_string WGL_EXT_extensions_string WGL_ARB_pixel_format WGL_ARB_create_context WGL_ARB_create_context_profile WGL_EXT_swap_control\0";

extern "win64" fn wglGetExtensionsStringARB(_hdc: usize) -> *const u8 {
    WGL_EXTENSIONS.as_ptr()
}

extern "win64" fn wglGetExtensionsStringEXT() -> *const u8 {
    WGL_EXTENSIONS.as_ptr()
}

extern "win64" fn wglCreateContextAttribsARB(
    _hdc: usize,
    _hShareContext: usize,
    _attribList: *const i32,
) -> usize {
    trace!("wglCreateContextAttribsARB — creating GL context");
    if let Some(hglrc) = x11::create_gl_context() {
        return hglrc;
    }
    1
}

extern "win64" fn wglChoosePixelFormatARB(
    _hdc: usize,
    _piAttribIList: *const i32,
    _pfAttribFList: *const f32,
    _nMaxFormats: u32,
    piFormats: *mut i32,
    nNumFormats: *mut u32,
) -> i32 {
    if !piFormats.is_null() && !nNumFormats.is_null() {
        unsafe {
            *piFormats = 1;
            *nNumFormats = 1;
        }
    }
    1
}

extern "win64" fn wglSwapIntervalEXT(_interval: i32) -> i32 {
    1
}

extern "win64" fn wglGetSwapIntervalEXT() -> i32 {
    1
}

extern "win64" fn wglGetPixelFormatAttribivARB(
    _hdc: usize,
    _iPixelFormat: i32,
    _iLayerPlane: i32,
    nAttributes: u32,
    piAttributes: *const i32,
    piValues: *mut i32,
) -> i32 {
    if piAttributes.is_null() || piValues.is_null() {
        return 0;
    }
    for i in 0..nAttributes as usize {
        let attr = unsafe { *piAttributes.add(i) };
        let val = match attr {
            0x2001 /* WGL_DRAW_TO_WINDOW_ARB */ => 1,
            0x2010 /* WGL_SUPPORT_OPENGL_ARB */ => 1,
            0x2011 /* WGL_DOUBLE_BUFFER_ARB */ => 1,
            0x2012 /* WGL_STEREO_ARB */ => 0,
            0x2013 /* WGL_PIXEL_TYPE_ARB */ => 0x2027, /* WGL_TYPE_RGBA_ARB */
            0x2014 /* WGL_COLOR_BITS_ARB */ => 32,
            0x2015 /* WGL_RED_BITS_ARB */ => 8,
            0x2017 /* WGL_GREEN_BITS_ARB */ => 8,
            0x2019 /* WGL_BLUE_BITS_ARB */ => 8,
            0x201B /* WGL_ALPHA_BITS_ARB */ => 8,
            0x2022 /* WGL_DEPTH_BITS_ARB */ => 24,
            0x2023 /* WGL_STENCIL_BITS_ARB */ => 8,
            0x2041 /* WGL_SAMPLE_BUFFERS_ARB */ => 0,
            0x2042 /* WGL_SAMPLES_ARB */ => 0,
            0x202B /* WGL_FRAMEBUFFER_SRGB_CAPABLE_ARB */ => 1,
            _ => 0,
        };
        unsafe {
            *piValues.add(i) = val;
        }
    }
    1
}

extern "win64" fn wglGetPixelFormatAttribfvARB(
    _hdc: usize,
    _iPixelFormat: i32,
    _iLayerPlane: i32,
    nAttributes: u32,
    piAttributes: *const i32,
    pfValues: *mut f32,
) -> i32 {
    if piAttributes.is_null() || pfValues.is_null() {
        return 0;
    }
    for i in 0..nAttributes as usize {
        let attr = unsafe { *piAttributes.add(i) };
        let val = match attr {
            0x2001 /* WGL_DRAW_TO_WINDOW_ARB */ => 1.0,
            0x2010 /* WGL_SUPPORT_OPENGL_ARB */ => 1.0,
            0x2011 /* WGL_DOUBLE_BUFFER_ARB */ => 1.0,
            0x2014 /* WGL_COLOR_BITS_ARB */ => 32.0,
            0x2022 /* WGL_DEPTH_BITS_ARB */ => 24.0,
            0x2023 /* WGL_STENCIL_BITS_ARB */ => 8.0,
            _ => 0.0,
        };
        unsafe {
            *pfValues.add(i) = val;
        }
    }
    1
}

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

struct TrampolinePool {
    base: usize,
    capacity: usize,
}

static TRAMPOLINE_POOL: OnceLock<Mutex<TrampolinePool>> = OnceLock::new();
static NEXT_TRAMPOLINE_OFFSET: AtomicUsize = AtomicUsize::new(0);
static THUNK_CACHE: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn thunk_cache() -> &'static Mutex<HashMap<String, usize>> {
    THUNK_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_trampoline_pool() -> &'static Mutex<TrampolinePool> {
    TRAMPOLINE_POOL.get_or_init(|| {
        let size = 128 * 1024;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        Mutex::new(TrampolinePool {
            base: ptr as usize,
            capacity: size,
        })
    })
}

pub fn resolve_gl_function(name: &str) -> Option<usize> {
    if let Ok(cache) = thunk_cache().lock() {
        if let Some(&addr) = cache.get(name) {
            return Some(addr);
        }
    }

    let c_name = std::ffi::CString::new(name).ok()?;
    let native_addr = unsafe {
        extern "C" {
            fn glXGetProcAddressARB(proc_name: *const u8) -> *const c_void;
        }
        let p = glXGetProcAddressARB(c_name.as_ptr() as *const u8);
        if !p.is_null() {
            p as usize
        } else {
            libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr()) as usize
        }
    };

    if native_addr == 0 {
        return None;
    }

    let offset = NEXT_TRAMPOLINE_OFFSET.fetch_add(128, Ordering::Relaxed);
    let pool = get_trampoline_pool().lock().ok()?;
    if offset + 128 > pool.capacity {
        trace!("OpenGL trampoline pool exhausted");
        return None;
    }

    let tramp_ptr = (pool.base + offset) as *mut u8;
    let mut code: Vec<u8> = Vec::with_capacity(128);
    // push %rbp
    code.push(0x55);
    // mov %rsp, %rbp
    code.extend_from_slice(&[0x48, 0x89, 0xE5]);
    // push %rsi
    code.push(0x56);
    // push %rdi
    code.push(0x57);
    // sub $0x20, %rsp (Stack args space for SysV Args 7..10)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    // mov 0x40(%rbp), %rax -> mov %rax, 0x00(%rsp) (SysV Arg 7)
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0x40]);
    code.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);
    // mov 0x48(%rbp), %rax -> mov %rax, 0x08(%rsp) (SysV Arg 8)
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0x48]);
    code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x08]);
    // mov 0x50(%rbp), %rax -> mov %rax, 0x10(%rsp) (SysV Arg 9)
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0x50]);
    code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]);
    // mov 0x58(%rbp), %rax -> mov %rax, 0x18(%rsp) (SysV Arg 10)
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0x58]);
    code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]);
    // mov %rcx, %rdi
    code.extend_from_slice(&[0x48, 0x89, 0xCF]);
    // mov %rdx, %rsi
    code.extend_from_slice(&[0x48, 0x89, 0xD6]);
    // mov %r8, %rdx
    code.extend_from_slice(&[0x4C, 0x89, 0xC2]);
    // mov %r9, %rcx
    code.extend_from_slice(&[0x4C, 0x89, 0xC9]);
    // mov 0x30(%rbp), %r8 (Win64 Arg 5)
    code.extend_from_slice(&[0x4C, 0x8B, 0x45, 0x30]);
    // mov 0x38(%rbp), %r9 (Win64 Arg 6)
    code.extend_from_slice(&[0x4C, 0x8B, 0x4D, 0x38]);
    // movabsq $native_addr, %r11
    code.extend_from_slice(&[0x49, 0xBB]);
    code.extend_from_slice(&native_addr.to_le_bytes());
    // callq *%r11
    code.extend_from_slice(&[0x41, 0xFF, 0xD3]);
    // lea -0x10(%rbp), %rsp
    code.extend_from_slice(&[0x48, 0x8D, 0x65, 0xF0]);
    // pop %rdi
    code.push(0x5F);
    // pop %rsi
    code.push(0x5E);
    // pop %rbp
    code.push(0x5D);
    // ret
    code.push(0xC3);

    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), tramp_ptr, code.len());
    }

    let thunk_addr = tramp_ptr as usize;
    if let Ok(mut cache) = thunk_cache().lock() {
        cache.insert(name.to_string(), thunk_addr);
    }

    trace!(name, native_addr = format_args!("0x{:x}", native_addr), thunk_addr = format_args!("0x{:x}", thunk_addr), "Bridged OpenGL function Win64 thunk");
    Some(thunk_addr)
}

extern "win64" fn wglGetProcAddress(lpszProc: *const u8) -> usize {
    if lpszProc.is_null() {
        return 0;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(lpszProc.cast()) }.to_str().unwrap_or_default();
    match name {
        "wglGetExtensionsStringARB" => return wglGetExtensionsStringARB as usize,
        "wglGetExtensionsStringEXT" => return wglGetExtensionsStringEXT as usize,
        "wglCreateContextAttribsARB" => return wglCreateContextAttribsARB as usize,
        "wglChoosePixelFormatARB" => return wglChoosePixelFormatARB as usize,
        "wglGetPixelFormatAttribivARB" => return wglGetPixelFormatAttribivARB as usize,
        "wglGetPixelFormatAttribfvARB" => return wglGetPixelFormatAttribfvARB as usize,
        "wglSwapIntervalEXT" => return wglSwapIntervalEXT as usize,
        "wglGetSwapIntervalEXT" => return wglGetSwapIntervalEXT as usize,
        _ => {}
    }

    if name.starts_with("wgl") {
        trace!(name, "wglGetProcAddress unhandled WGL function");
        return 0;
    }

    if let Some(thunk) = resolve_gl_function(name) {
        return thunk;
    }

    trace!(name, "wglGetProcAddress — fallback (null)");
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
    crate::platform::x11::swap_buffers(0);
    1
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("wglCreateContext", wglCreateContext as usize);
    exports.insert("wglDeleteContext", wglDeleteContext as usize);
    exports.insert("wglMakeCurrent", wglMakeCurrent as usize);
    exports.insert("wglGetProcAddress", wglGetProcAddress as usize);
    exports.insert("wglGetPixelFormatAttribivARB", wglGetPixelFormatAttribivARB as usize);
    exports.insert("wglGetPixelFormatAttribfvARB", wglGetPixelFormatAttribfvARB as usize);
    exports.insert("wglGetCurrentContext", wglGetCurrentContext as usize);
    exports.insert("wglGetCurrentDC", wglGetCurrentDC as usize);
    exports.insert("wglShareLists", wglShareLists as usize);
    exports.insert("wglCopyContext", wglCopyContext as usize);
    exports.insert("wglSwapIntervalEXT", wglSwapIntervalEXT as usize);
    exports.insert("wglGetSwapIntervalEXT", wglGetSwapIntervalEXT as usize);
    exports.insert("SwapBuffers", SwapBuffers as usize);
    exports
}
