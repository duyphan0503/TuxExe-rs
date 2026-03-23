//! Minimal C runtime implementation (msvcrt.dll exports).

use std::ffi::{c_char, c_void, CStr};
use tracing::trace;

pub extern "win64" fn puts(s: *const c_char) -> i32 {
    if s.is_null() {
        return -1;
    }
    
    let cstr = unsafe { CStr::from_ptr(s) };
    if let Ok(str_slice) = cstr.to_str() {
        println!("{}", str_slice);
        0
    } else {
        -1
    }
}

pub extern "win64" fn strlen(s: *const c_char) -> usize {
    if s.is_null() {
        0
    } else {
        unsafe { libc::strlen(s) }
    }
}

pub extern "win64" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe { libc::memcpy(dest, src, n) }
}

pub extern "win64" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memset(s, c, n) }
}

#[repr(C)]
pub struct StartupInfo {
    newmode: i32,
}

pub extern "win64" fn __getmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut c_char,
    envp: *mut *mut *mut c_char,
    _dowildcard: i32,
    _newinfo: *mut StartupInfo,
) -> i32 {
    trace!("__getmainargs()");
    // Return dummy args for now
    unsafe {
        if !argc.is_null() { *argc = 0; }
        if !argv.is_null() { *argv = std::ptr::null_mut(); }
        if !envp.is_null() { *envp = std::ptr::null_mut(); }
    }
    0
}

static mut APP_TYPE: i32 = 0;

pub extern "win64" fn __set_app_type(at: i32) {
    trace!("__set_app_type({})", at);
    unsafe { APP_TYPE = at };
}

pub extern "win64" fn _initterm(
    init_table_start: *const Option<extern "win64" fn()>,
    init_table_end: *const Option<extern "win64" fn()>,
) {
    trace!("_initterm({:p}, {:p})", init_table_start, init_table_end);
    let mut current = init_table_start;
    unsafe {
        while current < init_table_end {
            if let Some(func) = *current {
                func();
            }
            current = current.add(1);
        }
    }
}

pub extern "win64" fn exit(status: i32) -> ! {
    trace!("exit({})", status);
    std::process::exit(status);
}

pub extern "win64" fn wcslen(s: *const u16) -> usize {
    if s.is_null() { return 0; }
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub extern "win64" fn malloc(size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

pub extern "win64" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    unsafe { libc::calloc(nmemb, size) }
}

pub extern "win64" fn free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) }
}

pub extern "win64" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    unsafe { libc::strncmp(s1, s2, n) }
}

pub extern "win64" fn strerror(_errnum: i32) -> *const c_char {
    b"msvcrt error\0".as_ptr() as *const c_char
}

pub extern "win64" fn signal(_sig: i32, _func: usize) -> usize {
    0 // dummy
}

pub extern "win64" fn abort() -> ! {
    trace!("msvcrt abort()");
    std::process::abort();
}

pub extern "win64" fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, _stream: *mut c_void) -> usize {
    // For now write to stdout
    let total = size * nmemb;
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, total) };
    use std::io::Write;
    std::io::stdout().write(slice).unwrap_or(0) / size
}

pub extern "win64" fn fputc(c: i32, _stream: *mut c_void) -> i32 {
    print!("{}", c as u8 as char);
    c
}

pub extern "win64" fn fprintf(_stream: *mut c_void, _format: *const c_char) -> i32 {
    trace!("fprintf stub");
    0
}

pub extern "win64" fn vfprintf(_stream: *mut c_void, _format: *const c_char, _args: usize) -> i32 {
    trace!("vfprintf stub");
    0
}

pub extern "win64" fn localeconv() -> *mut c_void {
    std::ptr::null_mut()
}

pub extern "win64" fn ___lc_codepage_func() -> i32 { 0 }
pub extern "win64" fn ___mb_cur_max_func() -> i32 { 1 }
pub extern "win64" fn __setusermatherr(_func: usize) {}
pub extern "win64" fn _amsg_exit(_v: i32) { trace!("_amsg_exit({})", _v); }
pub extern "win64" fn _cexit() {}
pub extern "win64" fn _lock(_n: i32) {}
pub extern "win64" fn _unlock(_n: i32) {}
pub extern "win64" fn _onexit(_func: usize) -> usize { _func }

static mut ERRNO: i32 = 0;
pub extern "win64" fn _errno() -> *mut i32 { unsafe { &mut ERRNO } }

static mut FMODE: i32 = 0;
static mut COMMODE: i32 = 0;

pub extern "win64" fn __iob_func() -> *mut c_void {
    // dummy iob array
    static mut IOB: [u8; 1024] = [0; 1024];
    unsafe { IOB.as_mut_ptr() as *mut c_void }
}

static mut INITENV: *mut c_char = std::ptr::null_mut();

pub extern "win64" fn __C_specific_handler(_1: usize, _2: usize, _3: usize, _4: usize) -> i32 { 0 }

use std::collections::HashMap;

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    
    exports.insert("puts", puts as usize);
    exports.insert("strlen", strlen as usize);
    exports.insert("wcslen", wcslen as usize);
    exports.insert("memcpy", memcpy as usize);
    exports.insert("memset", memset as usize);
    exports.insert("malloc", malloc as usize);
    exports.insert("calloc", calloc as usize);
    exports.insert("free", free as usize);
    exports.insert("strncmp", strncmp as usize);
    exports.insert("strerror", strerror as usize);
    exports.insert("signal", signal as usize);
    exports.insert("abort", abort as usize);
    exports.insert("fwrite", fwrite as usize);
    exports.insert("fputc", fputc as usize);
    exports.insert("fprintf", fprintf as usize);
    exports.insert("vfprintf", vfprintf as usize);
    exports.insert("localeconv", localeconv as usize);
    
    exports.insert("___lc_codepage_func", ___lc_codepage_func as usize);
    exports.insert("___mb_cur_max_func", ___mb_cur_max_func as usize);
    exports.insert("__setusermatherr", __setusermatherr as usize);
    exports.insert("_amsg_exit", _amsg_exit as usize);
    exports.insert("_cexit", _cexit as usize);
    exports.insert("_lock", _lock as usize);
    exports.insert("_unlock", _unlock as usize);
    exports.insert("_onexit", _onexit as usize);
    exports.insert("_errno", _errno as usize);
    exports.insert("__iob_func", __iob_func as usize);
    exports.insert("__C_specific_handler", __C_specific_handler as usize);

    exports.insert("__getmainargs", __getmainargs as usize);
    exports.insert("__set_app_type", __set_app_type as usize);
    exports.insert("_initterm", _initterm as usize);
    exports.insert("exit", exit as usize);
    
    // Data exports (pointers to globals)
    unsafe {
        exports.insert("_fmode", &FMODE as *const i32 as usize);
        exports.insert("_commode", &COMMODE as *const i32 as usize);
        exports.insert("__initenv", &INITENV as *const *mut c_char as usize);
    }

    exports
}
