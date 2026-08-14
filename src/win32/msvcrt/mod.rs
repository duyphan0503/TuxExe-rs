#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Minimal C runtime implementation (msvcrt.dll exports).

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex, OnceLock,
};
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

pub extern "win64" fn memcpy(dest: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    if count > 0 {
        unsafe {
            libc::memcpy(dest, src, count);
        }
    }
    dest
}

pub extern "win64" fn memmove(dest: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    if count > 0 {
        unsafe {
            libc::memmove(dest, src, count);
        }
    }
    dest
}

pub extern "win64" fn memchr(s: *const c_void, c: i32, n: usize) -> *mut c_void {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::memchr(s, c, n) }
}

pub extern "win64" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe { libc::memcmp(s1, s2, n) }
}

pub extern "win64" fn strrchr(s: *const c_char, c: i32) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::strrchr(s, c).cast::<c_char>() }
}

pub extern "win64" fn strstr(s1: *const c_char, s2: *const c_char) -> *mut c_char {
    if s1.is_null() || s2.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::strstr(s1, s2).cast::<c_char>() }
}

pub extern "win64" fn wcscmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe {
        let mut i = 0;
        loop {
            let c1 = *s1.add(i);
            let c2 = *s2.add(i);
            if c1 != c2 || c1 == 0 {
                return (c1 as i32) - (c2 as i32);
            }
            i += 1;
        }
    }
}

pub extern "win64" fn wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }
    unsafe {
        let mut i = 0;
        while i < n {
            let c1 = *s1.add(i);
            let c2 = *s2.add(i);
            if c1 != c2 || c1 == 0 {
                return (c1 as i32) - (c2 as i32);
            }
            i += 1;
        }
        0
    }
}

pub extern "win64" fn wcscat(destination: *mut u16, source: *const u16) -> *mut u16 {
    if destination.is_null() || source.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        let mut destination_len = 0;
        while *destination.add(destination_len) != 0 {
            destination_len += 1;
        }
        let mut source_index = 0;
        loop {
            let character = *source.add(source_index);
            *destination.add(destination_len + source_index) = character;
            if character == 0 {
                break;
            }
            source_index += 1;
        }
    }
    destination
}

pub extern "win64" fn wcsrchr(string: *const u16, character: u16) -> *mut u16 {
    if string.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        let mut index = 0;
        let mut result = std::ptr::null_mut();
        loop {
            let current = *string.add(index);
            if current == character {
                result = string.add(index).cast_mut();
            }
            if current == 0 {
                return result;
            }
            index += 1;
        }
    }
}

pub extern "win64" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memset(s, c, n) }
}

pub extern "win64" fn mbrtowc(
    pwc: *mut u16,
    s: *const c_char,
    n: usize,
    _ps: *mut c_void,
) -> usize {
    if s.is_null() || n == 0 {
        return 0;
    }
    let b = unsafe { *s as u8 };
    if b == 0 {
        if !pwc.is_null() {
            unsafe { *pwc = 0; }
        }
        return 0;
    }
    if !pwc.is_null() {
        unsafe { *pwc = b as u16; }
    }
    1
}

pub extern "win64" fn wcrtomb(
    s: *mut c_char,
    wc: u16,
    _ps: *mut c_void,
) -> usize {
    if s.is_null() {
        return 1;
    }
    unsafe {
        *s = (wc & 0xFF) as c_char;
    }
    1
}

pub extern "win64" fn mbstowcs(pwcs: *mut u16, s: *const c_char, n: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut count = 0;
    unsafe {
        while count < n && *s.add(count) != 0 {
            if !pwcs.is_null() {
                *pwcs.add(count) = *s.add(count) as u8 as u16;
            }
            count += 1;
        }
        if !pwcs.is_null() && count < n {
            *pwcs.add(count) = 0;
        }
    }
    count
}

pub extern "win64" fn wcstombs(s: *mut c_char, pwcs: *const u16, n: usize) -> usize {
    if pwcs.is_null() {
        return 0;
    }
    let mut count = 0;
    unsafe {
        while count < n && *pwcs.add(count) != 0 {
            if !s.is_null() {
                *s.add(count) = (*pwcs.add(count) & 0xFF) as c_char;
            }
            count += 1;
        }
        if !s.is_null() && count < n {
            *s.add(count) = 0;
        }
    }
    count
}

pub extern "win64" fn strtoul(nptr: *const c_char, endptr: *mut *mut c_char, base: i32) -> u64 {
    if nptr.is_null() {
        return 0;
    }
    unsafe { libc::strtoul(nptr, endptr, base) }
}

pub extern "win64" fn strtol(nptr: *const c_char, endptr: *mut *mut c_char, base: i32) -> i64 {
    if nptr.is_null() {
        return 0;
    }
    unsafe { libc::strtol(nptr, endptr, base) }
}

pub extern "win64" fn strtoull(nptr: *const c_char, endptr: *mut *mut c_char, base: i32) -> u64 {
    if nptr.is_null() {
        return 0;
    }
    unsafe { libc::strtoull(nptr, endptr, base) }
}

pub extern "win64" fn strtoll(nptr: *const c_char, endptr: *mut *mut c_char, base: i32) -> i64 {
    if nptr.is_null() {
        return 0;
    }
    unsafe { libc::strtoll(nptr, endptr, base) }
}

pub extern "win64" fn strtod(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    if nptr.is_null() {
        return 0.0;
    }
    unsafe { libc::strtod(nptr, endptr) }
}

pub extern "win64" fn strtof(nptr: *const c_char, endptr: *mut *mut c_char) -> f32 {
    if nptr.is_null() {
        return 0.0;
    }
    unsafe { libc::strtof(nptr, endptr) }
}

pub extern "win64" fn powf(x: f32, y: f32) -> f32 {
    x.powf(y)
}
pub extern "win64" fn pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}
pub extern "win64" fn sin(x: f64) -> f64 {
    x.sin()
}
pub extern "win64" fn cos(x: f64) -> f64 {
    x.cos()
}
pub extern "win64" fn tan(x: f64) -> f64 {
    x.tan()
}
pub extern "win64" fn atan(x: f64) -> f64 {
    x.atan()
}
pub extern "win64" fn atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}
pub extern "win64" fn exp(x: f64) -> f64 {
    x.exp()
}
pub extern "win64" fn log(x: f64) -> f64 {
    x.ln()
}
pub extern "win64" fn sqrt(x: f64) -> f64 {
    x.sqrt()
}
pub extern "win64" fn ceil(x: f64) -> f64 {
    x.ceil()
}
pub extern "win64" fn floor(x: f64) -> f64 {
    x.floor()
}
pub extern "win64" fn fabsf(x: f32) -> f32 {
    x.abs()
}
pub extern "win64" fn fabs(x: f64) -> f64 {
    x.abs()
}

pub extern "win64" fn _fstat64(fd: i32, buf: *mut c_void) -> i32 {
    if buf.is_null() {
        return -1;
    }
    unsafe { std::ptr::write_bytes(buf.cast::<u8>(), 0, 48); }
    0
}

pub extern "win64" fn _stat64(path: *const c_char, buf: *mut c_void) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    unsafe { std::ptr::write_bytes(buf.cast::<u8>(), 0, 48); }
    0
}

pub extern "win64" fn _fstat64i32(fd: i32, buf: *mut c_void) -> i32 {
    _fstat64(fd, buf)
}

pub extern "win64" fn _stat64i32(path: *const c_char, buf: *mut c_void) -> i32 {
    _stat64(path, buf)
}

pub extern "win64" fn _access(path: *const c_char, _mode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    0
}

pub extern "win64" fn _lock_file(_stream: *mut c_void) {}
pub extern "win64" fn _unlock_file(_stream: *mut c_void) {}

pub extern "win64" fn remove(filename: *const c_char) -> i32 {
    if filename.is_null() {
        return -1;
    }
    unsafe { libc::remove(filename) }
}

pub extern "win64" fn rename(oldname: *const c_char, newname: *const c_char) -> i32 {
    if oldname.is_null() || newname.is_null() {
        return -1;
    }
    unsafe { libc::rename(oldname, newname) }
}

pub extern "win64" fn _unlink(filename: *const c_char) -> i32 {
    remove(filename)
}

pub extern "win64" fn _fdopen(fd: i32, mode: *const c_char) -> *mut c_void {
    if mode.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::fdopen(fd, mode).cast::<c_void>() }
}

pub extern "win64" fn _fileno(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fileno(stream.cast()) }
}

pub extern "win64" fn _open(filename: *const c_char, oflag: i32, pmode: i32) -> i32 {
    if filename.is_null() {
        return -1;
    }
    unsafe { libc::open(filename, oflag, pmode) }
}

pub extern "win64" fn _close(fd: i32) -> i32 {
    unsafe { libc::close(fd) }
}

pub extern "win64" fn _read(fd: i32, buffer: *mut c_void, count: u32) -> i32 {
    if buffer.is_null() {
        return -1;
    }
    unsafe { libc::read(fd, buffer, count as usize) as i32 }
}

pub extern "win64" fn _write(fd: i32, buffer: *const c_void, count: u32) -> i32 {
    if buffer.is_null() {
        return -1;
    }
    unsafe { libc::write(fd, buffer, count as usize) as i32 }
}

pub extern "win64" fn _lseek(fd: i32, offset: i32, origin: i32) -> i32 {
    unsafe { libc::lseek(fd, offset as i64, origin) as i32 }
}

pub extern "win64" fn _lseeki64(fd: i32, offset: i64, origin: i32) -> i64 {
    unsafe { libc::lseek(fd, offset, origin) }
}

pub extern "win64" fn __intrinsic_setjmpex(_buf: *mut c_void, _ctx: *mut c_void) -> i32 {
    0
}

pub extern "win64" fn setjmp(_buf: *mut c_void) -> i32 {
    0
}

pub extern "win64" fn longjmp(_buf: *mut c_void, _val: i32) -> i32 {
    0
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
        if !argc.is_null() {
            *argc = 0;
        }
        if !argv.is_null() {
            *argv = std::ptr::null_mut();
        }
        if !envp.is_null() {
            *envp = std::ptr::null_mut();
        }
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
    crate::runtime::telemetry::record(format!("guest_exit_code={status}"));
    unsafe { libc::_exit(status) }
}

pub extern "win64" fn wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub extern "win64" fn malloc(size: usize) -> *mut c_void {
    // Windows CRT allocations and HeapAlloc use the process heap
    // interchangeably.  Backing one with libc and the other with a custom
    // mmap allocator corrupts memory as soon as a Wine/Unity component hands
    // ownership across that boundary.
    let allocation = crate::memory::heap::heap_alloc(crate::memory::heap::get_process_heap(), 0, size);
    remember_allocation(allocation, size);
    allocation
}

pub extern "win64" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let Some(total) = nmemb.checked_mul(size) else {
        return std::ptr::null_mut();
    };
    let allocation = crate::memory::heap::heap_alloc(
        crate::memory::heap::get_process_heap(),
        crate::memory::heap::HEAP_ZERO_MEMORY,
        total,
    );
    remember_allocation(allocation, total);
    allocation
}

pub extern "win64" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        return malloc(size);
    }
    let allocation = crate::memory::heap::heap_realloc(crate::memory::heap::get_process_heap(), 0, ptr, size);
    replace_allocation(ptr, allocation, size);
    allocation
}

/// Windows' `_recalloc` grows an allocation and clears only its newly added
/// tail.  A generic compatibility stub here corrupts callers immediately:
/// they treat its integer return value as an owned heap pointer.
pub extern "win64" fn _recalloc(ptr: *mut c_void, count: usize, size: usize) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        return std::ptr::null_mut();
    };
    if ptr.is_null() {
        return calloc(count, size);
    }

    let heap = crate::memory::heap::get_process_heap();
    let old_size = allocation_size(ptr)
        .unwrap_or_else(|| crate::memory::heap::heap_size(heap, 0, ptr));
    let replacement = crate::memory::heap::heap_realloc(heap, 0, ptr, total);
    if replacement.is_null() {
        return replacement;
    }
    replace_allocation(ptr, replacement, total);
    if total > old_size {
        unsafe { std::ptr::write_bytes(replacement.cast::<u8>().add(old_size), 0, total - old_size) };
    }
    replacement
}

pub extern "win64" fn free(ptr: *mut c_void) {
    forget_allocation(ptr);
    crate::memory::heap::heap_free(crate::memory::heap::get_process_heap(), 0, ptr);
}

pub extern "win64" fn _aligned_malloc(size: usize, alignment: usize) -> *mut c_void {
    let align = if alignment == 0 { 8 } else { alignment };
    let mut ptr: *mut c_void = std::ptr::null_mut();
    unsafe {
        if libc::posix_memalign(&mut ptr, align, size) == 0 {
            ptr
        } else {
            std::ptr::null_mut()
        }
    }
}

pub extern "win64" fn _aligned_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { libc::free(ptr) }
    }
}

pub extern "win64" fn _aligned_realloc(ptr: *mut c_void, size: usize, alignment: usize) -> *mut c_void {
    if ptr.is_null() {
        return _aligned_malloc(size, alignment);
    }
    // Aligned allocations are intentionally kept separate from the ordinary
    // process heap, since their alignment may exceed mmap's 16-byte guest
    // allocation contract.  `malloc_usable_size` is valid for this path.
    let old_size = unsafe { libc::malloc_usable_size(ptr) };
    let new_ptr = _aligned_malloc(size, alignment);
    if !new_ptr.is_null() {
        unsafe {
            libc::memcpy(new_ptr, ptr, old_size.min(size));
            libc::free(ptr);
        }
    }
    new_ptr
}

fn allocations() -> &'static Mutex<HashMap<usize, usize>> {
    static ALLOCATIONS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_allocation(pointer: *mut c_void, size: usize) {
    if !pointer.is_null() {
        allocations()
            .lock()
            .expect("UCRT allocation map poisoned")
            .insert(pointer as usize, size);
    }
}

fn allocation_size(pointer: *mut c_void) -> Option<usize> {
    (!pointer.is_null()).then(|| {
        allocations()
            .lock()
            .expect("UCRT allocation map poisoned")
            .get(&(pointer as usize))
            .copied()
    })?
}

fn forget_allocation(pointer: *mut c_void) {
    if !pointer.is_null() {
        allocations()
            .lock()
            .expect("UCRT allocation map poisoned")
            .remove(&(pointer as usize));
    }
}

fn replace_allocation(original: *mut c_void, replacement: *mut c_void, size: usize) {
    if replacement.is_null() {
        return;
    }
    let mut allocations = allocations().lock().expect("UCRT allocation map poisoned");
    if !original.is_null() {
        allocations.remove(&(original as usize));
    }
    allocations.insert(replacement as usize, size);
}


pub extern "win64" fn _set_new_mode(_newmode: i32) -> i32 {
    0
}

pub extern "win64" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    unsafe { libc::strncmp(s1, s2, n) }
}

pub extern "win64" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    if s.is_null() || reject.is_null() {
        return 0;
    }
    unsafe {
        let mut length = 0;
        while *s.add(length) != 0 {
            let candidate = *s.add(length);
            let mut reject_index = 0;
            while *reject.add(reject_index) != 0 {
                if candidate == *reject.add(reject_index) {
                    return length;
                }
                reject_index += 1;
            }
            length += 1;
        }
        length
    }
}

/// Parses the ASCII subset used by Unity/Wine's UTF-16 path and version
/// helpers. Windows `long` remains 32-bit on Win64, unlike Linux `long`.
pub extern "win64" fn wcstol(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> i32 {
    if nptr.is_null() || !(base == 0 || (2..=36).contains(&base)) {
        if !endptr.is_null() {
            unsafe { *endptr = nptr.cast_mut() };
        }
        return 0;
    }

    unsafe {
        let mut index = 0usize;
        while matches!(*nptr.add(index), 0x20 | 0x09 | 0x0a | 0x0d) {
            index += 1;
        }
        let negative = match *nptr.add(index) {
            0x2d => {
                index += 1;
                true
            }
            0x2b => {
                index += 1;
                false
            }
            _ => false,
        };
        let mut radix = base as u32;
        if radix == 0 {
            radix = if *nptr.add(index) == b'0' as u16 {
                if matches!(*nptr.add(index + 1), 0x78 | 0x58) {
                    index += 2;
                    16
                } else {
                    8
                }
            } else {
                10
            };
        } else if radix == 16
            && *nptr.add(index) == b'0' as u16
            && matches!(*nptr.add(index + 1), 0x78 | 0x58)
        {
            index += 2;
        }

        let first_digit = index;
        let mut value: i64 = 0;
        loop {
            let c = *nptr.add(index);
            let digit = match c {
                c if (b'0' as u16..=b'9' as u16).contains(&c) => (c - b'0' as u16) as u32,
                c if (b'a' as u16..=b'z' as u16).contains(&c) => (c - b'a' as u16 + 10) as u32,
                c if (b'A' as u16..=b'Z' as u16).contains(&c) => (c - b'A' as u16 + 10) as u32,
                _ => break,
            };
            if digit >= radix {
                break;
            }
            value = value
                .saturating_mul(radix as i64)
                .saturating_add(digit as i64);
            index += 1;
        }
        if !endptr.is_null() {
            *endptr = if index == first_digit {
                nptr.cast_mut()
            } else {
                nptr.add(index).cast_mut()
            };
        }
        let signed = if negative { value.saturating_neg() } else { value };
        signed.clamp(i32::MIN as i64, i32::MAX as i64) as i32
    }
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

pub extern "win64" fn fwrite(
    ptr: *const c_void,
    size: usize,
    nmemb: usize,
    _stream: *mut c_void,
) -> usize {
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

pub extern "win64" fn ___lc_codepage_func() -> i32 {
    0
}
pub extern "win64" fn ___mb_cur_max_func() -> i32 {
    1
}
pub extern "win64" fn __setusermatherr(_func: usize) {}
pub extern "win64" fn _amsg_exit(_v: i32) {
    trace!("_amsg_exit({})", _v);
}
pub extern "win64" fn _cexit() {}
pub extern "win64" fn _lock(_n: i32) {}
pub extern "win64" fn _unlock(_n: i32) {}
pub extern "win64" fn _onexit(_func: usize) -> usize {
    _func
}

static mut ERRNO: i32 = 0;
pub extern "win64" fn _errno() -> *mut i32 {
    &raw mut ERRNO
}

static mut FMODE: i32 = 0;
static mut COMMODE: i32 = 0;
static mut MB_CUR_MAX_VALUE: i32 = 1;
static mut IOB: [u8; 1024] = [0; 1024];

pub extern "win64" fn __p__fmode() -> *mut i32 {
    &raw mut FMODE
}

pub extern "win64" fn __p__commode() -> *mut i32 {
    &raw mut COMMODE
}

pub extern "win64" fn fflush(_stream: *mut c_void) -> i32 {
    // Flush all streams. This is enough for current console-oriented smoke tests.
    unsafe { libc::fflush(std::ptr::null_mut()) }
}

pub extern "win64" fn atoi(s: *const c_char) -> i32 {
    if s.is_null() {
        0
    } else {
        unsafe { libc::atoi(s) }
    }
}

pub extern "win64" fn setlocale(category: i32, locale: *const c_char) -> *mut c_char {
    unsafe { libc::setlocale(category, locale).cast::<c_char>() }
}

pub extern "win64" fn strchr(s: *const c_char, c: i32) -> *mut c_char {
    if s.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { libc::strchr(s, c).cast::<c_char>() }
    }
}

pub extern "win64" fn __iob_func() -> *mut c_void {
    (&raw mut IOB).cast::<u8>().cast::<c_void>()
}

static mut INITENV: *mut c_char = std::ptr::null_mut();
static mut ENVIRON_PTR: *mut *mut c_char = std::ptr::null_mut();
static mut WENVIRON_PTR: *mut *mut u16 = std::ptr::null_mut();
static mut ARGC_VAL: i32 = 1;
static mut ARGV_PTR: *mut *mut c_char = std::ptr::null_mut();
static mut WARGV_PTR: *mut *mut u16 = std::ptr::null_mut();

pub extern "win64" fn __p___argc() -> *mut i32 {
    unsafe { &raw mut ARGC_VAL }
}

pub extern "win64" fn __p___argv() -> *mut *mut *mut c_char {
    unsafe { &raw mut ARGV_PTR }
}

pub extern "win64" fn __p___wargv() -> *mut *mut *mut u16 {
    unsafe { &raw mut WARGV_PTR }
}

type ThreadProcEx = extern "win64" fn(*mut c_void) -> u32;

pub extern "win64" fn _beginthreadex(
    security: *mut c_void,
    stack_size: u32,
    start_address: ThreadProcEx,
    arglist: *mut c_void,
    initflag: u32,
    thrdaddr: *mut u32,
) -> usize {
    crate::win32::kernel32::thread::CreateThread(
        security,
        stack_size as usize,
        unsafe { std::mem::transmute(start_address) },
        arglist,
        initflag,
        thrdaddr,
    ) as usize
}

pub extern "win64" fn _endthreadex(retval: u32) {
    crate::win32::kernel32::thread::ExitThread(retval);
}

pub extern "win64" fn _configure_narrow_argv(_mode: i32) -> i32 {
    0
}

pub extern "win64" fn _configure_wide_argv(_mode: i32) -> i32 {
    0
}

pub extern "win64" fn _initialize_narrow_environment() -> i32 {
    0
}

pub extern "win64" fn _initialize_wide_environment() -> i32 {
    0
}

pub extern "win64" fn _get_initial_narrow_environment() -> *mut *mut c_char {
    unsafe { ENVIRON_PTR }
}

pub extern "win64" fn _get_initial_wide_environment() -> *mut *mut u16 {
    unsafe { WENVIRON_PTR }
}

pub extern "win64" fn _initterm_e(_start: *const usize, _end: *const usize) -> i32 {
    0
}

pub extern "win64" fn _crt_at_quick_exit(_func: usize) -> i32 {
    0
}

pub extern "win64" fn _crt_atexit(_func: usize) -> i32 {
    0
}

#[repr(C)]
pub struct OnexitTable {
    first: *mut usize,
    last: *mut usize,
    end: *mut usize,
}

pub extern "win64" fn _initialize_onexit_table(table: *mut OnexitTable) -> i32 {
    if !table.is_null() {
        unsafe {
            (*table).first = std::ptr::null_mut();
            (*table).last = std::ptr::null_mut();
            (*table).end = std::ptr::null_mut();
        }
    }
    0
}

pub extern "win64" fn _register_onexit_function(_table: *mut OnexitTable, _function: usize) -> i32 {
    0
}

pub extern "win64" fn _execute_onexit_table(_table: *mut OnexitTable) -> i32 {
    0
}

pub extern "win64" fn _seh_filter_dll(_code: u32, _info: usize) -> i32 {
    0
}

pub extern "win64" fn _seh_filter_exe(_code: u32, _info: usize) -> i32 {
    0
}

pub extern "win64" fn _c_exit() {}

pub extern "win64" fn generic_msvcrt_stub() -> usize {
    0
}

pub extern "win64" fn strcmp(s1: *const c_char, s2: *const c_char) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe { libc::strcmp(s1, s2) }
}

pub extern "win64" fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    unsafe { libc::strncpy(dest, src, n) }
}

pub extern "win64" fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    unsafe { libc::strcpy(dest, src) }
}

pub extern "win64" fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    unsafe { libc::strcat(dest, src) }
}

pub extern "win64" fn _strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let length = unsafe { libc::strlen(s) };
    let duplicate = malloc(length.saturating_add(1)).cast::<c_char>();
    if !duplicate.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(s, duplicate, length + 1) };
    }
    duplicate
}

pub extern "win64" fn _wcsdup(s: *const u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    let ptr = malloc((len + 1) * 2).cast::<u16>();
    if !ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(s, ptr, len + 1);
        }
    }
    ptr
}

pub extern "win64" fn fmaxf(x: f32, y: f32) -> f32 {
    x.max(y)
}

pub extern "win64" fn fminf(x: f32, y: f32) -> f32 {
    x.min(y)
}

pub extern "win64" fn fmax(x: f64, y: f64) -> f64 {
    x.max(y)
}

pub extern "win64" fn fmin(x: f64, y: f64) -> f64 {
    x.min(y)
}

pub extern "win64" fn _wcsicmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    let s1_utf8 = unsafe { crate::utils::wide_string::from_wide_ptr(s1) }.unwrap_or_default();
    let s2_utf8 = unsafe { crate::utils::wide_string::from_wide_ptr(s2) }.unwrap_or_default();
    s1_utf8.to_lowercase().cmp(&s2_utf8.to_lowercase()) as i32
}

pub extern "win64" fn _stricmp(s1: *const c_char, s2: *const c_char) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe { libc::strcasecmp(s1, s2) }
}

pub extern "win64" fn _strnicmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe { libc::strncasecmp(s1, s2, n) }
}

pub extern "win64" fn iswctype(c: u16, _ctype: u16) -> i32 {
    if c == 0 { 0 } else { 1 }
}

pub extern "win64" fn towlower(c: u16) -> u16 {
    let char_val = std::char::from_u32(c as u32).unwrap_or('\0');
    char_val.to_lowercase().next().unwrap_or(char_val) as u16
}

pub extern "win64" fn towupper(c: u16) -> u16 {
    let char_val = std::char::from_u32(c as u32).unwrap_or('\0');
    char_val.to_uppercase().next().unwrap_or(char_val) as u16
}

pub extern "win64" fn rand_s(random_value: *mut u32) -> i32 {
    if !random_value.is_null() {
        unsafe {
            *random_value = libc::rand() as u32;
        }
    }
    0
}

static mut DAYLIGHT: i32 = 0;
static mut TIMEZONE: i32 = 0;
static TZNAME_0: [u8; 4] = *b"UTC\0";
static mut TZNAME_ARR: [*const c_char; 2] = [TZNAME_0.as_ptr().cast(), TZNAME_0.as_ptr().cast()];

pub extern "win64" fn __daylight() -> *mut i32 {
    unsafe { &raw mut DAYLIGHT }
}

pub extern "win64" fn __timezone() -> *mut i32 {
    unsafe { &raw mut TIMEZONE }
}

pub extern "win64" fn __tzname() -> *mut *const c_char {
    unsafe { &raw mut TZNAME_ARR as *mut *const c_char }
}

pub extern "win64" fn _tzset() {}

pub extern "win64" fn strcoll(s1: *const c_char, s2: *const c_char) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    unsafe { libc::strcoll(s1, s2) }
}

pub extern "win64" fn strxfrm(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    if src.is_null() { return 0; }
    unsafe { libc::strxfrm(dest, src, n) }
}

pub extern "win64" fn wcscoll(s1: *const u16, s2: *const u16) -> i32 {
    _wcsicmp(s1, s2)
}

pub extern "win64" fn wcsxfrm(dest: *mut u16, src: *const u16, n: usize) -> usize {
    if src.is_null() { return 0; }
    let mut i = 0;
    unsafe {
        while i < n && *src.add(i) != 0 {
            if !dest.is_null() {
                *dest.add(i) = *src.add(i);
            }
            i += 1;
        }
        if !dest.is_null() && i < n {
            *dest.add(i) = 0;
        }
    }
    i
}

pub extern "win64" fn strftime(s: *mut c_char, maxsize: usize, format: *const c_char, timeptr: *const c_void) -> usize {
    if s.is_null() || format.is_null() || timeptr.is_null() { return 0; }
    unsafe { libc::strftime(s, maxsize, format, timeptr.cast()) }
}

pub extern "win64" fn wcsftime(s: *mut u16, _maxsize: usize, _format: *const u16, _timeptr: *const c_void) -> usize {
    if s.is_null() { return 0; }
    unsafe { *s = 0; }
    0
}

pub extern "win64" fn getc(stream: *mut c_void) -> i32 {
    fgetc(stream)
}

pub extern "win64" fn getwc(stream: *mut c_void) -> i32 {
    fgetc(stream)
}

pub extern "win64" fn putc(c: i32, stream: *mut c_void) -> i32 {
    if stream.is_null() { return -1; }
    unsafe { libc::fputc(c, stream.cast()) }
}

pub extern "win64" fn putwc(c: u16, stream: *mut c_void) -> i32 {
    if stream.is_null() { return -1; }
    unsafe { libc::fputc(c as i32, stream.cast()) }
}

pub extern "win64" fn setvbuf(_stream: *mut c_void, _buf: *mut c_char, _mode: i32, _size: usize) -> i32 {
    0
}

pub extern "win64" fn ungetc(c: i32, stream: *mut c_void) -> i32 {
    if stream.is_null() { return -1; }
    unsafe { libc::ungetc(c, stream.cast()) }
}

pub extern "win64" fn ungetwc(c: u16, stream: *mut c_void) -> i32 {
    if stream.is_null() { return -1; }
    unsafe { libc::ungetc(c as i32, stream.cast()) }
}

pub extern "win64" fn __acrt_iob_func(index: u32) -> *mut c_void {
    let idx = if (index as usize) < 3 { index as usize } else { 0 };
    unsafe { (&raw mut IOB[idx]).cast::<u8>().cast::<c_void>() }
}

pub extern "win64" fn __stdio_common_vsprintf(
    _options: u64,
    buffer: *mut c_char,
    _count: usize,
    format: *const c_char,
    _locale: usize,
    _argptr: usize,
) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    unsafe {
        *buffer = 0;
    }
    0
}

pub extern "win64" fn __stdio_common_vsnprintf_s(
    _options: u64,
    buffer: *mut c_char,
    _buffer_count: usize,
    _max_count: usize,
    format: *const c_char,
    _locale: usize,
    _argptr: usize,
) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    unsafe {
        *buffer = 0;
    }
    0
}

pub extern "win64" fn __stdio_common_vfprintf(
    _options: u64,
    stream: *mut c_void,
    format: *const c_char,
    _locale: usize,
    _argptr: usize,
) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    0
}

pub extern "win64" fn __stdio_common_vfwprintf(
    _options: u64,
    stream: *mut c_void,
    format: *const u16,
    _locale: usize,
    _argptr: usize,
) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    0
}

pub extern "win64" fn __stdio_common_vswprintf(
    _options: u64,
    buffer: *mut u16,
    _count: usize,
    format: *const u16,
    _locale: usize,
    _argptr: usize,
) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    unsafe {
        *buffer = 0;
    }
    0
}

pub extern "win64" fn __stdio_common_vswprintf_s(
    _options: u64,
    buffer: *mut u16,
    _count: usize,
    format: *const u16,
    _locale: usize,
    _argptr: usize,
) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    unsafe {
        *buffer = 0;
    }
    0
}

pub extern "win64" fn _fseeki64(stream: *mut c_void, offset: i64, origin: i32) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fseek(stream.cast(), offset as libc::c_long, origin) }
}

pub extern "win64" fn _ftelli64(stream: *mut c_void) -> i64 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::ftell(stream.cast()) as i64 }
}

pub extern "win64" fn fopen(filename: *const c_char, mode: *const c_char) -> *mut c_void {
    if filename.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::fopen(filename, mode).cast::<c_void>() }
}

pub extern "win64" fn _wfopen(filename: *const u16, mode: *const u16) -> *mut c_void {
    if filename.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    let filename_utf8 = unsafe { crate::utils::wide_string::from_wide_ptr(filename) }
        .ok()
        .unwrap_or_default();
    let mode_utf8 = unsafe { crate::utils::wide_string::from_wide_ptr(mode) }
        .ok()
        .unwrap_or_default();
    let c_file = match std::ffi::CString::new(filename_utf8) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let c_mode = match std::ffi::CString::new(mode_utf8) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    unsafe { libc::fopen(c_file.as_ptr(), c_mode.as_ptr()).cast::<c_void>() }
}

pub extern "win64" fn fclose(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fclose(stream.cast()) }
}

pub extern "win64" fn fread(ptr: *mut c_void, size: usize, count: usize, stream: *mut c_void) -> usize {
    if ptr.is_null() || stream.is_null() {
        return 0;
    }
    unsafe { libc::fread(ptr, size, count, stream.cast()) }
}

pub extern "win64" fn fseek(stream: *mut c_void, offset: i32, origin: i32) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fseek(stream.cast(), offset as libc::c_long, origin) }
}

pub extern "win64" fn ftell(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::ftell(stream.cast()) as i32 }
}

pub extern "win64" fn fgetc(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fgetc(stream.cast()) }
}

pub extern "win64" fn fputs(s: *const c_char, stream: *mut c_void) -> i32 {
    if s.is_null() || stream.is_null() {
        return -1;
    }
    unsafe { libc::fputs(s, stream.cast()) }
}

pub extern "win64" fn fgets(s: *mut c_char, n: i32, stream: *mut c_void) -> *mut c_char {
    if s.is_null() || stream.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::fgets(s, n, stream.cast()).cast::<c_char>() }
}

pub extern "win64" fn feof(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 0;
    }
    unsafe { libc::feof(stream.cast()) }
}

pub extern "win64" fn ferror(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 0;
    }
    unsafe { libc::ferror(stream.cast()) }
}

pub extern "win64" fn clearerr(stream: *mut c_void) {
    if !stream.is_null() {
        unsafe { libc::clearerr(stream.cast()); }
    }
}

pub extern "win64" fn _get_osfhandle(fd: i32) -> isize {
    if fd < 0 {
        return -1;
    }
    fd as isize
}

pub extern "win64" fn _open_osfhandle(osfhandle: isize, _flags: i32) -> i32 {
    if osfhandle < 0 {
        return -1;
    }
    osfhandle as i32
}

pub extern "win64" fn __p__environ() -> *mut *mut *mut c_char {
    unsafe { &raw mut ENVIRON_PTR }
}

pub extern "win64" fn __p__wenviron() -> *mut *mut *mut u16 {
    unsafe { &raw mut WENVIRON_PTR }
}

pub extern "win64" fn getenv(varname: *const c_char) -> *mut c_char {
    if varname.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::getenv(varname).cast::<c_char>() }
}
static INVALID_PARAMETER_CALLS: AtomicUsize = AtomicUsize::new(0);
static INVALID_PARAMETER_HANDLER: AtomicUsize = AtomicUsize::new(0);

type InvalidParameterHandler = extern "win64" fn(*const u16, *const u16, *const u16, u32, usize);

pub extern "win64" fn __C_specific_handler(
    _dispatcher_context: usize,
    _exception_record: usize,
    _context_record: usize,
    _establisher_frame: usize,
) -> i32 {
    0
}

pub extern "win64" fn _invalid_parameter(
    expression: *const u16,
    function_name: *const u16,
    file_name: *const u16,
    line_number: u32,
    reserved: usize,
) {
    let call_idx = INVALID_PARAMETER_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    let decoded_expression =
        unsafe { crate::utils::wide_string::from_wide_ptr(expression) }.ok().unwrap_or_default();
    let decoded_function_name =
        unsafe { crate::utils::wide_string::from_wide_ptr(function_name) }.ok().unwrap_or_default();
    let decoded_file_name =
        unsafe { crate::utils::wide_string::from_wide_ptr(file_name) }.ok().unwrap_or_default();

    crate::runtime::telemetry::record(format!(
        "invalid_parameter#{call_idx}: fn='{decoded_function_name}' file='{decoded_file_name}' line={line_number} expr='{decoded_expression}'"
    ));

    tracing::warn!(
        call_idx,
        line_number,
        function = %decoded_function_name,
        file = %decoded_file_name,
        expression = %decoded_expression,
        "MSVCRT _invalid_parameter invoked"
    );

    let handler_ptr = INVALID_PARAMETER_HANDLER.load(Ordering::Acquire);
    if handler_ptr != 0 {
        let handler: InvalidParameterHandler = unsafe { std::mem::transmute(handler_ptr) };
        handler(expression, function_name, file_name, line_number, reserved);
    }
}

pub extern "win64" fn _invalid_parameter_noinfo() {
    _invalid_parameter(std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, 0);
}

pub extern "win64" fn _invalid_parameter_noinfo_noreturn() -> ! {
    _invalid_parameter_noinfo();
    abort()
}

pub extern "win64" fn _set_invalid_parameter_handler(handler: usize) -> usize {
    INVALID_PARAMETER_HANDLER.swap(handler, Ordering::AcqRel)
}

pub extern "win64" fn _get_invalid_parameter_handler() -> usize {
    INVALID_PARAMETER_HANDLER.load(Ordering::Acquire)
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    exports.insert("puts", puts as usize);
    exports.insert("strlen", strlen as usize);
    exports.insert("wcslen", wcslen as usize);
    exports.insert("memcpy", memcpy as usize);
    exports.insert("memmove", memmove as usize);
    exports.insert("memchr", memchr as usize);
    exports.insert("memcmp", memcmp as usize);
    exports.insert("strrchr", strrchr as usize);
    exports.insert("strstr", strstr as usize);
    exports.insert("wcscmp", wcscmp as usize);
    exports.insert("wcsncmp", wcsncmp as usize);
    exports.insert("wcscat", wcscat as usize);
    exports.insert("wcsrchr", wcsrchr as usize);
    exports.insert("memset", memset as usize);
    exports.insert("malloc", malloc as usize);
    exports.insert("calloc", calloc as usize);
    exports.insert("realloc", realloc as usize);
    exports.insert("_recalloc", _recalloc as usize);
    exports.insert("free", free as usize);
    exports.insert("_aligned_malloc", _aligned_malloc as usize);
    exports.insert("_aligned_free", _aligned_free as usize);
    exports.insert("_aligned_realloc", _aligned_realloc as usize);
    exports.insert("_set_new_mode", _set_new_mode as usize);
    exports.insert("strncmp", strncmp as usize);
    exports.insert("strcspn", strcspn as usize);
    exports.insert("wcstol", wcstol as usize);
    exports.insert("strerror", strerror as usize);
    exports.insert("signal", signal as usize);
    exports.insert("abort", abort as usize);
    exports.insert("fwrite", fwrite as usize);
    exports.insert("fputc", fputc as usize);
    exports.insert("fprintf", fprintf as usize);
    exports.insert("vfprintf", vfprintf as usize);
    exports.insert("localeconv", localeconv as usize);
    exports.insert("mbrtowc", mbrtowc as usize);
    exports.insert("wcrtomb", wcrtomb as usize);
    exports.insert("mbstowcs", mbstowcs as usize);
    exports.insert("wcstombs", wcstombs as usize);
    exports.insert("strtoul", strtoul as usize);
    exports.insert("strtol", strtol as usize);
    exports.insert("strtoull", strtoull as usize);
    exports.insert("strtoll", strtoll as usize);
    exports.insert("strtod", strtod as usize);
    exports.insert("strtof", strtof as usize);
    exports.insert("powf", powf as usize);
    exports.insert("pow", pow as usize);
    exports.insert("sin", sin as usize);
    exports.insert("cos", cos as usize);
    exports.insert("tan", tan as usize);
    exports.insert("atan", atan as usize);
    exports.insert("atan2", atan2 as usize);
    exports.insert("exp", exp as usize);
    exports.insert("log", log as usize);
    exports.insert("sqrt", sqrt as usize);
    exports.insert("ceil", ceil as usize);
    exports.insert("floor", floor as usize);
    exports.insert("fabsf", fabsf as usize);
    exports.insert("fabs", fabs as usize);
    exports.insert("_fstat64", _fstat64 as usize);
    exports.insert("_stat64", _stat64 as usize);
    exports.insert("_fstat64i32", _fstat64i32 as usize);
    exports.insert("_stat64i32", _stat64i32 as usize);
    exports.insert("_access", _access as usize);
    exports.insert("_lock_file", _lock_file as usize);
    exports.insert("_unlock_file", _unlock_file as usize);
    exports.insert("remove", remove as usize);
    exports.insert("rename", rename as usize);
    exports.insert("_unlink", _unlink as usize);
    exports.insert("_fdopen", _fdopen as usize);
    exports.insert("_fileno", _fileno as usize);
    exports.insert("_open", _open as usize);
    exports.insert("_close", _close as usize);
    exports.insert("_read", _read as usize);
    exports.insert("_write", _write as usize);
    exports.insert("_lseek", _lseek as usize);
    exports.insert("_lseeki64", _lseeki64 as usize);
    exports.insert("__intrinsic_setjmpex", __intrinsic_setjmpex as usize);
    exports.insert("setjmp", setjmp as usize);
    exports.insert("longjmp", longjmp as usize);

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
    exports.insert("_iob", (&raw mut IOB) as usize);
    exports.insert("__C_specific_handler", __C_specific_handler as usize);
    exports.insert("_invalid_parameter", _invalid_parameter as usize);
    exports.insert("_invalid_parameter_noinfo", _invalid_parameter_noinfo as usize);
    exports
        .insert("_invalid_parameter_noinfo_noreturn", _invalid_parameter_noinfo_noreturn as usize);
    exports.insert("_set_invalid_parameter_handler", _set_invalid_parameter_handler as usize);
    exports.insert("_get_invalid_parameter_handler", _get_invalid_parameter_handler as usize);
    exports.insert("fflush", fflush as usize);
    exports.insert("atoi", atoi as usize);
    exports.insert("setlocale", setlocale as usize);
    exports.insert("strchr", strchr as usize);
    exports.insert("__p__fmode", __p__fmode as usize);
    exports.insert("__p__commode", __p__commode as usize);
    exports.insert("__p___argc", __p___argc as usize);
    exports.insert("__p___argv", __p___argv as usize);
    exports.insert("__p___wargv", __p___wargv as usize);
    exports.insert("__p__environ", __p__environ as usize);
    exports.insert("__p__wenviron", __p__wenviron as usize);
    exports.insert("getenv", getenv as usize);
    exports.insert("_beginthreadex", _beginthreadex as usize);
    exports.insert("_endthreadex", _endthreadex as usize);
    exports.insert("_configure_narrow_argv", _configure_narrow_argv as usize);
    exports.insert("_configure_wide_argv", _configure_wide_argv as usize);
    exports.insert("_initialize_narrow_environment", _initialize_narrow_environment as usize);
    exports.insert("_initialize_wide_environment", _initialize_wide_environment as usize);
    exports.insert("_get_initial_narrow_environment", _get_initial_narrow_environment as usize);
    exports.insert("_get_initial_wide_environment", _get_initial_wide_environment as usize);
    exports.insert("_initterm_e", _initterm_e as usize);
    exports.insert("_crt_at_quick_exit", _crt_at_quick_exit as usize);
    exports.insert("_crt_atexit", _crt_atexit as usize);
    exports.insert("_initialize_onexit_table", _initialize_onexit_table as usize);
    exports.insert("_register_onexit_function", _register_onexit_function as usize);
    exports.insert("_execute_onexit_table", _execute_onexit_table as usize);
    exports.insert("_seh_filter_dll", _seh_filter_dll as usize);
    exports.insert("_seh_filter_exe", _seh_filter_exe as usize);
    exports.insert("_c_exit", _c_exit as usize);
    exports.insert("__acrt_iob_func", __acrt_iob_func as usize);
    exports.insert("__stdio_common_vsprintf", __stdio_common_vsprintf as usize);
    exports.insert("__stdio_common_vsnprintf_s", __stdio_common_vsnprintf_s as usize);
    exports.insert("__stdio_common_vfprintf", __stdio_common_vfprintf as usize);
    exports.insert("__stdio_common_vfwprintf", __stdio_common_vfwprintf as usize);
    exports.insert("__stdio_common_vswprintf", __stdio_common_vswprintf as usize);
    exports.insert("__stdio_common_vswprintf_s", __stdio_common_vswprintf_s as usize);
    exports.insert("_fseeki64", _fseeki64 as usize);
    exports.insert("_ftelli64", _ftelli64 as usize);
    exports.insert("fopen", fopen as usize);
    exports.insert("_wfopen", _wfopen as usize);
    exports.insert("fclose", fclose as usize);
    exports.insert("fread", fread as usize);
    exports.insert("fseek", fseek as usize);
    exports.insert("ftell", ftell as usize);
    exports.insert("fgetc", fgetc as usize);
    exports.insert("fputs", fputs as usize);
    exports.insert("fgets", fgets as usize);
    exports.insert("feof", feof as usize);
    exports.insert("ferror", ferror as usize);
    exports.insert("clearerr", clearerr as usize);
    exports.insert("_get_osfhandle", _get_osfhandle as usize);
    exports.insert("_open_osfhandle", _open_osfhandle as usize);
    exports.insert("strcmp", strcmp as usize);
    exports.insert("strncmp", strncmp as usize);
    exports.insert("strncpy", strncpy as usize);
    exports.insert("strcpy", strcpy as usize);
    exports.insert("strcat", strcat as usize);
    exports.insert("_strdup", _strdup as usize);
    exports.insert("_wcsdup", _wcsdup as usize);
    exports.insert("fmaxf", fmaxf as usize);
    exports.insert("fminf", fminf as usize);
    exports.insert("fmax", fmax as usize);
    exports.insert("fmin", fmin as usize);
    exports.insert("_wcsicmp", _wcsicmp as usize);
    exports.insert("_stricmp", _stricmp as usize);
    exports.insert("_strnicmp", _strnicmp as usize);
    exports.insert("iswctype", iswctype as usize);
    exports.insert("towlower", towlower as usize);
    exports.insert("towupper", towupper as usize);
    exports.insert("rand_s", rand_s as usize);
    exports.insert("__daylight", __daylight as usize);
    exports.insert("__timezone", __timezone as usize);
    exports.insert("__tzname", __tzname as usize);
    exports.insert("_tzset", _tzset as usize);
    exports.insert("strcoll", strcoll as usize);
    exports.insert("strxfrm", strxfrm as usize);
    exports.insert("wcscoll", wcscoll as usize);
    exports.insert("wcsxfrm", wcsxfrm as usize);
    exports.insert("strftime", strftime as usize);
    exports.insert("wcsftime", wcsftime as usize);
    exports.insert("getc", getc as usize);
    exports.insert("getwc", getwc as usize);
    exports.insert("putc", putc as usize);
    exports.insert("putwc", putwc as usize);
    exports.insert("setvbuf", setvbuf as usize);
    exports.insert("ungetc", ungetc as usize);
    exports.insert("ungetwc", ungetwc as usize);
    exports.insert("__mb_cur_max", (&raw mut MB_CUR_MAX_VALUE) as usize);

    exports.insert("__getmainargs", __getmainargs as usize);
    exports.insert("__set_app_type", __set_app_type as usize);
    exports.insert("_initterm", _initterm as usize);
    exports.insert("exit", exit as usize);

    // Data exports (pointers to globals)
    exports.insert("_fmode", (&raw const FMODE) as usize);
    exports.insert("_commode", (&raw const COMMODE) as usize);
    exports.insert("__initenv", (&raw const INITENV) as usize);
    exports.insert("_daylight", unsafe { (&raw const DAYLIGHT) as usize });
    exports.insert("_timezone", unsafe { (&raw const TIMEZONE) as usize });
    exports.insert("_tzname", unsafe { (&raw const TZNAME_ARR) as usize });

    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recalloc_preserves_prefix_and_zeros_extension() {
        let allocation = malloc(4).cast::<u8>();
        assert!(!allocation.is_null());
        unsafe {
            allocation.copy_from_nonoverlapping([1, 2, 3, 4].as_ptr(), 4);
        }
        let grown = _recalloc(allocation.cast(), 16, 1).cast::<u8>();
        assert!(!grown.is_null());
        unsafe {
            assert_eq!(std::slice::from_raw_parts(grown, 4), &[1, 2, 3, 4]);
            assert!(std::slice::from_raw_parts(grown.add(4), 12)
                .iter()
                .all(|byte| *byte == 0));
            free(grown.cast());
        }
    }

    #[test]
    fn strcspn_and_wcstol_follow_windows_widths() {
        assert_eq!(strcspn(c"game.exe".as_ptr(), c".x".as_ptr()), 4);
        let input: Vec<u16> = "  -0x80000001tail\0".encode_utf16().collect();
        let mut end = std::ptr::null_mut();
        assert_eq!(wcstol(input.as_ptr(), &mut end, 0), i32::MIN);
        assert_eq!(unsafe { end.offset_from(input.as_ptr()) }, 13);
    }

    #[test]
    fn utf16_string_helpers_return_windows_pointers() {
        let mut destination = [b'a' as u16, 0, 0, 0, 0];
        let source = [b'b' as u16, b'c' as u16, 0];
        assert_eq!(wcscat(destination.as_mut_ptr(), source.as_ptr()), destination.as_mut_ptr());
        assert_eq!(&destination[..4], &[b'a' as u16, b'b' as u16, b'c' as u16, 0]);
        let suffix = wcsrchr(destination.as_ptr(), b'b' as u16);
        assert_eq!(unsafe { suffix.offset_from(destination.as_ptr()) }, 1);
        assert_eq!(wcsrchr(destination.as_ptr(), 0), unsafe { destination.as_mut_ptr().add(3) });
    }
}
