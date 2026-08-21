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
            unsafe {
                *pwc = 0;
            }
        }
        return 0;
    }
    if !pwc.is_null() {
        unsafe {
            *pwc = b as u16;
        }
    }
    1
}

pub extern "win64" fn wcrtomb(s: *mut c_char, wc: u16, _ps: *mut c_void) -> usize {
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
pub extern "win64" fn acos(x: f64) -> f64 {
    x.acos()
}
pub extern "win64" fn acosf(x: f32) -> f32 {
    x.acos()
}
pub extern "win64" fn asin(x: f64) -> f64 {
    x.asin()
}
pub extern "win64" fn asinf(x: f32) -> f32 {
    x.asin()
}
pub extern "win64" fn atanf(x: f32) -> f32 {
    x.atan()
}
pub extern "win64" fn atan2f(y: f32, x: f32) -> f32 {
    y.atan2(x)
}
pub extern "win64" fn sinf(x: f32) -> f32 {
    x.sin()
}
pub extern "win64" fn cosf(x: f32) -> f32 {
    x.cos()
}
pub extern "win64" fn tanf(x: f32) -> f32 {
    x.tan()
}
pub extern "win64" fn sinh(x: f64) -> f64 {
    x.sinh()
}
pub extern "win64" fn cosh(x: f64) -> f64 {
    x.cosh()
}
pub extern "win64" fn tanh(x: f64) -> f64 {
    x.tanh()
}
pub extern "win64" fn expf(x: f32) -> f32 {
    x.exp()
}
pub extern "win64" fn exp2(x: f64) -> f64 {
    x.exp2()
}
pub extern "win64" fn exp2f(x: f32) -> f32 {
    x.exp2()
}
pub extern "win64" fn logf(x: f32) -> f32 {
    x.ln()
}
pub extern "win64" fn log10(x: f64) -> f64 {
    x.log10()
}
pub extern "win64" fn log10f(x: f32) -> f32 {
    x.log10()
}
pub extern "win64" fn log2f(x: f32) -> f32 {
    x.log2()
}
pub extern "win64" fn sqrtf(x: f32) -> f32 {
    x.sqrt()
}
pub extern "win64" fn ceilf(x: f32) -> f32 {
    x.ceil()
}
pub extern "win64" fn floorf(x: f32) -> f32 {
    x.floor()
}
pub extern "win64" fn fmod(x: f64, y: f64) -> f64 {
    x % y
}
pub extern "win64" fn fmodf(x: f32, y: f32) -> f32 {
    x % y
}
pub extern "win64" fn hypot(x: f64, y: f64) -> f64 {
    x.hypot(y)
}
pub extern "win64" fn _hypot(x: f64, y: f64) -> f64 {
    x.hypot(y)
}
pub extern "win64" fn round(x: f64) -> f64 {
    x.round()
}
pub extern "win64" fn roundf(x: f32) -> f32 {
    x.round()
}
pub extern "win64" fn trunc(x: f64) -> f64 {
    x.trunc()
}
pub extern "win64" fn truncf(x: f32) -> f32 {
    x.trunc()
}
pub extern "win64" fn cbrt(x: f64) -> f64 {
    x.cbrt()
}
pub extern "win64" fn frexp(x: f64, exp: *mut i32) -> f64 {
    if x == 0.0 {
        if !exp.is_null() {
            unsafe {
                *exp = 0;
            }
        }
        return 0.0;
    }
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i32 - 1022;
    let normalized = f64::from_bits((bits & !(0x7ff << 52)) | (1022 << 52));
    if !exp.is_null() {
        unsafe {
            *exp = e;
        }
    }
    normalized
}
pub extern "win64" fn modf(x: f64, iptr: *mut f64) -> f64 {
    let int_part = x.trunc();
    if !iptr.is_null() {
        unsafe {
            *iptr = int_part;
        }
    }
    x.fract()
}
pub extern "win64" fn rint(x: f64) -> f64 {
    x.round()
}
pub extern "win64" fn lrint(x: f64) -> i64 {
    x.round() as i64
}
pub extern "win64" fn lround(x: f64) -> i64 {
    x.round() as i64
}
pub extern "win64" fn lroundf(x: f32) -> i64 {
    x.round() as i64
}
pub extern "win64" fn fabsf(x: f32) -> f32 {
    x.abs()
}
pub extern "win64" fn fabs(x: f64) -> f64 {
    x.abs()
}

#[repr(C)]
struct Stat64 {
    st_dev: u32,
    st_ino: u16,
    st_mode: u16,
    st_nlink: i16,
    st_uid: i16,
    st_gid: i16,
    _pad: i16,
    st_rdev: u32,
    st_size: i64,
    st_atime: i64,
    st_mtime: i64,
    st_ctime: i64,
}

fn guest_path_to_host(path_str: &str) -> std::path::PathBuf {
    let drives = crate::filesystem::drives::DriveMap::default();
    let special = crate::filesystem::path::SpecialFolders::from_host_env();
    let host_path = if let Ok(host_path) =
        crate::filesystem::path::windows_to_host(path_str, &drives, &special)
    {
        host_path
    } else {
        let normalized = path_str.replace('\\', "/");
        let p = std::path::PathBuf::from(normalized);
        if p.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                cwd.join(p)
            } else {
                p
            }
        } else {
            p
        }
    };
    if host_path.exists() {
        host_path
    } else if let Some(resolved) =
        crate::filesystem::case_fold::resolve_case_insensitive(&host_path)
    {
        resolved
    } else {
        host_path
    }
}

fn fill_stat64_from_metadata(meta: &std::fs::Metadata, buf: *mut c_void) {
    let mut mode = 0o666;
    if meta.is_dir() {
        mode |= 0o040000 | 0o111;
    } else {
        mode |= 0o100000;
    }
    let size = meta.len() as i64;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    unsafe {
        let p = buf.cast::<Stat64>();
        (*p).st_dev = 0;
        (*p).st_ino = 0;
        (*p).st_mode = mode as u16;
        (*p).st_nlink = 1;
        (*p).st_uid = 0;
        (*p).st_gid = 0;
        (*p)._pad = 0;
        (*p).st_rdev = 0;
        (*p).st_size = size;
        (*p).st_atime = mtime;
        (*p).st_mtime = mtime;
        (*p).st_ctime = mtime;
    }
}

#[repr(C)]
struct Stat64i32 {
    st_dev: u32,
    st_ino: u16,
    st_mode: u16,
    st_nlink: i16,
    st_uid: i16,
    st_gid: i16,
    _pad: i16,
    st_rdev: u32,
    st_size: i32,
    st_atime: i64,
    st_mtime: i64,
    st_ctime: i64,
}

fn fill_stat64i32_from_metadata(meta: &std::fs::Metadata, buf: *mut c_void) {
    let mut mode = 0o666;
    if meta.is_dir() {
        mode |= 0o040000 | 0o111;
    } else {
        mode |= 0o100000;
    }
    let size = (meta.len() & 0x7fff_ffff) as i32;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    unsafe {
        let p = buf.cast::<Stat64i32>();
        (*p).st_dev = 0;
        (*p).st_ino = 0;
        (*p).st_mode = mode as u16;
        (*p).st_nlink = 1;
        (*p).st_uid = 0;
        (*p).st_gid = 0;
        (*p)._pad = 0;
        (*p).st_rdev = 0;
        (*p).st_size = size;
        (*p).st_atime = mtime;
        (*p).st_mtime = mtime;
        (*p).st_ctime = mtime;
    }
}

pub extern "win64" fn _fstat64(fd: i32, buf: *mut c_void) -> i32 {
    if buf.is_null() {
        return -1;
    }
    unsafe {
        std::ptr::write_bytes(buf.cast::<u8>(), 0, std::mem::size_of::<Stat64>());
    }
    0
}

pub extern "win64" fn _fstat64i32(fd: i32, buf: *mut c_void) -> i32 {
    if buf.is_null() {
        return -1;
    }
    unsafe {
        std::ptr::write_bytes(buf.cast::<u8>(), 0, std::mem::size_of::<Stat64i32>());
    }
    0
}

pub extern "win64" fn _stat64(path: *const c_char, buf: *mut c_void) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    let res = if let Ok(meta) = std::fs::metadata(&host_path) {
        fill_stat64_from_metadata(&meta, buf);
        0
    } else {
        -1
    };
    tracing::trace!(guest_path = %s, ?host_path, ?res, "MSVCRT _stat64");
    res
}

pub extern "win64" fn _wstat64(path: *const u16, buf: *mut c_void) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    let res = if let Ok(meta) = std::fs::metadata(&host_path) {
        fill_stat64_from_metadata(&meta, buf);
        0
    } else {
        -1
    };
    tracing::trace!(guest_path = %s, ?host_path, ?res, "MSVCRT _wstat64");
    res
}

pub extern "win64" fn _stat64i32(path: *const c_char, buf: *mut c_void) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    let res = if let Ok(meta) = std::fs::metadata(&host_path) {
        fill_stat64i32_from_metadata(&meta, buf);
        0
    } else {
        -1
    };
    tracing::trace!(guest_path = %s, ?host_path, ?res, "MSVCRT _stat64i32");
    res
}

pub extern "win64" fn _wstat64i32(path: *const u16, buf: *mut c_void) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    let res = if let Ok(meta) = std::fs::metadata(&host_path) {
        fill_stat64i32_from_metadata(&meta, buf);
        0
    } else {
        -1
    };
    tracing::trace!(guest_path = %s, ?host_path, ?res, "MSVCRT _wstat64i32");
    res
}

pub extern "win64" fn _access(path: *const c_char, _mode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    if host_path.exists() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _waccess(path: *const u16, _mode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    if host_path.exists() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _wfullpath(buffer: *mut u16, path: *const u16, maxlen: usize) -> *mut u16 {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    let full = host_path.to_string_lossy();
    let wide = crate::utils::wide_string::to_wide_null(&full);
    if buffer.is_null() {
        let len = wide.len();
        let alloc = malloc(len * 2).cast::<u16>();
        if !alloc.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), alloc, len);
            }
        }
        alloc
    } else {
        let copy_len = if maxlen > 0 { wide.len().min(maxlen) } else { wide.len() };
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), buffer, copy_len);
            if copy_len > 0 {
                *buffer.add(copy_len - 1) = 0;
            }
        }
        buffer
    }
}

pub extern "win64" fn _mkdir(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    if std::fs::create_dir_all(host_path).is_ok() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _wmkdir(path: *const u16) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    if std::fs::create_dir_all(host_path).is_ok() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _wremove(path: *const u16) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    if std::fs::remove_file(&host_path).is_ok() || std::fs::remove_dir(&host_path).is_ok() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _chdir(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    if std::env::set_current_dir(host_path).is_ok() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _wchdir(path: *const u16) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(path) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    if std::env::set_current_dir(host_path).is_ok() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn _lock_file(_stream: *mut c_void) {}
pub extern "win64" fn _unlock_file(_stream: *mut c_void) {}

pub extern "win64" fn remove(filename: *const c_char) -> i32 {
    if filename.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(filename) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    if std::fs::remove_file(&host_path).is_ok() || std::fs::remove_dir(&host_path).is_ok() {
        0
    } else {
        -1
    }
}

pub extern "win64" fn rename(oldname: *const c_char, newname: *const c_char) -> i32 {
    if oldname.is_null() || newname.is_null() {
        return -1;
    }
    let old_s = unsafe { CStr::from_ptr(oldname) }.to_str().unwrap_or_default();
    let new_s = unsafe { CStr::from_ptr(newname) }.to_str().unwrap_or_default();
    let old_host = guest_path_to_host(old_s);
    let new_host = guest_path_to_host(new_s);
    if std::fs::rename(old_host, new_host).is_ok() {
        0
    } else {
        -1
    }
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

fn win_oflag_to_linux(win_oflag: i32) -> i32 {
    let mut flags = match win_oflag & 0x0003 {
        0 => libc::O_RDONLY,
        1 => libc::O_WRONLY,
        2 => libc::O_RDWR,
        _ => libc::O_RDONLY,
    };
    if win_oflag & 0x0008 != 0 {
        flags |= libc::O_APPEND;
    }
    if win_oflag & 0x0100 != 0 {
        flags |= libc::O_CREAT;
    }
    if win_oflag & 0x0200 != 0 {
        flags |= libc::O_TRUNC;
    }
    if win_oflag & 0x0400 != 0 {
        flags |= libc::O_EXCL;
    }
    flags
}

pub extern "win64" fn _fileno(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    if is_iob_stream(stream, 0) {
        return 0;
    }
    if is_iob_stream(stream, 1) {
        return 1;
    }
    if is_iob_stream(stream, 2) {
        return 2;
    }
    unsafe { libc::fileno(stream.cast()) }
}

pub extern "win64" fn _open(filename: *const c_char, oflag: i32, pmode: i32) -> i32 {
    if filename.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(filename) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    let c_file = match std::ffi::CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let linux_flags = win_oflag_to_linux(oflag);
    let mode = if pmode == 0 { 0o666 } else { pmode as libc::mode_t };
    let fd = unsafe { libc::open(c_file.as_ptr(), linux_flags, mode) };
    if fd >= 0 {
        register_fd_handle(fd, host_path.clone());
    }
    tracing::trace!(guest_path = %s, ?host_path, oflag, linux_flags, fd, "MSVCRT _open");
    fd
}

pub extern "win64" fn _wopen(filename: *const u16, oflag: i32, pmode: i32) -> i32 {
    if filename.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(filename) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&s);
    let c_file = match std::ffi::CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let linux_flags = win_oflag_to_linux(oflag);
    let mode = if pmode == 0 { 0o666 } else { pmode as libc::mode_t };
    let fd = unsafe { libc::open(c_file.as_ptr(), linux_flags, mode) };
    if fd >= 0 {
        register_fd_handle(fd, host_path.clone());
    }
    tracing::trace!(guest_path = %s, ?host_path, oflag, linux_flags, fd, "MSVCRT _wopen");
    fd
}

pub extern "win64" fn _sopen(filename: *const c_char, oflag: i32, _shflag: i32, pmode: i32) -> i32 {
    _open(filename, oflag, pmode)
}

pub extern "win64" fn _wsopen(filename: *const u16, oflag: i32, _shflag: i32, pmode: i32) -> i32 {
    _wopen(filename, oflag, pmode)
}

pub extern "win64" fn _close(fd: i32) -> i32 {
    let handle = {
        let mut map1 = FD_TO_HANDLE.lock().unwrap();
        map1.remove(&fd)
    };
    if let Some(h) = handle {
        let mut map2 = HANDLE_TO_FD.lock().unwrap();
        map2.remove(&h);
        crate::utils::handle::global_table().close_handle(h);
    } else {
        unsafe { libc::close(fd) };
    }
    0
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
    tracing::info!("MSVCRT exit({})", status);
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
    let allocation =
        crate::memory::heap::heap_alloc(crate::memory::heap::get_process_heap(), 0, size);
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
    let allocation =
        crate::memory::heap::heap_realloc(crate::memory::heap::get_process_heap(), 0, ptr, size);
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
    let old_size =
        allocation_size(ptr).unwrap_or_else(|| crate::memory::heap::heap_size(heap, 0, ptr));
    let replacement = crate::memory::heap::heap_realloc(heap, 0, ptr, total);
    if replacement.is_null() {
        return replacement;
    }
    replace_allocation(ptr, replacement, total);
    if total > old_size {
        unsafe {
            std::ptr::write_bytes(replacement.cast::<u8>().add(old_size), 0, total - old_size)
        };
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

pub extern "win64" fn _aligned_realloc(
    ptr: *mut c_void,
    size: usize,
    alignment: usize,
) -> *mut c_void {
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
        allocations().lock().expect("UCRT allocation map poisoned").insert(pointer as usize, size);
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
        allocations().lock().expect("UCRT allocation map poisoned").remove(&(pointer as usize));
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
            value = value.saturating_mul(radix as i64).saturating_add(digit as i64);
            index += 1;
        }
        if !endptr.is_null() {
            *endptr =
                if index == first_digit { nptr.cast_mut() } else { nptr.add(index).cast_mut() };
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
    stream: *mut c_void,
) -> usize {
    if ptr.is_null() || stream.is_null() || size == 0 || nmemb == 0 {
        return 0;
    }
    use std::io::Write;
    let total = size.saturating_mul(nmemb);
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, total) };
    if is_iob_stream(stream, 1) {
        let written = std::io::stdout().write(slice).unwrap_or(0);
        return written / size;
    }
    if is_iob_stream(stream, 2) {
        let written = std::io::stderr().write(slice).unwrap_or(0);
        return written / size;
    }
    unsafe { libc::fwrite(ptr, size, nmemb, stream.cast()) }
}

pub extern "win64" fn fputc(c: i32, stream: *mut c_void) -> i32 {
    use std::io::Write;
    let byte = [c as u8];
    if is_iob_stream(stream, 1) {
        let _ = std::io::stdout().write(&byte);
        return c;
    }
    if is_iob_stream(stream, 2) {
        let _ = std::io::stderr().write(&byte);
        return c;
    }
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fputc(c, stream.cast()) }
}

pub extern "win64" fn fputs(s: *const c_char, stream: *mut c_void) -> i32 {
    if s.is_null() || stream.is_null() {
        return -1;
    }
    use std::io::Write;
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    if is_iob_stream(stream, 1) {
        let _ = std::io::stdout().write_all(bytes);
        return 0;
    }
    if is_iob_stream(stream, 2) {
        let _ = std::io::stderr().write_all(bytes);
        return 0;
    }
    unsafe { libc::fputs(s, stream.cast()) }
}

pub extern "win64" fn fprintf(stream: *mut c_void, format: *const c_char) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    fputs(format, stream)
}

pub extern "win64" fn vfprintf(stream: *mut c_void, format: *const c_char, args: usize) -> i32 {
    __stdio_common_vfprintf(0, stream, format, 0, args)
}

#[repr(C)]
pub struct Lconv {
    pub decimal_point: *const c_char,
    pub thousands_sep: *const c_char,
    pub grouping: *const c_char,
    pub int_curr_symbol: *const c_char,
    pub currency_symbol: *const c_char,
    pub mon_decimal_point: *const c_char,
    pub mon_thousands_sep: *const c_char,
    pub mon_grouping: *const c_char,
    pub positive_sign: *const c_char,
    pub negative_sign: *const c_char,
    pub int_frac_digits: c_char,
    pub frac_digits: c_char,
    pub p_cs_precedes: c_char,
    pub p_sep_by_space: c_char,
    pub n_cs_precedes: c_char,
    pub n_sep_by_space: c_char,
    pub p_sign_posn: c_char,
    pub n_sign_posn: c_char,
    pub _W_decimal_point: *const u16,
    pub _W_thousands_sep: *const u16,
    pub _W_int_curr_symbol: *const u16,
    pub _W_currency_symbol: *const u16,
    pub _W_mon_decimal_point: *const u16,
    pub _W_mon_thousands_sep: *const u16,
    pub _W_positive_sign: *const u16,
    pub _W_negative_sign: *const u16,
}

unsafe impl Sync for Lconv {}
unsafe impl Send for Lconv {}

static EMPTY_STR: &[u8] = b"\0";
static DOT_STR: &[u8] = b".\0";
static EMPTY_WSTR: &[u16] = &[0];
static DOT_WSTR: &[u16] = &[b'.' as u16, 0];

static DEFAULT_LCONV: Lconv = Lconv {
    decimal_point: DOT_STR.as_ptr().cast(),
    thousands_sep: EMPTY_STR.as_ptr().cast(),
    grouping: EMPTY_STR.as_ptr().cast(),
    int_curr_symbol: EMPTY_STR.as_ptr().cast(),
    currency_symbol: EMPTY_STR.as_ptr().cast(),
    mon_decimal_point: EMPTY_STR.as_ptr().cast(),
    mon_thousands_sep: EMPTY_STR.as_ptr().cast(),
    mon_grouping: EMPTY_STR.as_ptr().cast(),
    positive_sign: EMPTY_STR.as_ptr().cast(),
    negative_sign: EMPTY_STR.as_ptr().cast(),
    int_frac_digits: 127,
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
    _W_decimal_point: DOT_WSTR.as_ptr(),
    _W_thousands_sep: EMPTY_WSTR.as_ptr(),
    _W_int_curr_symbol: EMPTY_WSTR.as_ptr(),
    _W_currency_symbol: EMPTY_WSTR.as_ptr(),
    _W_mon_decimal_point: EMPTY_WSTR.as_ptr(),
    _W_mon_thousands_sep: EMPTY_WSTR.as_ptr(),
    _W_positive_sign: EMPTY_WSTR.as_ptr(),
    _W_negative_sign: EMPTY_WSTR.as_ptr(),
};

pub extern "win64" fn localeconv() -> *mut c_void {
    (&raw const DEFAULT_LCONV as *mut Lconv).cast()
}

pub extern "win64" fn _localeconv_l(_locale: *mut c_void) -> *mut c_void {
    localeconv()
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

static mut DOSERRNO: u32 = 0;
pub extern "win64" fn __doserrno() -> *mut u32 {
    &raw mut DOSERRNO
}

static SYS_NERR: i32 = 43;
pub extern "win64" fn __sys_nerr() -> *const i32 {
    &SYS_NERR
}

pub extern "win64" fn _getpid() -> i32 {
    std::process::id() as i32
}

pub extern "win64" fn _time64(timeptr: *mut i64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if !timeptr.is_null() {
        unsafe {
            *timeptr = now;
        }
    }
    now
}

pub extern "win64" fn _commit(fd: i32) -> i32 {
    unsafe { libc::fsync(fd) }
}

pub extern "win64" fn _dup(fd: i32) -> i32 {
    unsafe { libc::dup(fd) }
}

pub extern "win64" fn _dup2(fd1: i32, fd2: i32) -> i32 {
    unsafe { libc::dup2(fd1, fd2) }
}

pub extern "win64" fn _chsize_s(fd: i32, size: i64) -> i32 {
    unsafe { libc::ftruncate(fd, size) }
}

pub extern "win64" fn _umask(pmode: i32) -> i32 {
    unsafe { libc::umask(pmode as libc::mode_t) as i32 }
}

pub extern "win64" fn _wputenv(envstring: *const u16) -> i32 {
    if envstring.is_null() {
        return -1;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(envstring) }.unwrap_or_default();
    if let Some((k, v)) = s.split_once('=') {
        std::env::set_var(k, v);
        0
    } else {
        -1
    }
}

pub extern "win64" fn _wputenv_s(name: *const u16, value: *const u16) -> i32 {
    if name.is_null() {
        return -1;
    }
    let k = unsafe { crate::utils::wide_string::from_wide_ptr(name) }.unwrap_or_default();
    let v = if value.is_null() {
        String::new()
    } else {
        unsafe { crate::utils::wide_string::from_wide_ptr(value) }.unwrap_or_default()
    };
    std::env::set_var(k, v);
    0
}

pub extern "win64" fn wcscpy_s(dest: *mut u16, dest_sz: usize, src: *const u16) -> i32 {
    if dest.is_null() || src.is_null() || dest_sz == 0 {
        return 22;
    }
    let mut i = 0;
    unsafe {
        while i < dest_sz {
            let ch = *src.add(i);
            *dest.add(i) = ch;
            if ch == 0 {
                return 0;
            }
            i += 1;
        }
        *dest = 0;
    }
    34
}

pub extern "win64" fn wcsncpy_s(
    dest: *mut u16,
    dest_sz: usize,
    src: *const u16,
    count: usize,
) -> i32 {
    if dest.is_null() || dest_sz == 0 {
        return 22;
    }
    if count == 0 {
        unsafe {
            *dest = 0;
        }
        return 0;
    }
    if src.is_null() {
        unsafe {
            *dest = 0;
        }
        return 22;
    }
    let mut i = 0;
    unsafe {
        while i < count && i < dest_sz {
            let ch = *src.add(i);
            *dest.add(i) = ch;
            if ch == 0 {
                return 0;
            }
            i += 1;
        }
        if i < dest_sz {
            *dest.add(i) = 0;
            return 0;
        }
        *dest = 0;
    }
    34
}

pub extern "win64" fn wcscat_s(dest: *mut u16, dest_sz: usize, src: *const u16) -> i32 {
    if dest.is_null() || src.is_null() || dest_sz == 0 {
        return 22;
    }
    let mut cur_len = 0;
    unsafe {
        while cur_len < dest_sz && *dest.add(cur_len) != 0 {
            cur_len += 1;
        }
        if cur_len >= dest_sz {
            return 22;
        }
        let mut i = 0;
        while cur_len + i < dest_sz {
            let ch = *src.add(i);
            *dest.add(cur_len + i) = ch;
            if ch == 0 {
                return 0;
            }
            i += 1;
        }
        *dest = 0;
    }
    34
}

pub extern "win64" fn wcstok_s(
    str_tok: *mut u16,
    delim: *const u16,
    ptr_save: *mut *mut u16,
) -> *mut u16 {
    if delim.is_null() || ptr_save.is_null() {
        return std::ptr::null_mut();
    }
    let mut s = if !str_tok.is_null() { str_tok } else { unsafe { *ptr_save } };
    if s.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        while *s != 0 {
            let mut is_del = false;
            let mut d = delim;
            while *d != 0 {
                if *d == *s {
                    is_del = true;
                    break;
                }
                d = d.add(1);
            }
            if !is_del {
                break;
            }
            s = s.add(1);
        }
        if *s == 0 {
            *ptr_save = s;
            return std::ptr::null_mut();
        }
        let tok_start = s;
        while *s != 0 {
            let mut is_del = false;
            let mut d = delim;
            while *d != 0 {
                if *d == *s {
                    is_del = true;
                    break;
                }
                d = d.add(1);
            }
            if is_del {
                *s = 0;
                *ptr_save = s.add(1);
                return tok_start;
            }
            s = s.add(1);
        }
        *ptr_save = s;
        tok_start
    }
}

pub extern "win64" fn acosh(x: f64) -> f64 {
    x.acosh()
}
pub extern "win64" fn asinh(x: f64) -> f64 {
    x.asinh()
}
pub extern "win64" fn atanh(x: f64) -> f64 {
    x.atanh()
}
pub extern "win64" fn copysign(x: f64, y: f64) -> f64 {
    x.copysign(y)
}
pub extern "win64" fn expm1(x: f64) -> f64 {
    x.exp_m1()
}
pub extern "win64" fn log1p(x: f64) -> f64 {
    x.ln_1p()
}
pub extern "win64" fn log2(x: f64) -> f64 {
    x.log2()
}
pub extern "win64" fn fma(x: f64, y: f64, z: f64) -> f64 {
    x.mul_add(y, z)
}
pub extern "win64" fn nextafter(x: f64, y: f64) -> f64 {
    if x < y {
        f64::from_bits(x.to_bits() + 1)
    } else if x > y {
        f64::from_bits(x.to_bits() - 1)
    } else {
        x
    }
}

pub extern "win64" fn rewind(stream: *mut c_void) {
    if !stream.is_null() {
        unsafe {
            libc::rewind(stream.cast());
        }
    }
}

pub extern "win64" fn putchar(c: i32) -> i32 {
    fputc(c, __acrt_iob_func(1))
}

pub extern "win64" fn raise(sig: i32) -> i32 {
    unsafe { libc::raise(sig) }
}

pub extern "win64" fn _heapmin() -> i32 {
    0
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
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    0
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

fn parse_cmd_line_into_args(cmd_line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = cmd_line.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }

    while let Some(c) = chars.next() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                args.push(current.clone());
                current.clear();
            }
            while let Some(&next_c) = chars.peek() {
                if next_c.is_whitespace() && !in_quotes {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        args.push(String::new());
    }

    args
}

pub extern "win64" fn _configure_narrow_argv(_mode: i32) -> i32 {
    let cmd_ptr = crate::win32::kernel32::process::get_command_line_a();
    let cmd_str = if !cmd_ptr.is_null() {
        unsafe { std::ffi::CStr::from_ptr(cmd_ptr as *const std::ffi::c_char) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };

    let args = parse_cmd_line_into_args(&cmd_str);
    unsafe {
        ARGC_VAL = args.len() as i32;

        let argv_layout = std::alloc::Layout::array::<*mut c_char>(args.len() + 1).unwrap();
        let argv = std::alloc::alloc_zeroed(argv_layout) as *mut *mut c_char;

        for (i, arg) in args.iter().enumerate() {
            let bytes = std::ffi::CString::new(arg.as_str())
                .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
            let cstr_bytes = bytes.into_bytes_with_nul();
            let arg_layout = std::alloc::Layout::array::<u8>(cstr_bytes.len()).unwrap();
            let arg_ptr = std::alloc::alloc(arg_layout) as *mut c_char;
            std::ptr::copy_nonoverlapping(
                cstr_bytes.as_ptr(),
                arg_ptr as *mut u8,
                cstr_bytes.len(),
            );
            *argv.add(i) = arg_ptr;
        }
        *argv.add(args.len()) = std::ptr::null_mut();
        ARGV_PTR = argv;
    }
    0
}

pub extern "win64" fn _configure_wide_argv(_mode: i32) -> i32 {
    let cmd_ptr = crate::win32::kernel32::process::get_command_line_w();
    let cmd_str = if !cmd_ptr.is_null() {
        let mut len = 0;
        unsafe {
            while *cmd_ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(cmd_ptr, len);
            String::from_utf16_lossy(slice)
        }
    } else {
        String::new()
    };

    let args = parse_cmd_line_into_args(&cmd_str);
    unsafe {
        ARGC_VAL = args.len() as i32;

        let argv_layout = std::alloc::Layout::array::<*mut u16>(args.len() + 1).unwrap();
        let argv = std::alloc::alloc_zeroed(argv_layout) as *mut *mut u16;

        for (i, arg) in args.iter().enumerate() {
            let wide: Vec<u16> = arg.encode_utf16().chain(std::iter::once(0)).collect();
            let arg_layout = std::alloc::Layout::array::<u16>(wide.len()).unwrap();
            let arg_ptr = std::alloc::alloc(arg_layout) as *mut u16;
            std::ptr::copy_nonoverlapping(wide.as_ptr(), arg_ptr, wide.len());
            *argv.add(i) = arg_ptr;
        }
        *argv.add(args.len()) = std::ptr::null_mut();
        WARGV_PTR = argv;
    }
    0
}

pub extern "win64" fn _initialize_narrow_environment() -> i32 {
    unsafe {
        if !ENVIRON_PTR.is_null() {
            return 0;
        }
        let env_vars: Vec<(String, String)> = std::env::vars().collect();
        let layout = std::alloc::Layout::array::<*mut c_char>(env_vars.len() + 1).unwrap();
        let env_ptr = std::alloc::alloc_zeroed(layout) as *mut *mut c_char;

        for (i, (k, v)) in env_vars.iter().enumerate() {
            let entry = format!("{k}={v}");
            let cstr = std::ffi::CString::new(entry)
                .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
            let bytes = cstr.into_bytes_with_nul();
            let item_layout = std::alloc::Layout::array::<u8>(bytes.len()).unwrap();
            let item_ptr = std::alloc::alloc(item_layout) as *mut c_char;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), item_ptr as *mut u8, bytes.len());
            *env_ptr.add(i) = item_ptr;
        }
        *env_ptr.add(env_vars.len()) = std::ptr::null_mut();
        ENVIRON_PTR = env_ptr;
    }
    0
}

pub extern "win64" fn _initialize_wide_environment() -> i32 {
    unsafe {
        if !WENVIRON_PTR.is_null() {
            return 0;
        }
        let env_vars: Vec<(String, String)> = std::env::vars().collect();
        let layout = std::alloc::Layout::array::<*mut u16>(env_vars.len() + 1).unwrap();
        let env_ptr = std::alloc::alloc_zeroed(layout) as *mut *mut u16;

        for (i, (k, v)) in env_vars.iter().enumerate() {
            let entry = format!("{k}={v}");
            let wide: Vec<u16> = entry.encode_utf16().chain(std::iter::once(0)).collect();
            let item_layout = std::alloc::Layout::array::<u16>(wide.len()).unwrap();
            let item_ptr = std::alloc::alloc(item_layout) as *mut u16;
            std::ptr::copy_nonoverlapping(wide.as_ptr(), item_ptr, wide.len());
            *env_ptr.add(i) = item_ptr;
        }
        *env_ptr.add(env_vars.len()) = std::ptr::null_mut();
        WENVIRON_PTR = env_ptr;
    }
    0
}

pub extern "win64" fn _get_initial_narrow_environment() -> *mut *mut c_char {
    unsafe { ENVIRON_PTR }
}

pub extern "win64" fn _get_initial_wide_environment() -> *mut *mut u16 {
    unsafe { WENVIRON_PTR }
}

pub extern "win64" fn _initterm_e(
    init_table_start: *const Option<extern "win64" fn() -> i32>,
    init_table_end: *const Option<extern "win64" fn() -> i32>,
) -> i32 {
    trace!("_initterm_e({:p}, {:p})", init_table_start, init_table_end);
    if init_table_start.is_null() || init_table_end.is_null() {
        return 0;
    }
    let mut current = init_table_start;
    unsafe {
        while current < init_table_end {
            if let Some(func) = *current {
                let res = func();
                if res != 0 {
                    return res;
                }
            }
            current = current.add(1);
        }
    }
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
    let s_str = unsafe { CStr::from_ptr(s) }.to_str().unwrap_or_default();
    let length = s_str.len();
    let duplicate = malloc(length.saturating_add(1)).cast::<c_char>();
    if !duplicate.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(s, duplicate, length + 1) };
    }
    tracing::info!(s = %s_str, ?duplicate, "MSVCRT _strdup");
    duplicate
}

pub extern "win64" fn strncat(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    unsafe { libc::strncat(dest, src, n) }
}

pub extern "win64" fn strnlen(s: *const c_char, maxlen: usize) -> usize {
    if s.is_null() {
        0
    } else {
        unsafe { libc::strnlen(s, maxlen) }
    }
}

pub extern "win64" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    if s.is_null() || accept.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::strpbrk(s, accept) as *mut c_char }
}

pub extern "win64" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    if s.is_null() || accept.is_null() {
        return 0;
    }
    unsafe { libc::strspn(s, accept) }
}

pub extern "win64" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    if delim.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::strtok(s, delim) }
}

pub extern "win64" fn tolower(c: i32) -> i32 {
    (c as u8 as char).to_ascii_lowercase() as i32
}
pub extern "win64" fn toupper(c: i32) -> i32 {
    (c as u8 as char).to_ascii_uppercase() as i32
}
pub extern "win64" fn isalnum(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_alphanumeric() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isalpha(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_alphabetic() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isblank(c: i32) -> i32 {
    if c == b' ' as i32 || c == b'\t' as i32 {
        1
    } else {
        0
    }
}
pub extern "win64" fn iscntrl(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_control() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isdigit(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_digit() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isgraph(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_graphic() {
        1
    } else {
        0
    }
}
pub extern "win64" fn islower(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_lowercase() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isprint(c: i32) -> i32 {
    if (c as u8 as char).is_ascii() && !(c as u8 as char).is_ascii_control() {
        1
    } else {
        0
    }
}
pub extern "win64" fn ispunct(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_punctuation() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isspace(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_whitespace() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isupper(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_uppercase() {
        1
    } else {
        0
    }
}
pub extern "win64" fn isxdigit(c: i32) -> i32 {
    if (c as u8 as char).is_ascii_hexdigit() {
        1
    } else {
        0
    }
}

pub extern "win64" fn wcschr(s: *const u16, c: u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut i = 0;
    unsafe {
        loop {
            let ch = *s.add(i);
            if ch == c {
                return s.add(i) as *mut u16;
            }
            if ch == 0 {
                return std::ptr::null_mut();
            }
            i += 1;
        }
    }
}

pub extern "win64" fn wcsstr(s1: *const u16, s2: *const u16) -> *mut u16 {
    if s1.is_null() || s2.is_null() {
        return std::ptr::null_mut();
    }
    let s1_str = unsafe { crate::utils::wide_string::from_wide_ptr(s1) }.unwrap_or_default();
    let s2_str = unsafe { crate::utils::wide_string::from_wide_ptr(s2) }.unwrap_or_default();
    if let Some(idx) = s1_str.find(&s2_str) {
        unsafe { s1.add(idx) as *mut u16 }
    } else {
        std::ptr::null_mut()
    }
}

pub extern "win64" fn wcscpy(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0;
    unsafe {
        loop {
            let ch = *src.add(i);
            *dest.add(i) = ch;
            if ch == 0 {
                break;
            }
            i += 1;
        }
    }
    dest
}

pub extern "win64" fn wcsncpy(dest: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    let mut i = 0;
    let mut null_seen = false;
    unsafe {
        while i < n {
            if !null_seen {
                let ch = *src.add(i);
                *dest.add(i) = ch;
                if ch == 0 {
                    null_seen = true;
                }
            } else {
                *dest.add(i) = 0;
            }
            i += 1;
        }
    }
    dest
}

pub extern "win64" fn wcsnlen(s: *const u16, maxlen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut i = 0;
    unsafe {
        while i < maxlen && *s.add(i) != 0 {
            i += 1;
        }
    }
    i
}

pub extern "win64" fn _wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }
    let mut i = 0;
    unsafe {
        while i < n {
            let c1 = (*s1.add(i) as u8 as char).to_ascii_lowercase() as i32;
            let c2 = (*s2.add(i) as u8 as char).to_ascii_lowercase() as i32;
            if c1 != c2 || c1 == 0 {
                return c1 - c2;
            }
            i += 1;
        }
    }
    0
}

pub extern "win64" fn _strlwr(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return s;
    }
    let mut i = 0;
    unsafe {
        while *s.add(i) != 0 {
            *s.add(i) = (*s.add(i) as u8 as char).to_ascii_lowercase() as c_char;
            i += 1;
        }
    }
    s
}

pub extern "win64" fn _strupr(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return s;
    }
    let mut i = 0;
    unsafe {
        while *s.add(i) != 0 {
            *s.add(i) = (*s.add(i) as u8 as char).to_ascii_uppercase() as c_char;
            i += 1;
        }
    }
    s
}

pub extern "win64" fn _putenv(envstring: *const c_char) -> i32 {
    if envstring.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(envstring) }.to_str().unwrap_or_default();
    if let Some((k, v)) = s.split_once('=') {
        std::env::set_var(k, v);
        0
    } else {
        -1
    }
}

pub extern "win64" fn _wgetenv(varname: *const u16) -> *mut u16 {
    if varname.is_null() {
        return std::ptr::null_mut();
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(varname) }.unwrap_or_default();
    if let Ok(val) = std::env::var(s) {
        let wide = crate::utils::wide_string::to_wide_null(&val);
        let ptr = malloc(wide.len() * 2).cast::<u16>();
        if !ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
            }
        }
        ptr
    } else {
        std::ptr::null_mut()
    }
}

pub extern "win64" fn qsort(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<extern "win64" fn(*const c_void, *const c_void) -> i32>,
) {
    if base.is_null() || nmemb <= 1 || size == 0 {
        return;
    }
    let Some(cmp) = compar else {
        return;
    };
    unsafe {
        let ptr = base as *mut u8;
        let mut temp = vec![0u8; size];
        for i in 1..nmemb {
            let mut j = i;
            while j > 0 {
                let p1 = ptr.add((j - 1) * size);
                let p2 = ptr.add(j * size);
                if cmp(p1.cast(), p2.cast()) > 0 {
                    std::ptr::copy_nonoverlapping(p1, temp.as_mut_ptr(), size);
                    std::ptr::copy_nonoverlapping(p2, p1, size);
                    std::ptr::copy_nonoverlapping(temp.as_ptr(), p2, size);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
    }
}

pub extern "win64" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: Option<extern "win64" fn(*const c_void, *const c_void) -> i32>,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nmemb == 0 || size == 0 {
        return std::ptr::null_mut();
    }
    let Some(cmp) = compar else {
        return std::ptr::null_mut();
    };
    let mut low = 0usize;
    let mut high = nmemb;
    let ptr = base as *const u8;
    while low < high {
        let mid = low + (high - low) / 2;
        let p = unsafe { ptr.add(mid * size) };
        let c = cmp(key, p.cast());
        if c == 0 {
            return p as *mut c_void;
        } else if c < 0 {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    std::ptr::null_mut()
}

pub extern "win64" fn rand() -> i32 {
    unsafe { libc::rand() }
}

pub extern "win64" fn atof(nptr: *const c_char) -> f64 {
    strtod(nptr, std::ptr::null_mut())
}

pub extern "win64" fn _itoa(val: i32, buf: *mut c_char, radix: i32) -> *mut c_char {
    if buf.is_null() {
        return buf;
    }
    let s = match radix {
        10 => format!("{val}\0"),
        16 => format!("{:x}\0", val as u32),
        8 => format!("{:o}\0", val as u32),
        2 => format!("{:b}\0", val as u32),
        _ => format!("{val}\0"),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, buf, s.len());
    }
    buf
}

pub extern "win64" fn _ltoa(val: i32, buf: *mut c_char, radix: i32) -> *mut c_char {
    _itoa(val, buf, radix)
}

pub extern "win64" fn _i64toa(val: i64, buf: *mut c_char, radix: i32) -> *mut c_char {
    if buf.is_null() {
        return buf;
    }
    let s = match radix {
        10 => format!("{val}\0"),
        16 => format!("{:x}\0", val as u64),
        8 => format!("{:o}\0", val as u64),
        2 => format!("{:b}\0", val as u64),
        _ => format!("{val}\0"),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, buf, s.len());
    }
    buf
}

pub extern "win64" fn _ui64toa(val: u64, buf: *mut c_char, radix: i32) -> *mut c_char {
    if buf.is_null() {
        return buf;
    }
    let s = match radix {
        10 => format!("{val}\0"),
        16 => format!("{:x}\0", val),
        8 => format!("{:o}\0", val),
        2 => format!("{:b}\0", val),
        _ => format!("{val}\0"),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, buf, s.len());
    }
    buf
}

pub extern "win64" fn _ultoa(val: u32, buf: *mut c_char, radix: i32) -> *mut c_char {
    _ui64toa(val as u64, buf, radix)
}

pub extern "win64" fn wcstoul(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> u32 {
    wcstoull(nptr, endptr, base) as u32
}

pub extern "win64" fn wcstoull(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> u64 {
    if nptr.is_null() {
        return 0;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(nptr) }.unwrap_or_default();
    let trimmed = s.trim_start();
    let offset = s.len() - trimmed.len();
    let radix = if base == 0 { 10 } else { base as u32 };
    let parsed = u64::from_str_radix(
        trimmed.split(|c: char| !c.is_alphanumeric()).next().unwrap_or(""),
        radix,
    )
    .unwrap_or(0);
    if !endptr.is_null() {
        unsafe {
            *endptr = nptr.add(offset) as *mut u16;
        }
    }
    parsed
}

pub extern "win64" fn wcstoll(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> i64 {
    if nptr.is_null() {
        return 0;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(nptr) }.unwrap_or_default();
    let trimmed = s.trim_start();
    let offset = s.len() - trimmed.len();
    let radix = if base == 0 { 10 } else { base as u32 };
    let parsed = i64::from_str_radix(
        trimmed.split(|c: char| !c.is_alphanumeric() && c != '-').next().unwrap_or(""),
        radix,
    )
    .unwrap_or(0);
    if !endptr.is_null() {
        unsafe {
            *endptr = nptr.add(offset) as *mut u16;
        }
    }
    parsed
}

pub extern "win64" fn wcstod(nptr: *const u16, endptr: *mut *mut u16) -> f64 {
    if nptr.is_null() {
        return 0.0;
    }
    let s = unsafe { crate::utils::wide_string::from_wide_ptr(nptr) }.unwrap_or_default();
    s.trim().parse::<f64>().unwrap_or(0.0)
}

pub extern "win64" fn clock() -> i64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    // MSVC CLOCKS_PER_SEC is 1000 and clock() reports elapsed wall-clock
    // milliseconds; returning microseconds here would make any guest that
    // divides by CLOCKS_PER_SEC see time advance 1000x too fast.
    start.elapsed().as_millis() as i64
}

#[repr(C)]
pub struct Tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

pub extern "win64" fn _gmtime64(time: *const i64) -> *mut Tm {
    if time.is_null() {
        return std::ptr::null_mut();
    }
    static mut TM_RES: Tm = Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 1,
        tm_mon: 0,
        tm_year: 70,
        tm_wday: 4,
        tm_yday: 0,
        tm_isdst: 0,
    };
    let t = unsafe { *time } as libc::time_t;
    let mut ltm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::gmtime_r(&t, &mut ltm);
        TM_RES.tm_sec = ltm.tm_sec;
        TM_RES.tm_min = ltm.tm_min;
        TM_RES.tm_hour = ltm.tm_hour;
        TM_RES.tm_mday = ltm.tm_mday;
        TM_RES.tm_mon = ltm.tm_mon;
        TM_RES.tm_year = ltm.tm_year;
        TM_RES.tm_wday = ltm.tm_wday;
        TM_RES.tm_yday = ltm.tm_yday;
        TM_RES.tm_isdst = ltm.tm_isdst;
        &raw mut TM_RES
    }
}

pub extern "win64" fn _gmtime64_s(tm: *mut Tm, time: *const i64) -> i32 {
    if tm.is_null() || time.is_null() {
        return -1;
    }
    let t = unsafe { *time } as libc::time_t;
    let mut ltm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::gmtime_r(&t, &mut ltm);
        (*tm).tm_sec = ltm.tm_sec;
        (*tm).tm_min = ltm.tm_min;
        (*tm).tm_hour = ltm.tm_hour;
        (*tm).tm_mday = ltm.tm_mday;
        (*tm).tm_mon = ltm.tm_mon;
        (*tm).tm_year = ltm.tm_year;
        (*tm).tm_wday = ltm.tm_wday;
        (*tm).tm_yday = ltm.tm_yday;
        (*tm).tm_isdst = ltm.tm_isdst;
    }
    0
}

pub extern "win64" fn _localtime64_s(tm: *mut Tm, time: *const i64) -> i32 {
    if tm.is_null() || time.is_null() {
        return -1;
    }
    let t = unsafe { *time } as libc::time_t;
    let mut ltm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&t, &mut ltm);
        (*tm).tm_sec = ltm.tm_sec;
        (*tm).tm_min = ltm.tm_min;
        (*tm).tm_hour = ltm.tm_hour;
        (*tm).tm_mday = ltm.tm_mday;
        (*tm).tm_mon = ltm.tm_mon;
        (*tm).tm_year = ltm.tm_year;
        (*tm).tm_wday = ltm.tm_wday;
        (*tm).tm_yday = ltm.tm_yday;
        (*tm).tm_isdst = ltm.tm_isdst;
    }
    0
}

pub extern "win64" fn _mktime64(tm: *mut Tm) -> i64 {
    if tm.is_null() {
        return -1;
    }
    let mut ltm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        ltm.tm_sec = (*tm).tm_sec;
        ltm.tm_min = (*tm).tm_min;
        ltm.tm_hour = (*tm).tm_hour;
        ltm.tm_mday = (*tm).tm_mday;
        ltm.tm_mon = (*tm).tm_mon;
        ltm.tm_year = (*tm).tm_year;
        ltm.tm_wday = (*tm).tm_wday;
        ltm.tm_yday = (*tm).tm_yday;
        ltm.tm_isdst = (*tm).tm_isdst;
        libc::mktime(&mut ltm) as i64
    }
}

pub extern "win64" fn _strftime_l(
    str_dest: *mut c_char,
    maxsize: usize,
    format: *const c_char,
    timeptr: *const Tm,
    _locale: usize,
) -> usize {
    if str_dest.is_null() || format.is_null() || timeptr.is_null() || maxsize == 0 {
        return 0;
    }
    unsafe {
        let ltm = timeptr as *const libc::tm;
        libc::strftime(str_dest, maxsize, format, ltm)
    }
}

pub extern "win64" fn _wcsdup(s: *const u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let s_str = unsafe { crate::utils::wide_string::from_wide_ptr(s) }.unwrap_or_default();
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
    tracing::info!(s = %s_str, ?ptr, "MSVCRT _wcsdup");
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
    if c == 0 {
        0
    } else {
        1
    }
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
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe { libc::strcoll(s1, s2) }
}

pub extern "win64" fn strxfrm(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    if src.is_null() {
        return 0;
    }
    unsafe { libc::strxfrm(dest, src, n) }
}

pub extern "win64" fn wcscoll(s1: *const u16, s2: *const u16) -> i32 {
    _wcsicmp(s1, s2)
}

pub extern "win64" fn wcsxfrm(dest: *mut u16, src: *const u16, n: usize) -> usize {
    if src.is_null() {
        return 0;
    }
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

pub extern "win64" fn strftime(
    s: *mut c_char,
    maxsize: usize,
    format: *const c_char,
    timeptr: *const c_void,
) -> usize {
    if s.is_null() || format.is_null() || timeptr.is_null() {
        return 0;
    }
    unsafe { libc::strftime(s, maxsize, format, timeptr.cast()) }
}

pub extern "win64" fn wcsftime(
    s: *mut u16,
    _maxsize: usize,
    _format: *const u16,
    _timeptr: *const c_void,
) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe {
        *s = 0;
    }
    0
}

pub extern "win64" fn getc(stream: *mut c_void) -> i32 {
    fgetc(stream)
}

pub extern "win64" fn getwc(stream: *mut c_void) -> i32 {
    fgetc(stream)
}

pub extern "win64" fn putc(c: i32, stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fputc(c, stream.cast()) }
}

pub extern "win64" fn putwc(c: u16, stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fputc(c as i32, stream.cast()) }
}

pub extern "win64" fn setvbuf(
    _stream: *mut c_void,
    _buf: *mut c_char,
    _mode: i32,
    _size: usize,
) -> i32 {
    0
}

pub extern "win64" fn ungetc(c: i32, stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::ungetc(c, stream.cast()) }
}

pub extern "win64" fn ungetwc(c: u16, stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::ungetc(c as i32, stream.cast()) }
}

fn is_iob_stream(stream: *mut c_void, index: usize) -> bool {
    let base = unsafe { (&raw mut IOB).cast::<u8>() };
    let stream_addr = stream as usize;
    let base_addr = base as usize;
    if stream_addr >= base_addr && stream_addr < base_addr + 1024 {
        let offset = stream_addr - base_addr;
        let file_idx = offset / 48;
        return file_idx == index;
    }
    false
}

pub extern "win64" fn __acrt_iob_func(index: u32) -> *mut c_void {
    let idx = if (index as usize) < 3 { index as usize } else { 0 };
    unsafe { (&raw mut IOB[idx * 48]).cast::<u8>().cast::<c_void>() }
}

unsafe fn format_wide_args(format: *const u16, argptr: usize) -> Vec<u16> {
    if format.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut args = argptr as *const usize;
    let mut i = 0;
    loop {
        let ch = *format.add(i);
        if ch == 0 {
            break;
        }
        if ch == '%' as u16 {
            i += 1;
            let next_ch = *format.add(i);
            if next_ch == 0 {
                break;
            }
            if next_ch == '%' as u16 {
                result.push('%' as u16);
                i += 1;
                continue;
            }

            let mut length_mod = String::new();
            while i < 1000 {
                let c = *format.add(i);
                if c == 0 {
                    break;
                }
                let c_char = c as u8 as char;
                if c_char == 'l'
                    || c_char == 'h'
                    || c_char == 'w'
                    || c_char == 'I'
                    || c_char == 'z'
                    || c_char.is_ascii_digit()
                    || c_char == '.'
                    || c_char == '-'
                    || c_char == '+'
                    || c_char == ' '
                    || c_char == '#'
                    || c_char == '0'
                {
                    length_mod.push(c_char);
                    i += 1;
                } else {
                    break;
                }
            }

            let spec = *format.add(i);
            if spec == 0 {
                break;
            }
            i += 1;

            if !args.is_null() {
                let val = *args;
                args = args.add(1);

                let spec_char = spec as u8 as char;
                match spec_char {
                    's' | 'S' => {
                        let is_narrow = length_mod.contains('h');
                        if is_narrow {
                            let narrow_ptr = val as *const std::ffi::c_char;
                            if !narrow_ptr.is_null() {
                                let s = std::ffi::CStr::from_ptr(narrow_ptr).to_string_lossy();
                                for u in s.encode_utf16() {
                                    result.push(u);
                                }
                            } else {
                                for u in "(null)".encode_utf16() {
                                    result.push(u);
                                }
                            }
                        } else {
                            let wide_ptr = val as *const u16;
                            if !wide_ptr.is_null() {
                                let mut len = 0;
                                while *wide_ptr.add(len) != 0 {
                                    result.push(*wide_ptr.add(len));
                                    len += 1;
                                }
                            } else {
                                for u in "(null)".encode_utf16() {
                                    result.push(u);
                                }
                            }
                        }
                    }
                    'd' | 'i' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str =
                            if is_64 { (val as i64).to_string() } else { (val as i32).to_string() };
                        for u in num_str.encode_utf16() {
                            result.push(u);
                        }
                    }
                    'u' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str =
                            if is_64 { (val as u64).to_string() } else { (val as u32).to_string() };
                        for u in num_str.encode_utf16() {
                            result.push(u);
                        }
                    }
                    'x' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str = if is_64 {
                            format!("{:x}", val as u64)
                        } else {
                            format!("{:x}", val as u32)
                        };
                        for u in num_str.encode_utf16() {
                            result.push(u);
                        }
                    }
                    'X' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str = if is_64 {
                            format!("{:X}", val as u64)
                        } else {
                            format!("{:X}", val as u32)
                        };
                        for u in num_str.encode_utf16() {
                            result.push(u);
                        }
                    }
                    'p' => {
                        let num_str = format!("{:p}", val as *const ());
                        for u in num_str.encode_utf16() {
                            result.push(u);
                        }
                    }
                    'c' | 'C' => {
                        result.push(val as u16);
                    }
                    _ => {}
                }
            }
        } else {
            result.push(ch);
            i += 1;
        }
    }
    result.push(0);
    result
}

unsafe fn format_narrow_args(format: *const c_char, argptr: usize) -> Vec<u8> {
    if format.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut args = argptr as *const usize;
    let mut i = 0;
    loop {
        let ch = *format.add(i) as u8;
        if ch == 0 {
            break;
        }
        if ch == b'%' {
            i += 1;
            let next_ch = *format.add(i) as u8;
            if next_ch == 0 {
                break;
            }
            if next_ch == b'%' {
                result.push(b'%');
                i += 1;
                continue;
            }

            let mut length_mod = String::new();
            while i < 1000 {
                let c = *format.add(i) as u8;
                if c == 0 {
                    break;
                }
                let c_char = c as char;
                if c_char == 'l'
                    || c_char == 'h'
                    || c_char == 'w'
                    || c_char == 'I'
                    || c_char == 'z'
                    || c_char.is_ascii_digit()
                    || c_char == '.'
                    || c_char == '-'
                    || c_char == '+'
                    || c_char == ' '
                    || c_char == '#'
                    || c_char == '0'
                {
                    length_mod.push(c_char);
                    i += 1;
                } else {
                    break;
                }
            }

            let spec = *format.add(i) as u8;
            if spec == 0 {
                break;
            }
            i += 1;

            if !args.is_null() {
                let val = *args;
                args = args.add(1);

                let spec_char = spec as char;
                match spec_char {
                    's' | 'S' => {
                        let is_wide = length_mod.contains('l')
                            || length_mod.contains('w')
                            || spec_char == 'S';
                        if is_wide {
                            let wide_ptr = val as *const u16;
                            if !wide_ptr.is_null() {
                                let mut len = 0;
                                while *wide_ptr.add(len) != 0 {
                                    len += 1;
                                }
                                let slice = std::slice::from_raw_parts(wide_ptr, len);
                                let s = String::from_utf16_lossy(slice);
                                result.extend_from_slice(s.as_bytes());
                            } else {
                                result.extend_from_slice(b"(null)");
                            }
                        } else {
                            let narrow_ptr = val as *const std::ffi::c_char;
                            if !narrow_ptr.is_null() {
                                let s = std::ffi::CStr::from_ptr(narrow_ptr).to_bytes();
                                result.extend_from_slice(s);
                            } else {
                                result.extend_from_slice(b"(null)");
                            }
                        }
                    }
                    'd' | 'i' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str =
                            if is_64 { (val as i64).to_string() } else { (val as i32).to_string() };
                        result.extend_from_slice(num_str.as_bytes());
                    }
                    'u' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str =
                            if is_64 { (val as u64).to_string() } else { (val as u32).to_string() };
                        result.extend_from_slice(num_str.as_bytes());
                    }
                    'x' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str = if is_64 {
                            format!("{:x}", val as u64)
                        } else {
                            format!("{:x}", val as u32)
                        };
                        result.extend_from_slice(num_str.as_bytes());
                    }
                    'X' => {
                        let is_64 = length_mod.contains("ll") || length_mod.contains("I64");
                        let num_str = if is_64 {
                            format!("{:X}", val as u64)
                        } else {
                            format!("{:X}", val as u32)
                        };
                        result.extend_from_slice(num_str.as_bytes());
                    }
                    'p' => {
                        let num_str = format!("{:p}", val as *const ());
                        result.extend_from_slice(num_str.as_bytes());
                    }
                    'c' | 'C' => {
                        result.push(val as u8);
                    }
                    _ => {}
                }
            }
        } else {
            result.push(ch);
            i += 1;
        }
    }
    result.push(0);
    result
}

pub extern "win64" fn __stdio_common_vsprintf(
    _options: u64,
    buffer: *mut c_char,
    count: usize,
    format: *const c_char,
    _locale: usize,
    argptr: usize,
) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    let formatted = unsafe { format_narrow_args(format, argptr) };
    let len = formatted.len().saturating_sub(1);
    let copy_len = if count > 0 { len.min(count - 1) } else { len };
    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr(), buffer as *mut u8, copy_len);
        *buffer.add(copy_len) = 0;
    }
    copy_len as i32
}

pub extern "win64" fn __stdio_common_vsnprintf_s(
    _options: u64,
    buffer: *mut c_char,
    buffer_count: usize,
    max_count: usize,
    format: *const c_char,
    _locale: usize,
    argptr: usize,
) -> i32 {
    let count = if buffer_count > 0 && max_count > 0 {
        buffer_count.min(max_count)
    } else if buffer_count > 0 {
        buffer_count
    } else {
        max_count
    };
    __stdio_common_vsprintf(_options, buffer, count, format, _locale, argptr)
}

/// Legacy MSVCRT/NTDLL `_vsnprintf` entry point. Unlike `snprintf`, its final
/// argument is a Windows `va_list`, represented by a pointer to argument slots
/// on x64.
pub extern "win64" fn _vsnprintf(
    buffer: *mut c_char,
    count: usize,
    format: *const c_char,
    argptr: usize,
) -> i32 {
    __stdio_common_vsprintf(0, buffer, count, format, 0, argptr)
}

pub extern "win64" fn __stdio_common_vfprintf(
    _options: u64,
    stream: *mut c_void,
    format: *const c_char,
    _locale: usize,
    argptr: usize,
) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    use std::io::Write;
    let formatted = unsafe { format_narrow_args(format, argptr) };
    let len = formatted.len().saturating_sub(1);
    let bytes = &formatted[..len];
    if is_iob_stream(stream, 1) {
        let _ = std::io::stdout().write_all(bytes);
        return len as i32;
    }
    if is_iob_stream(stream, 2) {
        let _ = std::io::stderr().write_all(bytes);
        return len as i32;
    }
    unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, len, stream.cast()) as i32 }
}

pub extern "win64" fn __stdio_common_vfwprintf(
    _options: u64,
    stream: *mut c_void,
    format: *const u16,
    _locale: usize,
    argptr: usize,
) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    use std::io::Write;
    let formatted = unsafe { format_wide_args(format, argptr) };
    let len = formatted.len().saturating_sub(1);
    let s = String::from_utf16_lossy(&formatted[..len]);
    if is_iob_stream(stream, 1) {
        let _ = std::io::stdout().write_all(s.as_bytes());
        return len as i32;
    }
    if is_iob_stream(stream, 2) {
        let _ = std::io::stderr().write_all(s.as_bytes());
        return len as i32;
    }
    unsafe { libc::fwrite(s.as_ptr().cast(), 1, s.len(), stream.cast()) as i32 }
}

pub extern "win64" fn __stdio_common_vswprintf(
    _options: u64,
    buffer: *mut u16,
    count: usize,
    format: *const u16,
    _locale: usize,
    argptr: usize,
) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    let formatted = unsafe { format_wide_args(format, argptr) };
    let len = formatted.len().saturating_sub(1);
    let copy_len = if count > 0 { len.min(count - 1) } else { len };
    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr(), buffer, copy_len);
        *buffer.add(copy_len) = 0;
    }
    copy_len as i32
}

pub extern "win64" fn __stdio_common_vswprintf_s(
    _options: u64,
    buffer: *mut u16,
    count: usize,
    format: *const u16,
    _locale: usize,
    argptr: usize,
) -> i32 {
    __stdio_common_vswprintf(_options, buffer, count, format, _locale, argptr)
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
    let s = unsafe { CStr::from_ptr(filename) }.to_str().unwrap_or_default();
    let host_path = guest_path_to_host(s);
    let c_file = match std::ffi::CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let res = unsafe { libc::fopen(c_file.as_ptr(), mode).cast::<c_void>() };
    tracing::trace!(guest_path = %s, ?host_path, ?res, "MSVCRT fopen");
    res
}

pub extern "win64" fn _wfopen(filename: *const u16, mode: *const u16) -> *mut c_void {
    if filename.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    let filename_utf8 =
        unsafe { crate::utils::wide_string::from_wide_ptr(filename) }.ok().unwrap_or_default();
    let mode_utf8 =
        unsafe { crate::utils::wide_string::from_wide_ptr(mode) }.ok().unwrap_or_default();
    let host_path = guest_path_to_host(&filename_utf8);
    let c_file = match std::ffi::CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let c_mode = match std::ffi::CString::new(mode_utf8) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let res = unsafe { libc::fopen(c_file.as_ptr(), c_mode.as_ptr()).cast::<c_void>() };
    tracing::trace!(guest_path = %filename_utf8, ?host_path, ?res, "MSVCRT _wfopen");
    res
}

pub extern "win64" fn fclose(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fclose(stream.cast()) }
}

pub extern "win64" fn fread(
    ptr: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut c_void,
) -> usize {
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
        unsafe {
            libc::clearerr(stream.cast());
        }
    }
}

static FD_TO_HANDLE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<i32, usize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
static HANDLE_TO_FD: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<usize, i32>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

pub fn register_fd_handle(fd: i32, host_path: std::path::PathBuf) -> (i32, usize) {
    if fd < 0 {
        return (fd, 0);
    }
    let handle = crate::utils::handle::global_table()
        .alloc(Box::new(crate::nt_kernel::file::FileHandle { fd, host_path }));
    let mut map1 = FD_TO_HANDLE.lock().unwrap();
    let mut map2 = HANDLE_TO_FD.lock().unwrap();
    map1.insert(fd, handle);
    map2.insert(handle, fd);
    (fd, handle)
}

pub extern "win64" fn _get_osfhandle(fd: i32) -> isize {
    if fd < 0 {
        return -1;
    }
    if fd == 0 {
        return crate::utils::handle::PSEUDO_STDIN as isize;
    }
    if fd == 1 {
        return crate::utils::handle::PSEUDO_STDOUT as isize;
    }
    if fd == 2 {
        return crate::utils::handle::PSEUDO_STDERR as isize;
    }
    let mut map1 = FD_TO_HANDLE.lock().unwrap();
    if let Some(&handle) = map1.get(&fd) {
        return handle as isize;
    }
    let handle =
        crate::utils::handle::global_table().alloc(Box::new(crate::nt_kernel::file::FileHandle {
            fd,
            host_path: std::path::PathBuf::new(),
        }));
    map1.insert(fd, handle);
    HANDLE_TO_FD.lock().unwrap().insert(handle, fd);
    tracing::info!(fd, handle, "MSVCRT _get_osfhandle registered handle");
    handle as isize
}

pub extern "win64" fn _open_osfhandle(osfhandle: isize, _flags: i32) -> i32 {
    if osfhandle <= 0 {
        return -1;
    }
    let h = osfhandle as usize;
    if h == crate::utils::handle::PSEUDO_STDIN {
        return 0;
    }
    if h == crate::utils::handle::PSEUDO_STDOUT {
        return 1;
    }
    if h == crate::utils::handle::PSEUDO_STDERR {
        return 2;
    }

    let map2 = HANDLE_TO_FD.lock().unwrap();
    if let Some(&fd) = map2.get(&h) {
        return fd;
    }
    drop(map2);

    let mut fd_opt = None;
    crate::utils::handle::global_table().with(h, |obj: &dyn crate::utils::handle::HandleObject| {
        if let Some(file) = obj.as_any().downcast_ref::<crate::nt_kernel::file::FileHandle>() {
            fd_opt = Some(file.fd);
        }
    });

    if let Some(fd) = fd_opt {
        FD_TO_HANDLE.lock().unwrap().insert(fd, h);
        HANDLE_TO_FD.lock().unwrap().insert(h, fd);
        fd
    } else {
        -1
    }
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

static PCTYPE_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let c = i as u8;
        let mut mask = 0u16;
        if c.is_ascii_uppercase() {
            mask |= 0x0001 | 0x0100;
        }
        if c.is_ascii_lowercase() {
            mask |= 0x0002 | 0x0100;
        }
        if c.is_ascii_digit() {
            mask |= 0x0004;
        }
        if c == b' ' || c == b'\t' || c == b'\n' || c == 0x0b || c == 0x0c || c == b'\r' {
            mask |= 0x0008;
        }
        if c.is_ascii_punctuation() {
            mask |= 0x0010;
        }
        if c.is_ascii_control() {
            mask |= 0x0020;
        }
        if c == b' ' || c == b'\t' {
            mask |= 0x0040;
        }
        if c.is_ascii_hexdigit() {
            mask |= 0x0080;
        }
        table[i] = mask;
        i += 1;
    }
    table
};

pub extern "win64" fn __pctype_func() -> *const u16 {
    PCTYPE_TABLE.as_ptr()
}

pub extern "win64" fn _getcwd(buf: *mut c_char, size: i32) -> *mut c_char {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let win_cwd = format!("Z:{}", cwd.to_string_lossy().replace('/', "\\"));
    let len = win_cwd.len();
    if buf.is_null() {
        let alloc_size = if size > 0 { (size as usize).max(len + 1) } else { len + 1 };
        let ptr = malloc(alloc_size).cast::<c_char>();
        if !ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(win_cwd.as_ptr() as *const c_char, ptr, len);
                *ptr.add(len) = 0;
            }
        }
        ptr
    } else {
        if (size as usize) < len + 1 {
            return std::ptr::null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(win_cwd.as_ptr() as *const c_char, buf, len);
            *buf.add(len) = 0;
        }
        buf
    }
}

pub extern "win64" fn _wgetcwd(buf: *mut u16, size: i32) -> *mut u16 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let win_cwd = format!("Z:{}", cwd.to_string_lossy().replace('/', "\\"));
    let wide = crate::utils::wide_string::to_wide_null(&win_cwd);
    let len = wide.len();
    if buf.is_null() {
        let alloc_size = if size > 0 { (size as usize).max(len) } else { len };
        let ptr = malloc(alloc_size * 2).cast::<u16>();
        if !ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, len);
            }
        }
        ptr
    } else {
        if (size as usize) < len {
            return std::ptr::null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), buf, len);
        }
        buf
    }
}

pub extern "win64" fn _isatty(fd: i32) -> i32 {
    unsafe { libc::isatty(fd) }
}

pub extern "win64" fn _setmode(_fd: i32, _mode: i32) -> i32 {
    0x8000
}

pub extern "win64" fn _configthreadlocale(_per_thread_locale_type: i32) -> i32 {
    -1
}

pub extern "win64" fn _create_locale(_category: i32, _locale: *const c_char) -> *mut c_void {
    1 as *mut c_void
}

pub extern "win64" fn _free_locale(_locale: *mut c_void) {}

pub extern "win64" fn _mbtowc_l(
    pwc: *mut u16,
    s: *const c_char,
    count: usize,
    _locale: *mut c_void,
) -> i32 {
    if s.is_null() || count == 0 {
        return 0;
    }
    let b = unsafe { *s as u8 };
    if b == 0 {
        if !pwc.is_null() {
            unsafe {
                *pwc = 0;
            }
        }
        return 0;
    }
    if !pwc.is_null() {
        unsafe {
            *pwc = b as u16;
        }
    }
    1
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
    exports.insert("_localeconv_l", _localeconv_l as usize);
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
    exports.insert("_wstat64", _wstat64 as usize);
    exports.insert("_wstat64i32", _wstat64i32 as usize);
    exports.insert("_access", _access as usize);
    exports.insert("_waccess", _waccess as usize);
    exports.insert("_wfullpath", _wfullpath as usize);
    exports.insert("_mkdir", _mkdir as usize);
    exports.insert("_wmkdir", _wmkdir as usize);
    exports.insert("_wremove", _wremove as usize);
    exports.insert("_chdir", _chdir as usize);
    exports.insert("_wchdir", _wchdir as usize);
    exports.insert("_lock_file", _lock_file as usize);
    exports.insert("_unlock_file", _unlock_file as usize);
    exports.insert("remove", remove as usize);
    exports.insert("rename", rename as usize);
    exports.insert("_unlink", _unlink as usize);
    exports.insert("_fdopen", _fdopen as usize);
    exports.insert("_fileno", _fileno as usize);
    exports.insert("_open", _open as usize);
    exports.insert("_wopen", _wopen as usize);
    exports.insert("_sopen", _sopen as usize);
    exports.insert("_wsopen", _wsopen as usize);
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
    exports.insert("__pctype_func", __pctype_func as usize);
    exports.insert("_getcwd", _getcwd as usize);
    exports.insert("_wgetcwd", _wgetcwd as usize);
    exports.insert("_isatty", _isatty as usize);
    exports.insert("_setmode", _setmode as usize);
    exports.insert("_configthreadlocale", _configthreadlocale as usize);
    exports.insert("_create_locale", _create_locale as usize);
    exports.insert("_free_locale", _free_locale as usize);
    exports.insert("_mbtowc_l", _mbtowc_l as usize);
    exports.insert("__doserrno", __doserrno as usize);
    exports.insert("__sys_nerr", __sys_nerr as usize);
    exports.insert("_getpid", _getpid as usize);
    exports.insert("_time64", _time64 as usize);
    exports.insert("time", _time64 as usize);
    exports.insert("_commit", _commit as usize);
    exports.insert("_dup", _dup as usize);
    exports.insert("_dup2", _dup2 as usize);
    exports.insert("_chsize_s", _chsize_s as usize);
    exports.insert("_umask", _umask as usize);
    exports.insert("_wputenv", _wputenv as usize);
    exports.insert("_wputenv_s", _wputenv_s as usize);
    exports.insert("wcscpy_s", wcscpy_s as usize);
    exports.insert("wcsncpy_s", wcsncpy_s as usize);
    exports.insert("wcscat_s", wcscat_s as usize);
    exports.insert("wcstok_s", wcstok_s as usize);
    exports.insert("acosh", acosh as usize);
    exports.insert("asinh", asinh as usize);
    exports.insert("atanh", atanh as usize);
    exports.insert("copysign", copysign as usize);
    exports.insert("expm1", expm1 as usize);
    exports.insert("log1p", log1p as usize);
    exports.insert("log2", log2 as usize);
    exports.insert("fma", fma as usize);
    exports.insert("nextafter", nextafter as usize);
    exports.insert("rewind", rewind as usize);
    exports.insert("putchar", putchar as usize);
    exports.insert("raise", raise as usize);
    exports.insert("_heapmin", _heapmin as usize);
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
    exports.insert("_vsnprintf", _vsnprintf as usize);
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

    exports.insert("strncat", strncat as usize);
    exports.insert("strnlen", strnlen as usize);
    exports.insert("strpbrk", strpbrk as usize);
    exports.insert("strspn", strspn as usize);
    exports.insert("strtok", strtok as usize);
    exports.insert("tolower", tolower as usize);
    exports.insert("toupper", toupper as usize);
    exports.insert("isalnum", isalnum as usize);
    exports.insert("isalpha", isalpha as usize);
    exports.insert("isblank", isblank as usize);
    exports.insert("iscntrl", iscntrl as usize);
    exports.insert("isdigit", isdigit as usize);
    exports.insert("isgraph", isgraph as usize);
    exports.insert("islower", islower as usize);
    exports.insert("isprint", isprint as usize);
    exports.insert("ispunct", ispunct as usize);
    exports.insert("isspace", isspace as usize);
    exports.insert("isupper", isupper as usize);
    exports.insert("isxdigit", isxdigit as usize);
    exports.insert("wcschr", wcschr as usize);
    exports.insert("wcsstr", wcsstr as usize);
    exports.insert("wcscpy", wcscpy as usize);
    exports.insert("wcsncpy", wcsncpy as usize);
    exports.insert("wcsnlen", wcsnlen as usize);
    exports.insert("_wcsnicmp", _wcsnicmp as usize);
    exports.insert("_strlwr", _strlwr as usize);
    exports.insert("_strupr", _strupr as usize);
    exports.insert("_putenv", _putenv as usize);
    exports.insert("_wgetenv", _wgetenv as usize);
    exports.insert("qsort", qsort as usize);
    exports.insert("bsearch", bsearch as usize);
    exports.insert("rand", rand as usize);
    exports.insert("atof", atof as usize);
    exports.insert("_itoa", _itoa as usize);
    exports.insert("_ltoa", _ltoa as usize);
    exports.insert("_i64toa", _i64toa as usize);
    exports.insert("_ui64toa", _ui64toa as usize);
    exports.insert("_ultoa", _ultoa as usize);
    exports.insert("wcstoul", wcstoul as usize);
    exports.insert("wcstoull", wcstoull as usize);
    exports.insert("wcstoll", wcstoll as usize);
    exports.insert("wcstod", wcstod as usize);
    exports.insert("clock", clock as usize);
    exports.insert("_gmtime64", _gmtime64 as usize);
    exports.insert("_gmtime64_s", _gmtime64_s as usize);
    exports.insert("_localtime64_s", _localtime64_s as usize);
    exports.insert("_mktime64", _mktime64 as usize);
    exports.insert("_strftime_l", _strftime_l as usize);

    exports.insert("acos", acos as usize);
    exports.insert("acosf", acosf as usize);
    exports.insert("asin", asin as usize);
    exports.insert("asinf", asinf as usize);
    exports.insert("atanf", atanf as usize);
    exports.insert("atan2f", atan2f as usize);
    exports.insert("sinf", sinf as usize);
    exports.insert("cosf", cosf as usize);
    exports.insert("tanf", tanf as usize);
    exports.insert("sinh", sinh as usize);
    exports.insert("cosh", cosh as usize);
    exports.insert("tanh", tanh as usize);
    exports.insert("expf", expf as usize);
    exports.insert("exp2", exp2 as usize);
    exports.insert("exp2f", exp2f as usize);
    exports.insert("logf", logf as usize);
    exports.insert("log10", log10 as usize);
    exports.insert("log10f", log10f as usize);
    exports.insert("log2f", log2f as usize);
    exports.insert("sqrtf", sqrtf as usize);
    exports.insert("ceilf", ceilf as usize);
    exports.insert("floorf", floorf as usize);
    exports.insert("fmod", fmod as usize);
    exports.insert("fmodf", fmodf as usize);
    exports.insert("hypot", hypot as usize);
    exports.insert("_hypot", _hypot as usize);
    exports.insert("round", round as usize);
    exports.insert("roundf", roundf as usize);
    exports.insert("trunc", trunc as usize);
    exports.insert("truncf", truncf as usize);
    exports.insert("cbrt", cbrt as usize);
    exports.insert("frexp", frexp as usize);
    exports.insert("modf", modf as usize);
    exports.insert("rint", rint as usize);
    exports.insert("lrint", lrint as usize);
    exports.insert("lround", lround as usize);
    exports.insert("lroundf", lroundf as usize);

    exports.insert("__getmainargs", __getmainargs as usize);
    exports.insert("__set_app_type", __set_app_type as usize);
    exports.insert("_set_app_type", __set_app_type as usize);
    exports.insert("_initterm", _initterm as usize);
    exports.insert("exit", exit as usize);
    exports.insert("_exit", exit as usize);

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
    fn underscore_vsnprintf_formats_a_windows_va_list() {
        let format = c"value=%d";
        let args = [42usize];
        let mut output = [0_i8; 32];

        let written =
            _vsnprintf(output.as_mut_ptr(), output.len(), format.as_ptr(), args.as_ptr() as usize);

        assert_eq!(written, 8);
        assert_eq!(unsafe { CStr::from_ptr(output.as_ptr()) }.to_bytes(), b"value=42");
        assert_eq!(get_exports().get("_vsnprintf"), Some(&(_vsnprintf as usize)));
    }

    #[test]
    fn clock_uses_msvc_millisecond_ticks() {
        let start = clock();
        std::thread::sleep(std::time::Duration::from_millis(25));
        let elapsed = clock() - start;

        assert!((15..=250).contains(&elapsed), "clock advanced by {elapsed} ticks in 25 ms");
    }

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
            assert!(std::slice::from_raw_parts(grown.add(4), 12).iter().all(|byte| *byte == 0));
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
