#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! ExitProcess, GetModuleHandleA/W, GetCommandLineA/W, GetCurrentProcessId.

use std::ffi::{c_void, CStr, CString};
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{OnceLock, RwLock};
use tracing::{trace, warn};

use crate::dll_manager::{
    free_library, get_loaded_module_filename, get_loaded_module_handle, load_library,
    resolve_export,
};
use crate::exceptions::unwind::{lookup_runtime_function, RuntimeFunction};
use crate::utils::handle::{
    global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE,
};
use crate::utils::wide_string::from_wide_ptr;

pub extern "win64" fn exit_process(exit_code: u32) {
    trace!("ExitProcess({})", exit_code);
    std::process::exit(exit_code as i32);
}

// Global variable for the main image base
static mut MAIN_IMAGE_BASE: usize = 0x0040_0000; // Will be set during PE loading
static mut MAIN_IMAGE_SIZE: usize = 0;
static CMD_LINE_A_PTR: AtomicPtr<i8> = AtomicPtr::new(std::ptr::null_mut());
static CMD_LINE_W_PTR: AtomicPtr<u16> = AtomicPtr::new(std::ptr::null_mut());
static PROCESS_ERROR_MODE: AtomicU32 = AtomicU32::new(0);

pub fn set_main_image_base(base: usize) {
    unsafe {
        MAIN_IMAGE_BASE = base;
    }
}

pub fn set_main_image_layout(base: usize, size: usize) {
    unsafe {
        MAIN_IMAGE_BASE = base;
        MAIN_IMAGE_SIZE = size;
    }
}

pub fn main_image_contains(address: usize) -> bool {
    unsafe {
        if MAIN_IMAGE_BASE == 0 || MAIN_IMAGE_SIZE == 0 {
            return false;
        }
        let end = MAIN_IMAGE_BASE.saturating_add(MAIN_IMAGE_SIZE);
        address >= MAIN_IMAGE_BASE && address < end
    }
}

/// Fast check for specific addresses that are frequently accessed
pub fn is_likely_main_image_address(address: usize) -> bool {
    // Specific addresses that are commonly accessed based on our logs
    // The game seems to repeatedly access addresses around this range
    address >= 0x140000000 && address < 0x140003000
}

fn main_image_path_store() -> &'static RwLock<String> {
    static MAIN_IMAGE_PATH: OnceLock<RwLock<String>> = OnceLock::new();
    MAIN_IMAGE_PATH.get_or_init(|| RwLock::new("tuxexe".to_string()))
}

fn normalize_guest_path(path: &Path) -> String {
    let candidate = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    candidate.to_string_lossy().replace('/', "\\")
}

pub fn set_main_image_path(path: &Path) {
    let normalized = normalize_guest_path(path);
    *main_image_path_store().write().expect("main image path lock poisoned") = normalized;
}

fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() || arg.contains([' ', '\t', '"']) {
        let escaped = arg.replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        arg.to_string()
    }
}

fn build_guest_command_line(exe_path: &Path, args: &[String]) -> String {
    let exe = normalize_guest_path(exe_path);
    std::iter::once(exe)
        .chain(args.iter().cloned())
        .map(|arg| quote_windows_arg(&arg))
        .collect::<Vec<String>>()
        .join(" ")
}

fn install_guest_command_line(cmd: String) {
    let sanitized = cmd.replace('\0', " ");
    let cstring = CString::new(sanitized.clone())
        .unwrap_or_else(|_| CString::new("").expect("empty cstring must be valid"));
    let leaked_a: &'static mut std::ffi::CStr = Box::leak(cstring.into_boxed_c_str());
    CMD_LINE_A_PTR.store(leaked_a.as_ptr() as *mut i8, Ordering::Release);

    let mut wide: Vec<u16> = sanitized.encode_utf16().collect();
    wide.push(0);
    let leaked_wide: &'static mut [u16] = Box::leak(wide.into_boxed_slice());
    CMD_LINE_W_PTR.store(leaked_wide.as_mut_ptr(), Ordering::Release);
}

fn ensure_guest_command_line_initialized() {
    if !CMD_LINE_A_PTR.load(Ordering::Acquire).is_null()
        && !CMD_LINE_W_PTR.load(Ordering::Acquire).is_null()
    {
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.iter().map(|arg| quote_windows_arg(arg)).collect::<Vec<String>>().join(" ");
    install_guest_command_line(cmd);
}

pub fn set_guest_command_line(exe_path: &Path, args: &[String]) {
    let cmd = build_guest_command_line(exe_path, args);
    install_guest_command_line(cmd);
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_FILES: u32 = 18;
const STILL_ACTIVE: u32 = 259;
const WINDOWS_EPOCH_DIFF_SECS: u64 = 11_644_473_600;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const CURRENT_PROCESS_PSEUDO_HANDLE: usize = usize::MAX;
const CURRENT_THREAD_PSEUDO_HANDLE: u32 = 0xFFFF_FFFE;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_TYPE_AMD_X8664: u32 = 8664;
const BATTERY_FLAG_NO_BATTERY: u8 = 0x80;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;

fn set_last_error(err: u32) {
    super::error::set_last_error(err);
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleEntry32W {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: *mut u8,
    pub modBaseSize: u32,
    pub hModule: usize,
    pub szModule: [u16; 256],
    pub szExePath: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleEntry32A {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: *mut u8,
    pub modBaseSize: u32,
    pub hModule: usize,
    pub szModule: [u8; 256],
    pub szExePath: [u8; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemPowerStatus {
    ac_line_status: u8,
    battery_flag: u8,
    battery_life_percent: u8,
    system_status_flag: u8,
    battery_life_time: u32,
    battery_full_life_time: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessMemoryCounters {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
}

#[derive(Debug)]
struct ToolhelpSnapshot {
    process_consumed: AtomicBool,
    thread_consumed: AtomicBool,
    module_index: AtomicU32,
    module_count: u32,
    include_modules: bool,
}

impl HandleObject for ToolhelpSnapshot {
    fn type_name(&self) -> &'static str {
        "ToolhelpSnapshot"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessEntry32A {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [i8; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    th32_thread_id: u32,
    th32_owner_process_id: u32,
    tp_base_pri: i32,
    tp_delta_pri: i32,
    dw_flags: u32,
}

fn should_return_stub_for_missing_getproc() -> bool {
    std::env::var("TUXEXE_GETPROC_FALLBACK_STUB")
        .ok()
        .is_some_and(|value| value == "1")
}

extern "win64" fn missing_getproc_stub() -> usize {
    crate::runtime::telemetry::record("missing_getproc_stub invoked".to_string());
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemInfo {
    w_processor_architecture: u16,
    w_reserved: u16,
    dw_page_size: u32,
    lp_minimum_application_address: *mut c_void,
    lp_maximum_application_address: *mut c_void,
    dw_active_processor_mask: usize,
    dw_number_of_processors: u32,
    dw_processor_type: u32,
    dw_allocation_granularity: u32,
    w_processor_level: u16,
    w_processor_revision: u16,
}

fn write_system_info(lp_system_info: *mut c_void) {
    if lp_system_info.is_null() {
        return;
    }

    let cpu_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let active_mask =
        if cpu_count >= usize::BITS as usize { usize::MAX } else { (1usize << cpu_count) - 1 };

    let info = SystemInfo {
        w_processor_architecture: PROCESSOR_ARCHITECTURE_AMD64,
        w_reserved: 0,
        dw_page_size: 0x1000,
        lp_minimum_application_address: 0x0001_0000usize as *mut c_void,
        lp_maximum_application_address: 0x0000_7fff_ffff_ffffusize as *mut c_void,
        dw_active_processor_mask: active_mask,
        dw_number_of_processors: cpu_count as u32,
        dw_processor_type: PROCESSOR_TYPE_AMD_X8664,
        dw_allocation_granularity: 0x1_0000,
        w_processor_level: 6,
        w_processor_revision: 0,
    };

    unsafe {
        std::ptr::write(lp_system_info.cast::<SystemInfo>(), info);
    }
}

fn current_filetime_value() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0));
    let secs = now.as_secs() + WINDOWS_EPOCH_DIFF_SECS;
    let nanos = now.subsec_nanos() as u64;
    (secs * 10_000_000) + (nanos / 100)
}

pub extern "win64" fn get_module_handle_a(module_name: *const i8) -> *mut c_void {
    if module_name.is_null() {
        set_last_error(ERROR_SUCCESS);
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        let name = unsafe { CStr::from_ptr(module_name) };
        match name.to_str().ok().and_then(get_loaded_module_handle) {
            Some(handle) => {
                set_last_error(ERROR_SUCCESS);
                handle as *mut c_void
            }
            None => {
                set_last_error(ERROR_MOD_NOT_FOUND);
                std::ptr::null_mut()
            }
        }
    }
}

pub extern "win64" fn get_module_handle_w(module_name: *const u16) -> *mut c_void {
    if module_name.is_null() {
        set_last_error(ERROR_SUCCESS);
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        match unsafe { from_wide_ptr(module_name).ok() }.and_then(|s| get_loaded_module_handle(&s))
        {
            Some(handle) => {
                set_last_error(ERROR_SUCCESS);
                handle as *mut c_void
            }
            None => {
                set_last_error(ERROR_MOD_NOT_FOUND);
                std::ptr::null_mut()
            }
        }
    }
}

pub extern "win64" fn get_module_handle_ex_a(
    flags: u32,
    lp_module_name: *const i8,
    ph_module: *mut *mut c_void,
) -> i32 {
    if ph_module.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let handle = if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
        if lp_module_name.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        // Best-effort: map any in-process address to the main image handle.
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else if lp_module_name.is_null() {
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        get_module_handle_a(lp_module_name)
    };

    if handle.is_null() {
        return 0;
    }

    unsafe {
        *ph_module = handle;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn get_module_handle_ex_w(
    flags: u32,
    lp_module_name: *const u16,
    ph_module: *mut *mut c_void,
) -> i32 {
    if ph_module.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let handle = if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
        if lp_module_name.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        // Best-effort: map any in-process address to the main image handle.
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else if lp_module_name.is_null() {
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        get_module_handle_w(lp_module_name)
    };

    if handle.is_null() {
        return 0;
    }

    unsafe {
        *ph_module = handle;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn get_module_file_name_w(
    h_module: *mut c_void,
    lp_filename: *mut u16,
    n_size: u32,
) -> u32 {
    if lp_filename.is_null() || n_size == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let module_path = if h_module.is_null() || h_module as usize == unsafe { MAIN_IMAGE_BASE } {
        main_image_path_store().read().expect("main image path lock poisoned").clone()
    } else {
        let Some(path) = get_loaded_module_filename(h_module as usize) else {
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        };
        path.replace('/', "\\")
    };

    let wide: Vec<u16> = module_path.encode_utf16().collect();
    let capacity = n_size as usize;

    if wide.len() + 1 > capacity {
        let copy_len = capacity.saturating_sub(1);
        unsafe {
            if copy_len > 0 {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_filename, copy_len);
            }
            *lp_filename.add(copy_len) = 0;
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return n_size;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_filename, wide.len());
        *lp_filename.add(wide.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    wide.len() as u32
}

pub extern "win64" fn get_module_file_name_a(
    h_module: *mut c_void,
    lp_filename: *mut i8,
    n_size: u32,
) -> u32 {
    if lp_filename.is_null() || n_size == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let module_path = if h_module.is_null() || h_module as usize == unsafe { MAIN_IMAGE_BASE } {
        main_image_path_store().read().expect("main image path lock poisoned").clone()
    } else {
        let Some(path) = get_loaded_module_filename(h_module as usize) else {
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        };
        path.replace('/', "\\")
    };

    let bytes = module_path.as_bytes();
    let capacity = n_size as usize;

    if bytes.len() + 1 > capacity {
        let copy_len = capacity.saturating_sub(1);
        unsafe {
            if copy_len > 0 {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_filename.cast::<u8>(), copy_len);
            }
            *lp_filename.add(copy_len) = 0;
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return n_size;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_filename.cast::<u8>(), bytes.len());
        *lp_filename.add(bytes.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    bytes.len() as u32
}

pub extern "win64" fn load_library_a(lp_lib_file_name: *const i8) -> *mut c_void {
    if lp_lib_file_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    let Ok(name) = (unsafe { CStr::from_ptr(lp_lib_file_name).to_str() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    match load_library(name) {
        Ok(handle) => {
            trace!("LoadLibraryA(\"{}\") -> 0x{:x}", name, handle);
            set_last_error(ERROR_SUCCESS);
            handle as *mut c_void
        }
        Err(ref e) => {
            trace!("LoadLibraryA(\"{}\") FAILED: {}", name, e);
            set_last_error(ERROR_MOD_NOT_FOUND);
            std::ptr::null_mut()
        }
    }
}

pub extern "win64" fn load_library_w(lp_lib_file_name: *const u16) -> *mut c_void {
    if lp_lib_file_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }
    let Some(name) = (unsafe { from_wide_ptr(lp_lib_file_name).ok() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    let c_name = CString::new(name).unwrap_or_else(|_| CString::new("").expect("empty cstr"));
    load_library_a(c_name.as_ptr())
}

pub extern "win64" fn load_library_ex_a(
    lp_lib_file_name: *const i8,
    _h_file: *mut c_void,
    _dw_flags: u32,
) -> *mut c_void {
    load_library_a(lp_lib_file_name)
}

pub extern "win64" fn load_library_ex_w(
    lp_lib_file_name: *const u16,
    _h_file: *mut c_void,
    _dw_flags: u32,
) -> *mut c_void {
    load_library_w(lp_lib_file_name)
}

pub extern "win64" fn get_proc_address(
    h_module: *mut c_void,
    lp_proc_name: *const i8,
) -> *mut c_void {
    if h_module.is_null() || lp_proc_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    // Ordinal form is MAKEINTRESOURCEA(ordinal) where pointer value is <= 0xFFFF.
    let proc_raw = lp_proc_name as usize;
    if proc_raw <= 0xFFFF {
        trace!("GetProcAddress(0x{:x}, ordinal#{}) -> NULL", h_module as usize, proc_raw);
        set_last_error(ERROR_PROC_NOT_FOUND);
        return std::ptr::null_mut();
    }

    let Ok(proc_name) = (unsafe { CStr::from_ptr(lp_proc_name).to_str() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    let handle = h_module as usize;
    match resolve_export(handle, proc_name) {
        Some(addr) => {
            trace!("GetProcAddress(0x{:x}, \"{}\") -> 0x{:x}", handle, proc_name, addr);
            set_last_error(ERROR_SUCCESS);
            addr as *mut c_void
        }
        None => {
            trace!("GetProcAddress(0x{:x}, \"{}\") -> NULL", handle, proc_name);
            tracing::warn!(
                module = format_args!("0x{handle:x}"),
                proc = %proc_name,
                "GetProcAddress returned NULL"
            );
            if handle == 0 {
                set_last_error(ERROR_INVALID_HANDLE);
            } else {
                set_last_error(ERROR_PROC_NOT_FOUND);
            }
            std::ptr::null_mut()
        }
    }
}

pub extern "win64" fn free_library_api(h_lib_module: *mut c_void) -> i32 {
    if h_lib_module.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    match free_library(h_lib_module as usize) {
        Ok(()) => {
            set_last_error(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

lazy_static::lazy_static! {
    static ref ENV_STRINGS_W: Vec<u16> = {
        let mut block: Vec<u16> = Vec::new();
        for (k, v) in std::env::vars() {
            let entry = format!("{k}={v}");
            block.extend(entry.encode_utf16());
            block.push(0);
        }
        // Environment block terminator is an extra trailing NUL.
        block.push(0);
        block
    };

    static ref ENV_STRINGS_A: Vec<u8> = {
        let mut block: Vec<u8> = Vec::new();
        for (k, v) in std::env::vars() {
            let entry = format!("{k}={v}");
            block.extend(entry.as_bytes());
            block.push(0);
        }
        // Environment block terminator is an extra trailing NUL.
        block.push(0);
        block
    };
}

pub extern "win64" fn get_command_line_a() -> *const i8 {
    trace!("GetCommandLineA()");
    ensure_guest_command_line_initialized();
    CMD_LINE_A_PTR.load(Ordering::Acquire) as *const i8
}

pub extern "win64" fn get_command_line_w() -> *const u16 {
    trace!("GetCommandLineW()");
    ensure_guest_command_line_initialized();
    CMD_LINE_W_PTR.load(Ordering::Acquire) as *const u16
}

pub extern "win64" fn get_environment_strings_w() -> *mut u16 {
    ENV_STRINGS_W.as_ptr() as *mut u16
}

pub extern "win64" fn free_environment_strings_w(_lpsz_environment_block: *mut u16) -> i32 {
    1
}

pub extern "win64" fn get_environment_strings_a() -> *mut i8 {
    ENV_STRINGS_A.as_ptr() as *mut i8
}

pub extern "win64" fn free_environment_strings_a(_lpsz_environment_block: *mut i8) -> i32 {
    1
}

pub extern "win64" fn get_startup_info_a(lp_startup_info: *mut u8) {
    trace!("GetStartupInfoA()");
    if !lp_startup_info.is_null() {
        unsafe {
            // STARTUPINFOA is at least 68 bytes
            std::ptr::write_bytes(lp_startup_info, 0, 68);
            // cb (size) is the firstDWORD
            *(lp_startup_info as *mut u32) = 68;
        }
    }
}

pub extern "win64" fn get_startup_info_w(lp_startup_info: *mut u8) {
    trace!("GetStartupInfoW()");
    if !lp_startup_info.is_null() {
        unsafe {
            // STARTUPINFOW is at least 68 bytes
            std::ptr::write_bytes(lp_startup_info, 0, 68);
            // cb (size) is the first DWORD
            *(lp_startup_info as *mut u32) = 68;
        }
    }
}

pub extern "win64" fn get_current_process_id() -> u32 {
    let pid = std::process::id();
    trace!("GetCurrentProcessId() -> {}", pid);
    pid
}

pub extern "win64" fn get_current_process() -> *mut c_void {
    CURRENT_PROCESS_PSEUDO_HANDLE as *mut c_void
}

pub extern "win64" fn terminate_process(h_process: *mut c_void, u_exit_code: u32) -> i32 {
    let bt = std::backtrace::Backtrace::force_capture();
    warn!(
        h_process = format_args!("0x{:x}", h_process as usize),
        u_exit_code = format_args!("0x{u_exit_code:x}"),
        backtrace = %bt,
        "TerminateProcess invoked"
    );

    if h_process as usize == CURRENT_PROCESS_PSEUDO_HANDLE {
        exit_process(u_exit_code);
    }

    set_last_error(ERROR_INVALID_HANDLE);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_exit_code_process(h_process: *mut c_void, lp_exit_code: *mut u32) -> i32 {
    if lp_exit_code.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if !h_process.is_null() && !is_current_process_handle(h_process) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    unsafe {
        *lp_exit_code = STILL_ACTIVE;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn get_current_thread_id() -> u32 {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    trace!("GetCurrentThreadId() -> {}", tid);
    tid
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_thread_times(
    h_thread: *mut c_void,
    lp_creation_time: *mut u64,
    lp_exit_time: *mut u64,
    lp_kernel_time: *mut u64,
    lp_user_time: *mut u64,
) -> i32 {
    if lp_creation_time.is_null()
        || lp_exit_time.is_null()
        || lp_kernel_time.is_null()
        || lp_user_time.is_null()
    {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let raw_handle = h_thread as usize as u32;
    let is_current_thread = raw_handle == CURRENT_THREAD_PSEUDO_HANDLE;
    let is_known_thread = crate::utils::handle::global_table()
        .with(raw_handle, |obj| obj.as_any().is::<crate::nt_kernel::thread::ThreadHandleObject>())
        .unwrap_or(false);

    if !is_current_thread && !is_known_thread {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let now_ft = current_filetime_value();
    unsafe {
        *lp_creation_time = now_ft;
        *lp_exit_time = 0;
        *lp_kernel_time = 0;
        *lp_user_time = 0;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn open_thread(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    dw_thread_id: u32,
) -> *mut c_void {
    if dw_thread_id == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    set_last_error(ERROR_SUCCESS);
    (CURRENT_THREAD_PSEUDO_HANDLE as usize) as *mut c_void
}

pub extern "win64" fn get_thread_priority(_h_thread: *mut c_void) -> i32 {
    set_last_error(ERROR_SUCCESS);
    0
}

pub extern "win64" fn set_thread_priority(_h_thread: *mut c_void, _n_priority: i32) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_process_affinity_mask(
    h_process: *mut c_void,
    lp_process_affinity_mask: *mut usize,
    lp_system_affinity_mask: *mut usize,
) -> i32 {
    if lp_process_affinity_mask.is_null() || lp_system_affinity_mask.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if !h_process.is_null() && !is_current_process_handle(h_process) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let mask = get_host_active_processor_mask();
    unsafe {
        *lp_process_affinity_mask = mask;
        *lp_system_affinity_mask = mask;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn duplicate_handle(
    _h_source_process_handle: *mut c_void,
    h_source_handle: *mut c_void,
    _h_target_process_handle: *mut c_void,
    lp_target_handle: *mut *mut c_void,
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _dw_options: u32,
) -> i32 {
    if lp_target_handle.is_null() || h_source_handle.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        *lp_target_handle = h_source_handle;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn free_library_and_exit_thread(h_lib_module: *mut c_void, dw_exit_code: u32) {
    let _ = free_library_api(h_lib_module);
    crate::nt_kernel::thread::exit_thread(dw_exit_code);
}

pub extern "win64" fn get_native_system_info(lp_system_info: *mut c_void) {
    write_system_info(lp_system_info);
    set_last_error(ERROR_SUCCESS);
}

pub extern "win64" fn get_system_info(lp_system_info: *mut c_void) {
    write_system_info(lp_system_info);
    set_last_error(ERROR_SUCCESS);
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_system_power_status(lp_system_power_status: *mut c_void) -> i32 {
    if lp_system_power_status.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let status = SystemPowerStatus {
        // Linux host should be treated as AC-powered by default.
        ac_line_status: 1,
        battery_flag: BATTERY_FLAG_NO_BATTERY,
        battery_life_percent: 255,
        system_status_flag: 0,
        battery_life_time: u32::MAX,
        battery_full_life_time: u32::MAX,
    };

    unsafe {
        std::ptr::write(lp_system_power_status.cast::<SystemPowerStatus>(), status);
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn k32_get_process_memory_info(
    h_process: *mut c_void,
    ppsmem_counters: *mut c_void,
    cb: u32,
) -> i32 {
    if ppsmem_counters.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let expected = std::mem::size_of::<ProcessMemoryCounters>();
    if (cb as usize) < expected {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if !h_process.is_null() && h_process as usize != CURRENT_PROCESS_PSEUDO_HANDLE {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let counters = ProcessMemoryCounters {
        cb: expected as u32,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };

    unsafe {
        std::ptr::write(ppsmem_counters.cast::<ProcessMemoryCounters>(), counters);
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn is_processor_feature_present(processor_feature: u32) -> u32 {
    trace!("IsProcessorFeaturePresent({})", processor_feature);
    // Hardcode common features (e.g., SSE2 = 10, etc.)
    match processor_feature {
        10 => 1, // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        _ => 0,
    }
}

pub extern "win64" fn is_debugger_present() -> u32 {
    trace!("IsDebuggerPresent() -> 0");
    0
}

pub extern "win64" fn rtl_capture_context(context_record: *mut c_void) {
    trace!("RtlCaptureContext({:#x})", context_record as usize);
    if context_record.is_null() {
        return;
    }

    // CONTEXT (x64) is 0x4d0 bytes on Windows.
    const CONTEXT_SIZE_X64: usize = 0x4d0;
    const OFF_CONTEXT_FLAGS: usize = 0x30;
    const OFF_RSP: usize = 0x98;
    const OFF_RBP: usize = 0xA0;
    const OFF_RIP: usize = 0xF8;
    const CONTEXT_AMD64: u32 = 0x0010_0000;
    const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x0000_0001;
    const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x0000_0002;
    const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER;

    unsafe {
        std::ptr::write_bytes(context_record.cast::<u8>(), 0, CONTEXT_SIZE_X64);
        *(context_record.cast::<u8>().add(OFF_CONTEXT_FLAGS).cast::<u32>()) = CONTEXT_FULL;

        #[cfg(target_arch = "x86_64")]
        {
            let mut rsp: u64;
            let mut rbp: u64;
            let mut rip: u64;
            std::arch::asm!(
                "mov {rsp_out}, rsp",
                "mov {rbp_out}, rbp",
                "lea {rip_out}, [rip]",
                rsp_out = out(reg) rsp,
                rbp_out = out(reg) rbp,
                rip_out = out(reg) rip,
                options(nostack, preserves_flags)
            );

            *(context_record.cast::<u8>().add(OFF_RSP).cast::<u64>()) = rsp;
            *(context_record.cast::<u8>().add(OFF_RBP).cast::<u64>()) = rbp;
            *(context_record.cast::<u8>().add(OFF_RIP).cast::<u64>()) = rip;
        }
    }
}

thread_local! {
    static LAST_LOOKUP_RUNTIME_FUNCTION: std::cell::RefCell<Option<RuntimeFunction>> =
        const { std::cell::RefCell::new(None) };
}

pub extern "win64" fn rtl_lookup_function_entry(
    control_pc: u64,
    image_base: *mut u64,
    _history_table: *mut c_void,
) -> *const c_void {
    trace!("RtlLookupFunctionEntry({:#x})", control_pc);

    let Some(found) = lookup_runtime_function(control_pc as usize) else {
        if !image_base.is_null() {
            unsafe {
                *image_base = 0;
            }
        }
        return std::ptr::null();
    };

    if !image_base.is_null() {
        unsafe {
            *image_base = found.image_base as u64;
        }
    }

    LAST_LOOKUP_RUNTIME_FUNCTION.with(|slot| {
        let mut storage = slot.borrow_mut();
        *storage = Some(found.function);
        storage
            .as_ref()
            .map(|entry| entry as *const RuntimeFunction as *const c_void)
            .unwrap_or(std::ptr::null())
    })
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn rtl_pc_to_file_header(
    pc_value: *const c_void,
    base_of_image: *mut *mut c_void,
) -> *mut c_void {
    let pc = pc_value as usize;
    trace!("RtlPcToFileHeader(pc={:#x})", pc);

    let resolved_base = lookup_runtime_function(pc)
        .map(|entry| entry.image_base)
        .or_else(|| crate::dll_manager::loader::module_base_for_address(pc))
        .or_else(|| {
            if main_image_contains(pc) {
                Some(unsafe { MAIN_IMAGE_BASE })
            } else {
                None
            }
        });

    if let Some(base) = resolved_base {
        if !base_of_image.is_null() {
            unsafe {
                *base_of_image = base as *mut c_void;
            }
        }
        return base as *mut c_void;
    }

    if !base_of_image.is_null() {
        unsafe {
            *base_of_image = std::ptr::null_mut();
        }
    }
    std::ptr::null_mut()
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn rtl_virtual_unwind(
    _handler_type: u32,
    _image_base: u64,
    _control_pc: u64,
    _function_entry: *const c_void,
    _context_record: *mut c_void,
    handler_data: *mut *mut c_void,
    establisher_frame: *mut u64,
    _context_pointers: *mut c_void,
) -> *mut c_void {
    trace!("RtlVirtualUnwind(...) ");
    if !handler_data.is_null() {
        unsafe {
            *handler_data = std::ptr::null_mut();
        }
    }
    if !establisher_frame.is_null() {
        unsafe {
            *establisher_frame = 0;
        }
    }
    std::ptr::null_mut()
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn rtl_unwind_ex(
    _target_frame: *mut c_void,
    _target_ip: *mut c_void,
    _exception_record: *mut c_void,
    _return_value: *mut c_void,
    _original_context: *mut c_void,
    _history_table: *mut c_void,
) {
    trace!("RtlUnwindEx(...)");
}

pub extern "win64" fn rtl_unwind(
    _target_frame: *mut c_void,
    _target_ip: *mut c_void,
    _exception_record: *mut c_void,
    _return_value: *mut c_void,
) {
    trace!("RtlUnwind(...)");
}

#[repr(C)]
struct ProcessInformation {
    h_process: *mut c_void,
    h_thread: *mut c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

pub extern "win64" fn get_process_id(_h_process: *mut c_void) -> u32 {
    get_current_process_id()
}

fn is_current_process_handle(handle: *mut c_void) -> bool {
    (handle as usize) == CURRENT_PROCESS_PSEUDO_HANDLE
}

fn get_host_active_processor_mask() -> usize {
    let cpu_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if cpu_count >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << cpu_count) - 1
    }
}

pub extern "win64" fn set_thread_affinity_mask(
    _h_thread: *mut c_void,
    dw_thread_affinity_mask: usize,
) -> usize {
    // We currently do not pin host threads for guest requests.
    // Return a plausible previous mask for compatibility.
    if dw_thread_affinity_mask == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let previous = get_host_active_processor_mask();
    set_last_error(ERROR_SUCCESS);
    previous
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn read_process_memory(
    h_process: *mut c_void,
    lp_base_address: *const c_void,
    lp_buffer: *mut c_void,
    n_size: usize,
    lp_number_of_bytes_read: *mut usize,
) -> i32 {
    if !is_current_process_handle(h_process) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    if lp_base_address.is_null() || lp_buffer.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(lp_base_address.cast::<u8>(), lp_buffer.cast::<u8>(), n_size);
        if !lp_number_of_bytes_read.is_null() {
            *lp_number_of_bytes_read = n_size;
        }
    }
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn write_process_memory(
    h_process: *mut c_void,
    lp_base_address: *mut c_void,
    lp_buffer: *const c_void,
    n_size: usize,
    lp_number_of_bytes_written: *mut usize,
) -> i32 {
    if !is_current_process_handle(h_process) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    if lp_base_address.is_null() || lp_buffer.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(lp_buffer.cast::<u8>(), lp_base_address.cast::<u8>(), n_size);
        if !lp_number_of_bytes_written.is_null() {
            *lp_number_of_bytes_written = n_size;
        }
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn get_error_mode() -> u32 {
    PROCESS_ERROR_MODE.load(Ordering::Acquire)
}

pub extern "win64" fn set_error_mode(new_mode: u32) -> u32 {
    PROCESS_ERROR_MODE.swap(new_mode, Ordering::AcqRel)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn set_thread_error_mode(new_mode: u32, old_mode: *mut u32) -> i32 {
    let previous = set_error_mode(new_mode);
    if !old_mode.is_null() {
        unsafe {
            *old_mode = previous;
        }
    }
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_current_directory_w(n_buffer_length: u32, lp_buffer: *mut u16) -> u32 {
    if lp_buffer.is_null() || n_buffer_length == 0 {
        return 0;
    }
    let cwd = std::env::current_dir().ok().unwrap_or_else(|| std::path::PathBuf::from("."));
    let wide: Vec<u16> = cwd.to_string_lossy().replace('/', "\\").encode_utf16().collect();
    if wide.len() + 1 > n_buffer_length as usize {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return (wide.len() + 1) as u32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_buffer, wide.len());
        *lp_buffer.add(wide.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    wide.len() as u32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_current_directory_a(n_buffer_length: u32, lp_buffer: *mut i8) -> u32 {
    if lp_buffer.is_null() || n_buffer_length == 0 {
        return 0;
    }
    let cwd = std::env::current_dir().ok().unwrap_or_else(|| std::path::PathBuf::from("."));
    let bytes = cwd.to_string_lossy().replace('/', "\\").into_bytes();
    if bytes.len() + 1 > n_buffer_length as usize {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return (bytes.len() + 1) as u32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer.cast::<u8>(), bytes.len());
        *lp_buffer.add(bytes.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    bytes.len() as u32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_environment_variable_w(
    lp_name: *const u16,
    lp_buffer: *mut u16,
    n_size: u32,
) -> u32 {
    let Some(name) = (unsafe { from_wide_ptr(lp_name).ok() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Ok(value) = std::env::var(name) else {
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    };
    let wide: Vec<u16> = value.encode_utf16().collect();
    if lp_buffer.is_null() || n_size == 0 {
        return (wide.len() + 1) as u32;
    }
    if wide.len() + 1 > n_size as usize {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return (wide.len() + 1) as u32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_buffer, wide.len());
        *lp_buffer.add(wide.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    wide.len() as u32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_environment_variable_a(
    lp_name: *const i8,
    lp_buffer: *mut i8,
    n_size: u32,
) -> u32 {
    if lp_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(lp_name).to_str() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Ok(value) = std::env::var(name) else {
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    };
    let bytes = value.as_bytes();
    if lp_buffer.is_null() || n_size == 0 {
        return (bytes.len() + 1) as u32;
    }
    if bytes.len() + 1 > n_size as usize {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return (bytes.len() + 1) as u32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer.cast::<u8>(), bytes.len());
        *lp_buffer.add(bytes.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    bytes.len() as u32
}

fn expand_environment_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == '%' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '%' {
                j += 1;
            }

            if j < chars.len() && j > i + 1 {
                let var_name: String = chars[i + 1..j].iter().collect();
                if let Ok(value) = std::env::var(&var_name) {
                    out.push_str(&value);
                } else {
                    out.push('%');
                    out.push_str(&var_name);
                    out.push('%');
                }
                i = j + 1;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn expand_environment_strings_w(
    lp_src: *const u16,
    lp_dst: *mut u16,
    n_size: u32,
) -> u32 {
    let Some(src) = (unsafe { from_wide_ptr(lp_src).ok() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let expanded = expand_environment_tokens(&src);
    let wide: Vec<u16> = expanded.encode_utf16().collect();
    let required = (wide.len() + 1) as u32;

    if lp_dst.is_null() || n_size == 0 {
        return required;
    }

    if required > n_size {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return required;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_dst, wide.len());
        *lp_dst.add(wide.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    required
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn expand_environment_strings_a(
    lp_src: *const i8,
    lp_dst: *mut i8,
    n_size: u32,
) -> u32 {
    if lp_src.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let Ok(src) = (unsafe { CStr::from_ptr(lp_src).to_str() }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let expanded = expand_environment_tokens(src);
    let bytes = expanded.as_bytes();
    let required = (bytes.len() + 1) as u32;

    if lp_dst.is_null() || n_size == 0 {
        return required;
    }

    if required > n_size {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return required;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_dst.cast::<u8>(), bytes.len());
        *lp_dst.add(bytes.len()) = 0;
    }
    set_last_error(ERROR_SUCCESS);
    required
}

pub extern "win64" fn encode_pointer(ptr: *mut c_void) -> *mut c_void {
    ptr
}

pub extern "win64" fn decode_pointer(ptr: *mut c_void) -> *mut c_void {
    ptr
}

pub extern "win64" fn switch_to_thread() -> i32 {
    std::thread::yield_now();
    1
}

pub extern "win64" fn sleep_ex(dw_milliseconds: u32, _b_alertable: i32) -> u32 {
    if dw_milliseconds != u32::MAX {
        std::thread::sleep(std::time::Duration::from_millis(dw_milliseconds as u64));
    }
    0
}

pub extern "win64" fn output_debug_string_a(_lp_output_string: *const i8) {}

pub extern "win64" fn debug_break() {}

pub extern "win64" fn set_dll_directory_w(_lp_path_name: *const u16) -> i32 {
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn get_computer_name_w(lp_buffer: *mut u16, n_size: *mut u32) -> i32 {
    if lp_buffer.is_null() || n_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let name: Vec<u16> = "tuxexe-host".encode_utf16().collect();
    let cap = unsafe { *n_size as usize };
    if cap <= name.len() {
        unsafe {
            *n_size = (name.len() + 1) as u32;
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), lp_buffer, name.len());
        *lp_buffer.add(name.len()) = 0;
        *n_size = name.len() as u32;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn initialize_proc_thread_attribute_list(
    lp_attribute_list: *mut c_void,
    _dw_attribute_count: u32,
    _dw_flags: u32,
    lp_size: *mut usize,
) -> i32 {
    if lp_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let required = 64usize;
    if lp_attribute_list.is_null() {
        unsafe {
            *lp_size = required;
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        std::ptr::write_bytes(lp_attribute_list.cast::<u8>(), 0, required.min(*lp_size));
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn delete_proc_thread_attribute_list(_lp_attribute_list: *mut c_void) {}

pub extern "win64" fn update_proc_thread_attribute(
    _lp_attribute_list: *mut c_void,
    _dw_flags: u32,
    _attribute: usize,
    _lp_value: *mut c_void,
    _cb_size: usize,
    _lp_previous_value: *mut c_void,
    _lp_return_size: *mut usize,
) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn create_process_w(
    _lp_application_name: *const u16,
    _lp_command_line: *mut u16,
    _lp_process_attributes: *mut c_void,
    _lp_thread_attributes: *mut c_void,
    _b_inherit_handles: i32,
    _dw_creation_flags: u32,
    _lp_environment: *mut c_void,
    _lp_current_directory: *const u16,
    _lp_startup_info: *mut c_void,
    lp_process_information: *mut c_void,
) -> i32 {
    if lp_process_information.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let info = lp_process_information.cast::<ProcessInformation>();
    unsafe {
        (*info).h_process = std::ptr::null_mut();
        (*info).h_thread = std::ptr::null_mut();
        (*info).dw_process_id = 0;
        (*info).dw_thread_id = 0;
    }
    set_last_error(2); // ERROR_FILE_NOT_FOUND
    0
}

pub extern "win64" fn create_toolhelp32_snapshot(
    dw_flags: u32,
    _th32_process_id: u32,
) -> *mut c_void {
    let allowed = TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    if (dw_flags & allowed) == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE as usize as *mut c_void;
    }

    init_global_table();
    let handle = global_table().alloc(Box::new(ToolhelpSnapshot {
        process_consumed: AtomicBool::new(false),
        thread_consumed: AtomicBool::new(false),
        module_index: AtomicU32::new(0),
        module_count: 0,
        include_modules: (dw_flags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)) != 0,
    }));
    set_last_error(ERROR_SUCCESS);
    handle as usize as *mut c_void
}

fn with_toolhelp_snapshot<F>(snapshot: *mut c_void, f: F) -> bool
where
    F: FnOnce(&ToolhelpSnapshot),
{
    if snapshot.is_null() || snapshot as usize == INVALID_HANDLE_VALUE as usize {
        return false;
    }

    let handle = snapshot as Handle;
    global_table()
        .with(handle, |obj| obj.as_any().downcast_ref::<ToolhelpSnapshot>().map(f).is_some())
        .unwrap_or(false)
}

pub extern "win64" fn module32_first_w(
    h_snapshot: *mut c_void,
    lpme: *mut ModuleEntry32W,
) -> i32 {
    if lpme.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let snapshot_handle = h_snapshot as Handle;
    let include_modules = global_table()
        .with(snapshot_handle, |obj| {
            obj.as_any().downcast_ref::<ToolhelpSnapshot>().map(|snapshot| {
                snapshot.module_index.store(1, Ordering::SeqCst);
                snapshot.include_modules
            })
        })
        .flatten();

    let Some(true) = include_modules else {
        set_last_error(if include_modules.is_none() {
            ERROR_INVALID_HANDLE
        } else {
            ERROR_NO_MORE_FILES
        });
        return 0;
    };

    unsafe {
        (*lpme).dwSize = std::mem::size_of::<ModuleEntry32W>() as u32;
    }

    // Get loaded modules from DLL manager
    let modules = get_loaded_module_list();
    if modules.is_empty() {
        set_last_error(ERROR_NO_MORE_FILES);
        return 0;
    }

    fill_module_entry_w(lpme, &modules[0]);
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn module32_next_w(
    h_snapshot: *mut c_void,
    lpme: *mut ModuleEntry32W,
) -> i32 {
    if lpme.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let modules = get_loaded_module_list();
    let idx = {
        let snapshot_handle = h_snapshot as Handle;
        global_table()
            .with(snapshot_handle, |obj| {
                obj.as_any().downcast_ref::<ToolhelpSnapshot>().and_then(|s| {
                    if !s.include_modules {
                        return None;
                    }
                    Some(s.module_index.fetch_add(1, Ordering::SeqCst))
                })
            })
            .flatten()
    };

    let Some(idx) = idx else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };

    if idx >= modules.len() as u32 {
        set_last_error(ERROR_NO_MORE_FILES);
        return 0;
    }

    fill_module_entry_w(lpme, &modules[idx as usize]);
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn module32_first_a(
    h_snapshot: *mut c_void,
    lpme: *mut ModuleEntry32A,
) -> i32 {
    if lpme.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let snapshot_handle = h_snapshot as Handle;
    let include_modules = global_table()
        .with(snapshot_handle, |obj| {
            obj.as_any().downcast_ref::<ToolhelpSnapshot>().map(|snapshot| {
                snapshot.module_index.store(1, Ordering::SeqCst);
                snapshot.include_modules
            })
        })
        .flatten();

    let Some(true) = include_modules else {
        set_last_error(if include_modules.is_none() {
            ERROR_INVALID_HANDLE
        } else {
            ERROR_NO_MORE_FILES
        });
        return 0;
    };

    unsafe {
        (*lpme).dwSize = std::mem::size_of::<ModuleEntry32A>() as u32;
    }

    let modules = get_loaded_module_list();
    if modules.is_empty() {
        set_last_error(ERROR_NO_MORE_FILES);
        return 0;
    }

    fill_module_entry_a(lpme, &modules[0]);
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn module32_next_a(
    h_snapshot: *mut c_void,
    lpme: *mut ModuleEntry32A,
) -> i32 {
    if lpme.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let modules = get_loaded_module_list();
    let idx = {
        let snapshot_handle = h_snapshot as Handle;
        global_table()
            .with(snapshot_handle, |obj| {
                obj.as_any().downcast_ref::<ToolhelpSnapshot>().and_then(|s| {
                    if !s.include_modules {
                        return None;
                    }
                    Some(s.module_index.fetch_add(1, Ordering::SeqCst))
                })
            })
            .flatten()
    };

    let Some(idx) = idx else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };

    if idx >= modules.len() as u32 {
        set_last_error(ERROR_NO_MORE_FILES);
        return 0;
    }

    fill_module_entry_a(lpme, &modules[idx as usize]);
    set_last_error(ERROR_SUCCESS);
    1
}

fn fill_module_entry_w(entry: *mut ModuleEntry32W, module_info: &LoadedModuleInfo) {
    unsafe {
        (*entry).dwSize = std::mem::size_of::<ModuleEntry32W>() as u32;
        (*entry).th32ModuleID = module_info.id;
        (*entry).th32ProcessID = std::process::id();
        (*entry).GlblcntUsage = 1;
        (*entry).ProccntUsage = 1;
        (*entry).modBaseAddr = module_info.base as *mut u8;
        (*entry).modBaseSize = module_info.size as u32;
        (*entry).hModule = module_info.handle;

        // Module name
        let name_wide: Vec<u16> = module_info.name.encode_utf16().take(255).collect();
        (*entry).szModule.fill(0);
        for (i, ch) in name_wide.iter().enumerate() {
            (*entry).szModule[i] = *ch;
        }

        // Exe path
        let path_wide: Vec<u16> = module_info.path.encode_utf16().take(259).collect();
        (*entry).szExePath.fill(0);
        for (i, ch) in path_wide.iter().enumerate() {
            (*entry).szExePath[i] = *ch;
        }
    }
}

fn fill_module_entry_a(entry: *mut ModuleEntry32A, module_info: &LoadedModuleInfo) {
    unsafe {
        (*entry).dwSize = std::mem::size_of::<ModuleEntry32A>() as u32;
        (*entry).th32ModuleID = module_info.id;
        (*entry).th32ProcessID = std::process::id();
        (*entry).GlblcntUsage = 1;
        (*entry).ProccntUsage = 1;
        (*entry).modBaseAddr = module_info.base as *mut u8;
        (*entry).modBaseSize = module_info.size as u32;
        (*entry).hModule = module_info.handle;

        let name = module_info.name.as_bytes();
        (*entry).szModule.fill(0);
        for (i, ch) in name.iter().copied().enumerate().take(255) {
            (*entry).szModule[i] = ch;
        }

        let path = module_info.path.as_bytes();
        (*entry).szExePath.fill(0);
        for (i, ch) in path.iter().copied().enumerate().take(259) {
            (*entry).szExePath[i] = ch;
        }
    }
}

#[derive(Clone)]
struct LoadedModuleInfo {
    id: u32,
    name: String,
    path: String,
    base: usize,
    size: usize,
    handle: usize,
}

fn get_loaded_module_list() -> Vec<LoadedModuleInfo> {
    let mut modules = Vec::new();
    let mut id_counter = 1u32;

    // Add main executable
    if let Ok(exe_path) = std::env::current_exe() {
        modules.push(LoadedModuleInfo {
            id: id_counter,
            name: exe_path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
            path: exe_path.to_string_lossy().to_string(),
            base: 0x140000000, // Typical main exe base
            size: 0x100000,
            handle: 0,
        });
        id_counter += 1;
    }

    // Add loaded DLLs
    if let Ok(registry) = crate::dll_manager::loader::registry().read() {
        for (name, module) in registry.iter() {
            modules.push(LoadedModuleInfo {
                id: id_counter,
                name: name.clone(),
                path: match &module.source {
                    crate::dll_manager::ModuleSource::Native(native) => native.path.to_string_lossy().to_string(),
                    _ => format!("C:\\Windows\\System32\\{}", name),
                },
                base: module.handle,
                size: 0x1000000,
                handle: module.handle,
            });
            id_counter += 1;
        }
    }

    modules
}

fn fill_process_entry_w(entry: &mut ProcessEntry32W) {
    let exe_name = std::path::Path::new(
        main_image_path_store().read().expect("main image path lock poisoned").as_str(),
    )
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("tuxexe.exe")
    .to_string();

    entry.cnt_usage = 1;
    entry.th32_process_id = std::process::id();
    entry.th32_default_heap_id = 0;
    entry.th32_module_id = 0;
    entry.cnt_threads = 1;
    entry.th32_parent_process_id = 0;
    entry.pc_pri_class_base = 8;
    entry.dw_flags = 0;
    entry.sz_exe_file.fill(0);
    for (idx, ch) in
        exe_name.encode_utf16().take(entry.sz_exe_file.len().saturating_sub(1)).enumerate()
    {
        entry.sz_exe_file[idx] = ch;
    }
}

fn fill_process_entry_a(entry: &mut ProcessEntry32A) {
    let exe_name = std::path::Path::new(
        main_image_path_store().read().expect("main image path lock poisoned").as_str(),
    )
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("tuxexe.exe")
    .to_string();

    entry.cnt_usage = 1;
    entry.th32_process_id = std::process::id();
    entry.th32_default_heap_id = 0;
    entry.th32_module_id = 0;
    entry.cnt_threads = 1;
    entry.th32_parent_process_id = 0;
    entry.pc_pri_class_base = 8;
    entry.dw_flags = 0;
    entry.sz_exe_file.fill(0);
    for (idx, b) in
        exe_name.as_bytes().iter().take(entry.sz_exe_file.len().saturating_sub(1)).enumerate()
    {
        entry.sz_exe_file[idx] = *b as i8;
    }
}

pub extern "win64" fn process32_first_w(h_snapshot: *mut c_void, lppe: *mut c_void) -> i32 {
    if lppe.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let ok = with_toolhelp_snapshot(h_snapshot, |snapshot| {
        snapshot.process_consumed.store(true, Ordering::Release);
        let entry = unsafe { &mut *lppe.cast::<ProcessEntry32W>() };
        fill_process_entry_w(entry);
    });

    if !ok {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn process32_next_w(h_snapshot: *mut c_void, _lppe: *mut c_void) -> i32 {
    let ok = with_toolhelp_snapshot(h_snapshot, |snapshot| {
        let _ = snapshot.process_consumed.load(Ordering::Acquire);
    });

    if !ok {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    set_last_error(ERROR_NO_MORE_FILES);
    0
}

pub extern "win64" fn process32_first_a(h_snapshot: *mut c_void, lppe: *mut c_void) -> i32 {
    if lppe.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let ok = with_toolhelp_snapshot(h_snapshot, |snapshot| {
        snapshot.process_consumed.store(true, Ordering::Release);
        let entry = unsafe { &mut *lppe.cast::<ProcessEntry32A>() };
        fill_process_entry_a(entry);
    });

    if !ok {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn process32_next_a(h_snapshot: *mut c_void, _lppe: *mut c_void) -> i32 {
    let ok = with_toolhelp_snapshot(h_snapshot, |snapshot| {
        let _ = snapshot.process_consumed.load(Ordering::Acquire);
    });

    if !ok {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    set_last_error(ERROR_NO_MORE_FILES);
    0
}

fn fill_thread_entry(entry: &mut ThreadEntry32) {
    entry.cnt_usage = 0;
    entry.th32_thread_id = get_current_thread_id();
    entry.th32_owner_process_id = std::process::id();
    entry.tp_base_pri = 8;
    entry.tp_delta_pri = 0;
    entry.dw_flags = 0;
}

pub extern "win64" fn thread32_first(h_snapshot: *mut c_void, lpte: *mut c_void) -> i32 {
    if lpte.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let ok = with_toolhelp_snapshot(h_snapshot, |snapshot| {
        snapshot.thread_consumed.store(true, Ordering::Release);
        let entry = unsafe { &mut *lpte.cast::<ThreadEntry32>() };
        fill_thread_entry(entry);
    });

    if !ok {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn thread32_next(h_snapshot: *mut c_void, _lpte: *mut c_void) -> i32 {
    let ok = with_toolhelp_snapshot(h_snapshot, |snapshot| {
        let _ = snapshot.thread_consumed.load(Ordering::Acquire);
    });

    if !ok {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    set_last_error(ERROR_NO_MORE_FILES);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_manager::loader::reset_registry_for_tests;
    use crate::utils::wide_string::to_wide_null;

    #[test]
    fn load_library_a_and_get_module_handle_a_work_for_reimplemented_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let name = CString::new("kernel32.dll").expect("cstring");
        let handle = load_library_a(name.as_ptr());
        assert!(!handle.is_null());

        let queried = get_module_handle_a(name.as_ptr());
        assert_eq!(queried, handle);
    }

    #[test]
    fn get_module_handle_ex_w_returns_handle() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let wide = to_wide_null("kernel32.dll");
        let loaded = load_library_w(wide.as_ptr());
        assert!(!loaded.is_null());

        let mut out: *mut c_void = std::ptr::null_mut();
        assert_eq!(get_module_handle_ex_w(0, wide.as_ptr(), &raw mut out), 1);
        assert_eq!(out, loaded);
    }

    #[test]
    fn load_library_w_and_get_module_handle_w_work_for_reimplemented_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let wide = to_wide_null("msvcrt.dll");
        let handle = load_library_w(wide.as_ptr());
        assert!(!handle.is_null());

        let queried = get_module_handle_w(wide.as_ptr());
        assert_eq!(queried, handle);
    }

    #[test]
    fn load_library_ex_variants_work_for_reimplemented_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();

        let name_a = CString::new("kernel32.dll").expect("name a");
        let h_a = load_library_ex_a(name_a.as_ptr(), std::ptr::null_mut(), 0);
        assert!(!h_a.is_null());

        let name_w = to_wide_null("msvcrt.dll");
        let h_w = load_library_ex_w(name_w.as_ptr(), std::ptr::null_mut(), 0);
        assert!(!h_w.is_null());
    }

    #[test]
    fn environment_strings_w_are_double_null_terminated() {
        let block = get_environment_strings_w();
        assert!(!block.is_null());

        let mut i = 0usize;
        let mut saw_separator = false;
        loop {
            let ch = unsafe { *block.add(i) };
            let next = unsafe { *block.add(i + 1) };
            if ch == 0 {
                if next == 0 {
                    break;
                }
                saw_separator = true;
            }
            i += 1;
            assert!(i < 1_000_000, "environment block missing double NUL terminator");
        }

        assert!(saw_separator || unsafe { *block } == 0);
        assert_eq!(free_environment_strings_w(block), 1);
    }

    #[test]
    fn expand_environment_strings_w_expands_percent_tokens() {
        let _guard = crate::test_support::serial_guard();
        std::env::set_var("TUXEXE_EXPAND_TEST", "value42");

        let src = to_wide_null("%TUXEXE_EXPAND_TEST%\\tail");
        let mut dst = vec![0u16; 64];
        let copied = expand_environment_strings_w(src.as_ptr(), dst.as_mut_ptr(), dst.len() as u32);
        assert!(copied > 0);

        let out = unsafe { from_wide_ptr(dst.as_ptr()).expect("expanded wide string") };
        assert_eq!(out, "value42\\tail");
    }

    #[test]
    fn expand_environment_strings_a_reports_required_size() {
        let _guard = crate::test_support::serial_guard();
        std::env::set_var("TUXEXE_EXPAND_TEST_A", "abc");

        let src = CString::new("%TUXEXE_EXPAND_TEST_A%/x").expect("src");
        let required = expand_environment_strings_a(src.as_ptr(), std::ptr::null_mut(), 0);
        assert_eq!(required, 6);
    }

    #[test]
    fn get_module_file_name_w_returns_main_image_path_for_null_module() {
        let mut buffer = vec![0u16; 1024];
        let len =
            get_module_file_name_w(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32);
        assert!(len > 0);
        let value = unsafe { from_wide_ptr(buffer.as_ptr()).expect("valid wide") };
        assert!(!value.is_empty());
    }

    #[test]
    fn get_module_file_name_w_truncates_and_sets_last_error() {
        let mut buffer = vec![0u16; 4];
        let len =
            get_module_file_name_w(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32);
        assert_eq!(len, buffer.len() as u32);
        assert_eq!(super::super::error::get_last_error(), ERROR_INSUFFICIENT_BUFFER);
        assert_eq!(buffer[buffer.len() - 1], 0);
    }

    #[test]
    fn get_module_file_name_a_returns_path_for_null_module() {
        let mut buffer = vec![0_i8; 512];
        let len =
            get_module_file_name_a(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32);
        assert!(len > 0);
        let value = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy().to_string();
        assert!(!value.is_empty());
    }

    #[test]
    fn guest_command_line_reflects_target_exe_and_args() {
        let _guard = crate::test_support::serial_guard();
        let fake_exe = Path::new("/tmp/Game Folder/game.exe");
        let args = vec!["-windowed".to_string(), "arg with space".to_string()];

        set_guest_command_line(fake_exe, &args);

        let cmd_a = unsafe { CStr::from_ptr(get_command_line_a()) }.to_string_lossy().to_string();
        assert!(cmd_a.contains("game.exe"));
        assert!(cmd_a.contains("Game Folder"));
        assert!(cmd_a.contains("-windowed"));
        assert!(cmd_a.contains("\"arg with space\""));

        let cmd_w = unsafe { from_wide_ptr(get_command_line_w()).expect("wide command line") };
        assert_eq!(cmd_w, cmd_a);
    }

    #[test]
    fn get_proc_address_resolves_reimplemented_export() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let dll = CString::new("kernel32.dll").expect("dll");
        let proc = CString::new("LoadLibraryA").expect("proc");
        let module = load_library_a(dll.as_ptr());
        assert!(!module.is_null());

        let fn_ptr = get_proc_address(module, proc.as_ptr());
        assert!(!fn_ptr.is_null());
    }

    #[test]
    fn get_proc_address_resolves_get_environment_strings_w() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let dll = CString::new("kernel32.dll").expect("dll");
        let proc = CString::new("GetEnvironmentStringsW").expect("proc");
        let module = load_library_a(dll.as_ptr());
        assert!(!module.is_null());

        let fn_ptr = get_proc_address(module, proc.as_ptr());
        assert!(!fn_ptr.is_null());
    }

    #[test]
    fn free_library_unloads_after_last_reference() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let dll = CString::new("kernel32.dll").expect("dll");
        let m1 = load_library_a(dll.as_ptr());
        let m2 = load_library_a(dll.as_ptr());
        assert_eq!(m1, m2);

        assert_eq!(free_library_api(m1), 1);
        assert!(!get_module_handle_a(dll.as_ptr()).is_null());

        assert_eq!(free_library_api(m1), 1);
        assert!(get_module_handle_a(dll.as_ptr()).is_null());
    }

    #[test]
    fn rtl_capture_context_sets_flags() {
        let mut context = [0_u8; 0x4d0];
        rtl_capture_context(context.as_mut_ptr().cast::<c_void>());
        let flags = u32::from_ne_bytes(context[0x30..0x34].try_into().expect("flags slice"));
        assert_ne!(flags, 0);
    }

    #[test]
    fn rtl_virtual_unwind_clears_out_params() {
        let mut handler_data = 0x1usize as *mut c_void;
        let mut frame = 0xFFFF_u64;
        let result = rtl_virtual_unwind(
            0,
            0,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut handler_data,
            &mut frame,
            std::ptr::null_mut(),
        );
        assert!(result.is_null());
        assert!(handler_data.is_null());
        assert_eq!(frame, 0);
    }

    #[test]
    fn is_debugger_present_returns_false() {
        assert_eq!(is_debugger_present(), 0);
    }

    #[test]
    fn get_current_process_returns_pseudo_handle() {
        assert_eq!(get_current_process() as usize, CURRENT_PROCESS_PSEUDO_HANDLE);
    }

    #[test]
    fn terminate_process_rejects_non_current_handle() {
        let ok = terminate_process(1usize as *mut c_void, 0);
        assert_eq!(ok, 0);
        assert_eq!(super::super::error::get_last_error(), ERROR_INVALID_HANDLE);
    }

    #[test]
    fn get_system_power_status_returns_stubbed_ac_values() {
        let mut status = SystemPowerStatus {
            ac_line_status: 0,
            battery_flag: 0,
            battery_life_percent: 0,
            system_status_flag: 0,
            battery_life_time: 0,
            battery_full_life_time: 0,
        };

        assert_eq!(get_system_power_status((&mut status as *mut SystemPowerStatus).cast()), 1);
        assert_eq!(status.ac_line_status, 1);
        assert_eq!(status.battery_flag, BATTERY_FLAG_NO_BATTERY);
    }

    #[test]
    fn k32_get_process_memory_info_accepts_current_process() {
        let mut counters = ProcessMemoryCounters {
            cb: 0,
            page_fault_count: 0,
            peak_working_set_size: 0,
            working_set_size: 0,
            quota_peak_paged_pool_usage: 0,
            quota_paged_pool_usage: 0,
            quota_peak_non_paged_pool_usage: 0,
            quota_non_paged_pool_usage: 0,
            pagefile_usage: 0,
            peak_pagefile_usage: 0,
        };

        assert_eq!(
            k32_get_process_memory_info(
                get_current_process(),
                (&mut counters as *mut ProcessMemoryCounters).cast::<c_void>(),
                std::mem::size_of::<ProcessMemoryCounters>() as u32
            ),
            1
        );
        assert_eq!(counters.cb as usize, std::mem::size_of::<ProcessMemoryCounters>());
    }

    #[test]
    fn toolhelp_process_snapshot_roundtrip() {
        let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
        assert_ne!(snapshot as usize, INVALID_HANDLE_VALUE as usize);

        let mut entry = ProcessEntry32W {
            dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0; 260],
        };

        assert_eq!(process32_first_w(snapshot, (&mut entry as *mut ProcessEntry32W).cast()), 1);
        assert_ne!(entry.th32_process_id, 0);
        assert_eq!(process32_next_w(snapshot, (&mut entry as *mut ProcessEntry32W).cast()), 0);
    }

    #[test]
    fn rtl_unwind_calls_are_safe_noops() {
        rtl_unwind_ex(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        rtl_unwind(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

// ─── Additional kernel32 stubs for Unity initialization ───

pub extern "win64" fn init_once_execute_once(
    _pInitOnce: *mut c_void,
    _pCallback: *mut c_void,
    _pContext: *mut c_void,
    _lpParameter: *mut *mut c_void,
) -> i32 {
    trace!("InitOnceExecuteOnce — stub");
    1
}

pub extern "win64" fn get_current_processor_number() -> u32 {
    trace!("GetCurrentProcessorNumber — stub");
    0
}

pub extern "win64" fn get_system_time_precise_as_file_time(lp_file_time: *mut u8) {
    trace!("GetSystemTimePreciseAsFileTime — stub");
    if !lp_file_time.is_null() {
        // FILETIME: 100-nanosecond intervals since January 1, 1601
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let filetime = 116444736000000000u64 + (now.as_nanos() / 100) as u64;
        unsafe {
            std::ptr::write_unaligned(lp_file_time as *mut u64, filetime);
        }
    }
}

pub extern "win64" fn get_locale_info_ex(
    _lpLocaleName: *const u16,
    _LCType: u32,
    _lpLCData: *mut u16,
    _cchData: i32,
) -> i32 {
    trace!("GetLocaleInfoEx — stub");
    0
}

pub extern "win64" fn compare_string_ex(
    _lpLocaleName: *const u16,
    _dwCmpFlags: u32,
    _lpString1: *const u16,
    _cchCount1: i32,
    _lpString2: *const u16,
    _cchCount2: i32,
    _lpVersionInformation: *mut c_void,
) -> i32 {
    trace!("CompareStringEx — stub");
    2 // CSTR_EQUAL
}

pub extern "win64" fn lc_map_string_ex(
    _lpLocaleName: *const u16,
    _dwMapFlags: u32,
    _lpSrcStr: *const u16,
    _cchSrc: i32,
    _lpDestStr: *mut u16,
    _cchDest: i32,
    _lpVersionInformation: *mut c_void,
    _lpReserved: *mut c_void,
    _sortHandle: usize,
) -> i32 {
    trace!("LCMapStringEx — stub");
    0
}

pub extern "win64" fn are_file_apis_ansi() -> i32 {
    trace!("AreFileApisANSI — stub");
    1
}

pub extern "win64" fn set_thread_description(
    _hThread: usize,
    _lpThreadDescription: *const u16,
) -> i32 {
    trace!("SetThreadDescription — stub");
    0
}

pub extern "win64" fn flush_process_write_buffers() {
    trace!("FlushProcessWriteBuffers — stub");
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

pub extern "win64" fn get_current_package_id(
    _buffer_length: *mut u32,
    _buffer: *mut u8,
) -> i32 {
    trace!("GetCurrentPackageId — stub (APPMODEL_ERROR_NO_PACKAGE)");
    15700 // APPMODEL_ERROR_NO_PACKAGE
}

pub extern "win64" fn create_symbolic_link_w(
    _lpSymlinkFileName: *const u16,
    _lpTargetFileName: *const u16,
    _dwFlags: u32,
) -> i32 {
    trace!("CreateSymbolicLinkW — stub");
    0
}

pub extern "win64" fn get_file_information_by_handle_ex(
    _hFile: usize,
    _FileInformationClass: u32,
    _lpFileInformation: *mut c_void,
    _dwBufferSize: u32,
) -> i32 {
    trace!("GetFileInformationByHandleEx — stub");
    0
}

pub extern "win64" fn set_file_information_by_handle(
    _hFile: usize,
    _FileInformationClass: u32,
    _lpFileInformation: *mut c_void,
    _dwBufferSize: u32,
) -> i32 {
    trace!("SetFileInformationByHandle — stub");
    0
}

// ─── Thread Pool Implementation ───

#[derive(Debug)]
struct ThreadPoolTimer {
    cancelled: std::sync::atomic::AtomicBool,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl HandleObject for ThreadPoolTimer {
    fn type_name(&self) -> &'static str {
        "ThreadPoolTimer"
    }
    fn close(&mut self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug)]
struct ThreadPoolWait {
    cancelled: std::sync::atomic::AtomicBool,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl HandleObject for ThreadPoolWait {
    fn type_name(&self) -> &'static str {
        "ThreadPoolWait"
    }
    fn close(&mut self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug)]
struct ThreadPoolWork {
    submitted: std::sync::atomic::AtomicBool,
}

impl HandleObject for ThreadPoolWork {
    fn type_name(&self) -> &'static str {
        "ThreadPoolWork"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub extern "win64" fn create_threadpool_timer(
    callback: *mut c_void,
) -> *mut c_void {
    trace!("CreateThreadpoolTimer — implementation");
    if callback.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }
    
    init_global_table();
    let handle = global_table().alloc(Box::new(ThreadPoolTimer {
        cancelled: std::sync::atomic::AtomicBool::new(false),
        join_handle: None,
    }));
    set_last_error(ERROR_SUCCESS);
    handle as usize as *mut c_void
}

pub extern "win64" fn set_threadpool_timer(
    timer: *mut c_void,
    pft_due_time: *mut i64,
    ms_period: u32,
    ms_window_length: u32,
) -> i32 {
    trace!("SetThreadpoolTimer — implementation");
    if timer.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    
    let timer_handle = timer as Handle;
    let callback_ptr = 0usize; // Would need to store this
    
    // Cancel existing timer
    global_table().with(timer_handle, |obj| {
        if let Some(tp_timer) = obj.as_any().downcast_ref::<ThreadPoolTimer>() {
            tp_timer.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    
    // Due time in 100-ns intervals (negative = relative)
    let due_time_100ns = if pft_due_time.is_null() { 0 } else {
        unsafe { *pft_due_time }
    };
    
    // Convert to milliseconds
    let due_time_ms = if due_time_100ns < 0 {
        ((-due_time_100ns) / 10000) as u64
    } else {
        // Absolute time - treat as relative for now
        0
    };
    
    let period = ms_period;
    let cancelled = global_table().with(timer_handle, |obj| {
        obj.as_any().downcast_ref::<ThreadPoolTimer>().map(|t| &t.cancelled as *const _)
    }).flatten();
    
    if let Some(cancelled_ptr) = cancelled {
        let cancelled: &std::sync::atomic::AtomicBool = unsafe { &*cancelled_ptr };
        cancelled.store(false, std::sync::atomic::Ordering::SeqCst);
        // Spawn timer thread
        let handle = std::thread::Builder::new()
            .name("threadpool-timer".to_string())
            .spawn(move || {
                if due_time_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(due_time_ms));
                }
                // Would call callback here
            })
            .ok();
        
        // Store the join handle - we'll use a separate mechanism since we can't mutably borrow
        // For now, the timer thread will run to completion or check the cancelled flag
    }
    
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn wait_for_threadpool_timer_callbacks(
    timer: *mut c_void,
    f_cancel_pending_callbacks: i32,
) {
    trace!("WaitForThreadpoolTimerCallbacks — implementation");
    if timer.is_null() {
        return;
    }
    
    let timer_handle = timer as Handle;
    global_table().with(timer_handle, |obj| {
        if let Some(tp_timer) = obj.as_any().downcast_ref::<ThreadPoolTimer>() {
            tp_timer.cancelled.store(f_cancel_pending_callbacks != 0, std::sync::atomic::Ordering::SeqCst);
        }
    });
}

pub extern "win64" fn close_threadpool_timer(
    timer: *mut c_void,
) {
    trace!("CloseThreadpoolTimer — implementation");
    if timer.is_null() {
        return;
    }
    
    let timer_handle = timer as Handle;
    global_table().with(timer_handle, |obj| {
        if let Some(tp_timer) = obj.as_any().downcast_ref::<ThreadPoolTimer>() {
            tp_timer.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    
    global_table().close_handle(timer_handle);
}

pub extern "win64" fn create_threadpool_wait(
    callback: *mut c_void,
) -> *mut c_void {
    trace!("CreateThreadpoolWait — implementation");
    
    init_global_table();
    let handle = global_table().alloc(Box::new(ThreadPoolWait {
        cancelled: std::sync::atomic::AtomicBool::new(false),
        join_handle: None,
    }));
    set_last_error(ERROR_SUCCESS);
    handle as usize as *mut c_void
}

pub extern "win64" fn set_threadpool_wait(
    wait: *mut c_void,
    handle_to_wait: usize,
    pft_timeout: *mut i64,
) -> i32 {
    trace!("SetThreadpoolWait — implementation");
    if wait.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    
    let wait_handle = wait as Handle;
    
    // Cancel existing wait
    global_table().with(wait_handle, |obj| {
        if let Some(tp_wait) = obj.as_any().downcast_ref::<ThreadPoolWait>() {
            tp_wait.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    
    // For now, just succeed - in reality we'd set up a wait on the handle
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn close_threadpool_wait(
    wait: *mut c_void,
) {
    trace!("CloseThreadpoolWait — implementation");
    if wait.is_null() {
        return;
    }
    
    let wait_handle = wait as Handle;
    global_table().with(wait_handle, |obj| {
        if let Some(tp_wait) = obj.as_any().downcast_ref::<ThreadPoolWait>() {
            tp_wait.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    
    global_table().close_handle(wait_handle);
}

pub extern "win64" fn create_threadpool_work(
    callback: *mut c_void,
) -> *mut c_void {
    trace!("CreateThreadpoolWork — implementation");
    
    init_global_table();
    let handle = global_table().alloc(Box::new(ThreadPoolWork {
        submitted: std::sync::atomic::AtomicBool::new(false),
    }));
    set_last_error(ERROR_SUCCESS);
    handle as usize as *mut c_void
}

pub extern "win64" fn submit_threadpool_work(
    work: *mut c_void,
) {
    trace!("SubmitThreadpoolWork — implementation");
    if work.is_null() {
        return;
    }
    
    let work_handle = work as Handle;
    global_table().with(work_handle, |obj| {
        if let Some(tp_work) = obj.as_any().downcast_ref::<ThreadPoolWork>() {
            tp_work.submitted.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
}

pub extern "win64" fn close_threadpool_work(
    work: *mut c_void,
) {
    trace!("CloseThreadpoolWork — implementation");
    if work.is_null() {
        return;
    }
    
    let work_handle = work as Handle;
    global_table().close_handle(work_handle);
}

pub extern "win64" fn free_library_when_callback_returns(
    pcbk: *mut c_void,
    h_module: usize,
) -> i32 {
    trace!("FreeLibraryWhenCallbackReturns — stub");
    0
}

// SRW Lock and Condition Variable stubs
pub extern "win64" fn initialize_srw_lock(srw_lock: *mut c_void) {
    trace!("InitializeSRWLock — stub");
    if !srw_lock.is_null() {
        unsafe {
            std::ptr::write_bytes(srw_lock, 0, std::mem::size_of::<usize>());
        }
    }
}

pub extern "win64" fn try_acquire_srw_lock_exclusive(
    _srw_lock: *mut c_void,
) -> i32 {
    trace!("TryAcquireSRWLockExclusive — stub");
    0
}

pub extern "win64" fn initialize_condition_variable(
    cond_var: *mut c_void,
) {
    trace!("InitializeConditionVariable — stub");
    if !cond_var.is_null() {
        unsafe {
            std::ptr::write_bytes(cond_var, 0, std::mem::size_of::<usize>());
        }
    }
}

pub extern "win64" fn sleep_condition_variable_cs(
    _cond_var: *mut c_void,
    _crit_section: *mut c_void,
    _dw_milliseconds: u32,
) -> i32 {
    trace!("SleepConditionVariableCS — stub");
    0
}

pub extern "win64" fn sleep_condition_variable_srw(
    _cond_var: *mut c_void,
    _srw_lock: *mut c_void,
    _dw_milliseconds: u32,
    _flags: u32,
) -> i32 {
    trace!("SleepConditionVariableSRW — stub");
    0
}

pub extern "win64" fn wake_condition_variable(
    _cond_var: *mut c_void,
) {
    trace!("WakeConditionVariable — stub");
}

pub extern "win64" fn wake_all_condition_variable(
    _cond_var: *mut c_void,
) {
    trace!("WakeAllConditionVariable — stub");
}
