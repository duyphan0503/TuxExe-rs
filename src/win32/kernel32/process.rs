#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! ExitProcess, GetModuleHandleA/W, GetCommandLineA/W, GetCurrentProcessId.

use std::ffi::c_void;
use tracing::trace;

pub extern "win64" fn exit_process(exit_code: u32) {
    trace!("ExitProcess({})", exit_code);
    std::process::exit(exit_code as i32);
}

// Global variable for the main image base
static mut MAIN_IMAGE_BASE: usize = 0x0040_0000; // Will be set during PE loading

pub fn set_main_image_base(base: usize) {
    unsafe {
        MAIN_IMAGE_BASE = base;
    }
}

pub extern "win64" fn get_module_handle_a(module_name: *const i8) -> *mut c_void {
    if module_name.is_null() {
        unsafe { MAIN_IMAGE_BASE as *mut c_void }
    } else {
        // We only support getting the main image handle for now
        std::ptr::null_mut()
    }
}

use std::ffi::CString;

lazy_static::lazy_static! {
    static ref CMD_LINE_A: CString = {
        let args: Vec<String> = std::env::args().collect();
        // Quote arguments if they contain spaces
        let cmd = args.iter().map(|arg| {
            if arg.contains(' ') {
                format!("\"{}\"", arg)
            } else {
                arg.clone()
            }
        }).collect::<Vec<String>>().join(" ");
        CString::new(cmd).unwrap_or_else(|_| CString::new("").unwrap())
    };

    static ref CMD_LINE_W: Vec<u16> = {
        let args: Vec<String> = std::env::args().collect();
        let cmd = args.iter().map(|arg| {
            if arg.contains(' ') {
                format!("\"{}\"", arg)
            } else {
                arg.clone()
            }
        }).collect::<Vec<String>>().join(" ");
        let mut utf16: Vec<u16> = cmd.encode_utf16().collect();
        utf16.push(0);
        utf16
    };
}

pub extern "win64" fn get_command_line_a() -> *const i8 {
    trace!("GetCommandLineA()");
    CMD_LINE_A.as_ptr()
}

pub extern "win64" fn get_command_line_w() -> *const u16 {
    trace!("GetCommandLineW()");
    CMD_LINE_W.as_ptr()
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

pub extern "win64" fn get_current_thread_id() -> u32 {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    trace!("GetCurrentThreadId() -> {}", tid);
    tid
}

pub extern "win64" fn is_processor_feature_present(processor_feature: u32) -> u32 {
    trace!("IsProcessorFeaturePresent({})", processor_feature);
    // Hardcode common features (e.g., SSE2 = 10, etc.)
    match processor_feature {
        10 => 1, // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        _ => 0,
    }
}
