//! Linux signal to Windows exception scaffolding.

use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{error, trace};

use super::{seh, unwind};

pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
pub const EXCEPTION_UNHANDLED_SIGNAL: u32 = 0xC000_013A;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub signal_number: i32,
    pub fault_address: usize,
}

static SIGNAL_HANDLERS_INSTALLED: AtomicBool = AtomicBool::new(false);

pub fn signal_to_exception_code(signal: i32) -> u32 {
    match signal {
        libc::SIGSEGV => EXCEPTION_ACCESS_VIOLATION,
        libc::SIGILL => EXCEPTION_ILLEGAL_INSTRUCTION,
        libc::SIGFPE => EXCEPTION_INT_DIVIDE_BY_ZERO,
        libc::SIGTRAP => EXCEPTION_BREAKPOINT,
        _ => EXCEPTION_UNHANDLED_SIGNAL,
    }
}

extern "C" fn host_signal_handler(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    let fault_address = unsafe {
        if info.is_null() {
            0
        } else {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                (*info).si_addr() as usize
            }

            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                0
            }
        }
    };

    let record = ExceptionRecord {
        exception_code: signal_to_exception_code(signal),
        signal_number: signal,
        fault_address,
    };

    let unwind_match = unwind::lookup_runtime_function(record.fault_address);
    if let Some(hit) = unwind_match {
        trace!(
            fault_address = format_args!("0x{:x}", record.fault_address),
            image_base = format_args!("0x{:x}", hit.image_base),
            begin_rva = format_args!("0x{:x}", hit.function.begin_address_rva),
            end_rva = format_args!("0x{:x}", hit.function.end_address_rva),
            unwind_rva = format_args!("0x{:x}", hit.function.unwind_info_rva),
            "Fault address is covered by RUNTIME_FUNCTION"
        );
    } else {
        trace!(
            fault_address = format_args!("0x{:x}", record.fault_address),
            "No RUNTIME_FUNCTION coverage for fault address"
        );
    }

    if seh::walk_x86_seh_chain(&record) || seh::walk_seh_chain(&record) {
        trace!("Signal handled by SEH chain");
        return;
    }

    error!(?record, "Unhandled host signal in SEH emulation path");
    // Fall back to default signal behavior once unhandled.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

pub fn install_signal_handlers() -> Result<(), String> {
    if SIGNAL_HANDLERS_INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let handler = libc::sigaction {
        sa_sigaction: host_signal_handler as usize,
        sa_mask: unsafe { std::mem::zeroed() },
        sa_flags: libc::SA_SIGINFO,
        sa_restorer: None,
    };

    for signal in [libc::SIGSEGV, libc::SIGFPE, libc::SIGILL, libc::SIGTRAP] {
        let result = unsafe { libc::sigaction(signal, &handler, std::ptr::null_mut()) };
        if result != 0 {
            SIGNAL_HANDLERS_INSTALLED.store(false, Ordering::SeqCst);
            return Err(format!("sigaction({signal}) failed: {}", std::io::Error::last_os_error()));
        }
    }

    trace!("Installed Linux signal handlers for SEH emulation");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_mapping_matches_expected_windows_exceptions() {
        assert_eq!(signal_to_exception_code(libc::SIGSEGV), EXCEPTION_ACCESS_VIOLATION);
        assert_eq!(signal_to_exception_code(libc::SIGILL), EXCEPTION_ILLEGAL_INSTRUCTION);
        assert_eq!(signal_to_exception_code(libc::SIGFPE), EXCEPTION_INT_DIVIDE_BY_ZERO);
        assert_eq!(signal_to_exception_code(libc::SIGTRAP), EXCEPTION_BREAKPOINT);
    }
}
