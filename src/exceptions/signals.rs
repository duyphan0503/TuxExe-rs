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
    context: *mut libc::c_void,
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

    let instruction_pointer = extract_instruction_pointer(context);
    let reg_dump = extract_register_dump(context);

    if instruction_pointer != 0 {
        let ip_unwind_match = unwind::lookup_runtime_function(instruction_pointer);
        if let Some(hit) = ip_unwind_match {
            trace!(
                instruction_pointer = format_args!("0x{:x}", instruction_pointer),
                image_base = format_args!("0x{:x}", hit.image_base),
                begin_rva = format_args!("0x{:x}", hit.function.begin_address_rva),
                end_rva = format_args!("0x{:x}", hit.function.end_address_rva),
                unwind_rva = format_args!("0x{:x}", hit.function.unwind_info_rva),
                "Instruction pointer is covered by RUNTIME_FUNCTION"
            );
        } else {
            trace!(
                instruction_pointer = format_args!("0x{:x}", instruction_pointer),
                "No RUNTIME_FUNCTION coverage for instruction pointer"
            );
        }
    }

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

    error!(
        ?record,
        instruction_pointer = format_args!("0x{:x}", instruction_pointer),
        rax = format_args!("0x{:x}", reg_dump.rax),
        rbx = format_args!("0x{:x}", reg_dump.rbx),
        rcx = format_args!("0x{:x}", reg_dump.rcx),
        rdx = format_args!("0x{:x}", reg_dump.rdx),
        rsi = format_args!("0x{:x}", reg_dump.rsi),
        rdi = format_args!("0x{:x}", reg_dump.rdi),
        r8 = format_args!("0x{:x}", reg_dump.r8),
        r9 = format_args!("0x{:x}", reg_dump.r9),
        r10 = format_args!("0x{:x}", reg_dump.r10),
        r11 = format_args!("0x{:x}", reg_dump.r11),
        r12 = format_args!("0x{:x}", reg_dump.r12),
        r13 = format_args!("0x{:x}", reg_dump.r13),
        r14 = format_args!("0x{:x}", reg_dump.r14),
        r15 = format_args!("0x{:x}", reg_dump.r15),
        rsp = format_args!("0x{:x}", reg_dump.rsp),
        rbp = format_args!("0x{:x}", reg_dump.rbp),
        return_address = format_args!("0x{:x}", reg_dump.return_address),
        "Unhandled host signal in SEH emulation path"
    );
    // Fall back to default signal behavior once unhandled.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

fn extract_instruction_pointer(context: *mut libc::c_void) -> usize {
    if context.is_null() {
        return 0;
    }

    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
    {
        // SAFETY: context is provided by kernel signal trampoline as ucontext_t.
        unsafe {
            let uctx = context.cast::<libc::ucontext_t>();
            (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] as usize
        }
    }

    #[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64")))]
    {
        0
    }
}

#[derive(Default, Clone, Copy)]
struct RegisterDump {
    rax: usize,
    rbx: usize,
    rcx: usize,
    rdx: usize,
    rsi: usize,
    rdi: usize,
    r8: usize,
    r9: usize,
    r10: usize,
    r11: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    rsp: usize,
    rbp: usize,
    return_address: usize,
}

fn extract_register_dump(context: *mut libc::c_void) -> RegisterDump {
    if context.is_null() {
        return RegisterDump::default();
    }

    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
    {
        // SAFETY: context is provided by kernel signal trampoline as ucontext_t.
        unsafe {
            let uctx = context.cast::<libc::ucontext_t>();
            let gregs = &(*uctx).uc_mcontext.gregs;
            let rsp = gregs[libc::REG_RSP as usize] as usize;
            let return_address = if rsp == 0 {
                0
            } else {
                // Best-effort read of callsite return address.
                *(rsp as *const usize)
            };

            RegisterDump {
                rax: gregs[libc::REG_RAX as usize] as usize,
                rbx: gregs[libc::REG_RBX as usize] as usize,
                rcx: gregs[libc::REG_RCX as usize] as usize,
                rdx: gregs[libc::REG_RDX as usize] as usize,
                rsi: gregs[libc::REG_RSI as usize] as usize,
                rdi: gregs[libc::REG_RDI as usize] as usize,
                r8: gregs[libc::REG_R8 as usize] as usize,
                r9: gregs[libc::REG_R9 as usize] as usize,
                r10: gregs[libc::REG_R10 as usize] as usize,
                r11: gregs[libc::REG_R11 as usize] as usize,
                r12: gregs[libc::REG_R12 as usize] as usize,
                r13: gregs[libc::REG_R13 as usize] as usize,
                r14: gregs[libc::REG_R14 as usize] as usize,
                r15: gregs[libc::REG_R15 as usize] as usize,
                rsp,
                rbp: gregs[libc::REG_RBP as usize] as usize,
                return_address,
            }
        }
    }

    #[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64")))]
    {
        RegisterDump::default()
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
