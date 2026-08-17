//! Linux signal to Windows exception scaffolding.

use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{error, trace, warn};

use crate::runtime::telemetry;

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

    if crate::memory::virtual_alloc::try_handle_page_fault(record.fault_address) {
        trace!(fault_address = format_args!("0x{:x}", record.fault_address), "Auto-committed VirtualAlloc page");
        return;
    }

    let instruction_pointer = extract_instruction_pointer(context);
    let reg_dump = extract_register_dump(context);

    if instruction_pointer != 0 {
        let ip_unwind_match = unwind::lookup_static_runtime_function(instruction_pointer);
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

    let unwind_match = unwind::lookup_static_runtime_function(record.fault_address);
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

    // 1. Dispatch Vectored Exception Handlers (VEH)
    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
    unsafe {
        let uctx = context.cast::<libc::ucontext_t>();
        if !uctx.is_null() {
            let gregs = &mut (*uctx).uc_mcontext.gregs;
            let mut win_ctx = crate::win32::kernel32::error::WinContext {
                rax: gregs[libc::REG_RAX as usize] as u64,
                rbx: gregs[libc::REG_RBX as usize] as u64,
                rcx: gregs[libc::REG_RCX as usize] as u64,
                rdx: gregs[libc::REG_RDX as usize] as u64,
                rsi: gregs[libc::REG_RSI as usize] as u64,
                rdi: gregs[libc::REG_RDI as usize] as u64,
                rbp: gregs[libc::REG_RBP as usize] as u64,
                rsp: gregs[libc::REG_RSP as usize] as u64,
                r8: gregs[libc::REG_R8 as usize] as u64,
                r9: gregs[libc::REG_R9 as usize] as u64,
                r10: gregs[libc::REG_R10 as usize] as u64,
                r11: gregs[libc::REG_R11 as usize] as u64,
                r12: gregs[libc::REG_R12 as usize] as u64,
                r13: gregs[libc::REG_R13 as usize] as u64,
                r14: gregs[libc::REG_R14 as usize] as u64,
                r15: gregs[libc::REG_R15 as usize] as u64,
                rip: gregs[libc::REG_RIP as usize] as u64,
                eflags: gregs[libc::REG_EFL as usize] as u32,
                ..Default::default()
            };

            if crate::win32::kernel32::error::dispatch_vectored_exception(&record, &mut win_ctx) {
                trace!("Signal handled by Vectored Exception Handler");
                gregs[libc::REG_RAX as usize] = win_ctx.rax as i64;
                gregs[libc::REG_RBX as usize] = win_ctx.rbx as i64;
                gregs[libc::REG_RCX as usize] = win_ctx.rcx as i64;
                gregs[libc::REG_RDX as usize] = win_ctx.rdx as i64;
                gregs[libc::REG_RSI as usize] = win_ctx.rsi as i64;
                gregs[libc::REG_RDI as usize] = win_ctx.rdi as i64;
                gregs[libc::REG_RBP as usize] = win_ctx.rbp as i64;
                gregs[libc::REG_RSP as usize] = win_ctx.rsp as i64;
                gregs[libc::REG_R8 as usize] = win_ctx.r8 as i64;
                gregs[libc::REG_R9 as usize] = win_ctx.r9 as i64;
                gregs[libc::REG_R10 as usize] = win_ctx.r10 as i64;
                gregs[libc::REG_R11 as usize] = win_ctx.r11 as i64;
                gregs[libc::REG_R12 as usize] = win_ctx.r12 as i64;
                gregs[libc::REG_R13 as usize] = win_ctx.r13 as i64;
                gregs[libc::REG_R14 as usize] = win_ctx.r14 as i64;
                gregs[libc::REG_R15 as usize] = win_ctx.r15 as i64;
                gregs[libc::REG_RIP as usize] = win_ctx.rip as i64;
                gregs[libc::REG_EFL as usize] = win_ctx.eflags as i64;
                return;
            }
        }
    }

    // 2. Walk structured exception handling (SEH)
    if seh::walk_x86_seh_chain(&record) || seh::walk_seh_chain(&record) {
        trace!("Signal handled by SEH chain");
        return;
    }

    trace!("SEH chain walk failed — checking for special cases");

    if instruction_pointer != 0
        && crate::win32::kernel32::process::is_likely_main_image_address(instruction_pointer)
    {
        trace!("Instruction pointer is in mapped PE image range");
        // Do not resume a guest fault by skipping its store. In particular,
        // skipping a linked-list write leaves Unity's allocator internally
        // inconsistent and merely converts the original fault into a later,
        // opaque heap corruption. Guest faults must continue to normal SEH or
        // the unhandled path until the missing API/lifecycle cause is fixed.
    }

    // Special handling for NULL function pointer calls (rip=0x0)
    // This is common when stubs don't fully emulate Windows behavior.
    // We skip the call by advancing RIP past the indirect call instruction.
    if instruction_pointer == 0 && record.fault_address == 0 {
        trace!("Caught NULL function pointer call — attempting to skip");
        // Try to skip the call by finding the return address on the stack
        // This is a hacky workaround for Unity compatibility
        #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
        unsafe {
            let uctx = context.cast::<libc::ucontext_t>();
            if !uctx.is_null() {
                let rip_ptr = &mut (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize];
                let rsp_ptr = &mut (*uctx).uc_mcontext.gregs[libc::REG_RSP as usize];
                let rax_ptr = &mut (*uctx).uc_mcontext.gregs[libc::REG_RAX as usize];

                // Read return address from stack
                let rsp = *rsp_ptr as usize;
                let return_addr = if rsp != 0 { *(rsp as *const usize) } else { 0 };
                trace!("Return address on stack: 0x{:x}", return_addr);

                let is_plausible_return = |addr: usize| {
                    addr > 0x10000
                        && addr < 0x0000_8000_0000_0000usize
                        && (unwind::lookup_static_runtime_function(addr).is_some()
                            || crate::dll_manager::loader::module_base_for_address(addr).is_some())
                };

                if is_plausible_return(return_addr) {
                    // Set RIP to return address (skip the call)
                    *rip_ptr = return_addr as i64;
                    // Bump RSP past the return address
                    *rsp_ptr = (rsp + 8) as i64;
                    // Set RAX to 0 (simulating failed call)
                    *rax_ptr = 0;
                    trace!("Skipped NULL call, returning to 0x{:x}", return_addr);
                    return;
                }

                // Fallback heuristic: scan a small stack window for a plausible return address.
                // Some guest fast-fail paths leave [RSP] = 0 during indirect NULL calls.
                let mut recovered: Option<(usize, usize)> = None;
                for slot in 1..=32usize {
                    let candidate_ptr = (rsp + slot * 8) as *const usize;
                    let candidate = if candidate_ptr as usize != 0 { *candidate_ptr } else { 0 };
                    if is_plausible_return(candidate) {
                        recovered = Some((candidate, slot));
                        break;
                    }
                }

                if let Some((candidate, slot)) = recovered {
                    *rip_ptr = candidate as i64;
                    *rsp_ptr = (rsp + (slot + 1) * 8) as i64;
                    *rax_ptr = 0;
                    warn!(
                        recovered_return = format_args!("0x{candidate:x}"),
                        stack_slot = slot,
                        "Recovered NULL call by scanning stack for plausible return address"
                    );
                    return;
                } else {
                    // Final fallback: Try to get return address from frame pointer (RBP)
                    let rbp = (*uctx).uc_mcontext.gregs[libc::REG_RBP as usize] as usize;
                    if rbp != 0 {
                        let potential_ret_addr = if rbp + 8 < rsp + 1024 {
                            // reasonable bounds check
                            *((rbp + 8) as *const usize)
                        } else {
                            0
                        };

                        if is_plausible_return(potential_ret_addr) {
                            *rip_ptr = potential_ret_addr as i64;
                            *rsp_ptr = (rbp + 16) as i64; // adjust stack appropriately
                            *rax_ptr = 0;
                            warn!(
                                recovered_return = format_args!("0x{potential_ret_addr:x}"),
                                method = "frame_pointer",
                                "Recovered NULL call using frame pointer"
                            );
                            return;
                        }
                    }

                    // As a last resort, try to get the return address from the main executable range
                    // since the entry point was at 0x140001260 according to our logs
                    let main_image_range = crate::win32::kernel32::process::main_image_contains;
                    // Limit scan to reduce excessive logging - only try a few strategic locations
                    let scan_offsets =
                        [0x1008, 0x1020, 0x1040, 0x1080, 0x1100, 0x1200, 0x1400, 0x1800, 0x2000];
                    for offset in scan_offsets.iter() {
                        let potential_addr = 0x140000000 + offset;
                        if is_plausible_return(potential_addr) && main_image_range(potential_addr) {
                            *rip_ptr = potential_addr as i64;
                            *rsp_ptr = (*rsp_ptr as usize + 8) as i64; // increment stack pointer
                            *rax_ptr = 0;
                            trace!(
                                // Changed from warn to trace to reduce log spam
                                recovered_return = format_args!("0x{potential_addr:x}"),
                                method = "main_image_scan",
                                "Recovered NULL call by scanning main image for return address"
                            );
                            return;
                        }
                    }

                    // No valid return address means we cannot recover execution.
                    // Re-raising avoids spinning forever in the signal handler loop.
                    let breadcrumbs = telemetry::recent_compact(24);
                    warn!(
                        return_addr = format_args!("0x{return_addr:x}"),
                        breadcrumbs = %breadcrumbs,
                        "No valid return address for NULL call; re-raising signal"
                    );
                }
            } else {
                trace!("Context is null, cannot skip");
            }
        }
    }

    let breadcrumbs = telemetry::recent_compact(24);
    let ip_module = crate::dll_manager::loader::module_base_for_address(instruction_pointer);
    let ret_module = crate::dll_manager::loader::module_base_for_address(reg_dump.return_address);

    // Inspect stack words
    let mut stack_words = Vec::new();
    for i in 0..24 {
        let sp = reg_dump.rsp + i * 8;
        let mut val = 0usize;
        let read_ok = unsafe {
            libc::memcpy(&mut val as *mut _ as *mut libc::c_void, sp as *const libc::c_void, 8)
        };
        if !read_ok.is_null() {
            let m = crate::dll_manager::loader::module_base_for_address(val);
            stack_words.push(format!("+0x{:02x}: 0x{:x} ({:?})", i * 8, val, m.map(|b| format!("base+0x{:x}", val - b))));
        }
    }

    // Inspect string at rdx if readable
    let mut rdx_str = String::new();
    for offset in [32, 40, 48, 0] {
        let ptr = reg_dump.rdx + offset;
        let mut buf = [0u8; 64];
        let ok = unsafe {
            libc::memcpy(buf.as_mut_ptr() as *mut libc::c_void, ptr as *const libc::c_void, 63)
        };
        if !ok.is_null() {
            let s: String = buf.iter().take_while(|&&b| b >= 0x20 && b <= 0x7e).map(|&b| b as char).collect();
            if s.len() >= 3 {
                rdx_str = format!("offset {}: \"{}\"", offset, s);
                break;
            }
        }
    }

    error!(
        ?record,
        breadcrumbs = %breadcrumbs,
        instruction_pointer = format_args!("0x{:x} (module_base: {:?}, rva: {:?})", instruction_pointer, ip_module.map(|b| format!("0x{:x}", b)), ip_module.map(|b| format!("0x{:x}", instruction_pointer - b))),
        return_address = format_args!("0x{:x} (module_base: {:?}, rva: {:?})", reg_dump.return_address, ret_module.map(|b| format!("0x{:x}", b)), ret_module.map(|b| format!("0x{:x}", reg_dump.return_address - b))),
        rdx_str = %rdx_str,
        stack = ?stack_words,
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
        sa_sigaction: host_signal_handler as *const () as usize,
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
