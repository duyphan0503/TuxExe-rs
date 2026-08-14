#![allow(non_snake_case)]

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::trace;

use crate::{nt_kernel::thread as nt_thread, threading::tls, utils::handle::Handle};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
static THREAD_CONTEXT_TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct FiberContext {
    start_routine: Option<extern "system" fn(*mut c_void)>,
    parameter: *mut c_void,
    has_run: bool,
    converted_thread_fiber: bool,
}

thread_local! {
    static CURRENT_FIBER: Cell<*mut FiberContext> = const { Cell::new(ptr::null_mut()) };
    static STACK_GUARANTEE: Cell<u32> = const { Cell::new(0) };
}

fn set_last_error(err: u32) {
    super::error::set_last_error(err);
}

pub extern "win64" fn SetThreadStackGuarantee(stack_size_in_bytes: *mut u32) -> i32 {
    if stack_size_in_bytes.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let requested = unsafe { *stack_size_in_bytes };
    // Guest stacks are pre-reserved by runtime::guest_stack. Record the
    // accepted guarantee per guest thread without overcommitting host pages.
    STACK_GUARANTEE.with(|guarantee| guarantee.set(requested));
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn TlsAlloc() -> u32 {
    let result = tls::tls_alloc();
    trace!("TlsAlloc() -> {}", result);
    result
}

pub extern "win64" fn TlsFree(dwTlsIndex: u32) -> i32 {
    let result = tls::tls_free(dwTlsIndex) as i32;
    trace!("TlsFree({}) -> {}", dwTlsIndex, result);
    result
}

pub extern "win64" fn TlsSetValue(dwTlsIndex: u32, lpTlsValue: *mut c_void) -> i32 {
    tls::tls_set_value(dwTlsIndex, lpTlsValue) as i32
}

pub extern "win64" fn TlsGetValue(dwTlsIndex: u32) -> *mut c_void {
    tls::tls_get_value(dwTlsIndex)
}

pub extern "win64" fn FlsAlloc(_lp_callback: *const c_void) -> u32 {
    let result = TlsAlloc();
    trace!("FlsAlloc({:p}) -> {}", _lp_callback, result);
    result
}

pub extern "win64" fn FlsFree(dw_fls_index: u32) -> i32 {
    TlsFree(dw_fls_index)
}

pub extern "win64" fn FlsSetValue(dw_fls_index: u32, lp_fls_data: *mut c_void) -> i32 {
    TlsSetValue(dw_fls_index, lp_fls_data)
}

pub extern "win64" fn FlsGetValue(dw_fls_index: u32) -> *mut c_void {
    let result = TlsGetValue(dw_fls_index);
    trace!("FlsGetValue({}) -> {:p}", dw_fls_index, result);
    result
}

pub extern "win64" fn CreateThread(
    lpThreadAttributes: *const c_void,
    dwStackSize: usize,
    lpStartAddress: *const c_void,
    lpParameter: *mut c_void,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> Handle {
    nt_thread::create_thread(
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
    )
}

pub extern "win64" fn ExitThread(dwExitCode: u32) -> ! {
    nt_thread::exit_thread(dwExitCode)
}

pub extern "win64" fn GetCurrentThread() -> Handle {
    nt_thread::current_thread_pseudo_handle()
}

pub extern "win64" fn SuspendThread(hThread: Handle) -> u32 {
    nt_thread::suspend_thread(hThread)
}

pub extern "win64" fn ResumeThread(hThread: Handle) -> u32 {
    nt_thread::resume_thread(hThread)
}

pub extern "win64" fn GetThreadContext(_hThread: Handle, lpContext: *mut c_void) -> i32 {
    if std::env::var_os("TUXEXE_TRACE_THREAD_CONTEXT").is_some()
        && THREAD_CONTEXT_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 32
    {
        tracing::info!(handle = _hThread, context = ?lpContext, "GetThreadContext requested");
    }
    if lpContext.is_null() {
        return 0;
    }
    let ctx = lpContext.cast::<crate::win32::kernel32::error::WinContext>();
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::asm!(
            "mov qword ptr [{ctx} + 0x78], rax",
            "mov qword ptr [{ctx} + 0x80], rcx",
            "mov qword ptr [{ctx} + 0x88], rdx",
            "mov qword ptr [{ctx} + 0x90], rbx",
            "mov qword ptr [{ctx} + 0x98], rsp",
            "mov qword ptr [{ctx} + 0xa0], rbp",
            "mov qword ptr [{ctx} + 0xa8], rsi",
            "mov qword ptr [{ctx} + 0xb0], rdi",
            "mov qword ptr [{ctx} + 0xb8], r8",
            "mov qword ptr [{ctx} + 0xc0], r9",
            "mov qword ptr [{ctx} + 0xc8], r10",
            "mov qword ptr [{ctx} + 0xd0], r11",
            "mov qword ptr [{ctx} + 0xd8], r12",
            "mov qword ptr [{ctx} + 0xe0], r13",
            "mov qword ptr [{ctx} + 0xe8], r14",
            "mov qword ptr [{ctx} + 0xf0], r15",
            "lea rax, [rip]",
            "mov qword ptr [{ctx} + 0xf8], rax",
            ctx = in(reg) ctx,
            out("rax") _,
            options(nostack)
        );
    }
    1
}

pub extern "win64" fn SetThreadContext(_hThread: Handle, lpContext: *const c_void) -> i32 {
    if lpContext.is_null() {
        return 0;
    }
    1
}

pub extern "win64" fn CreateFiber(
    _dwStackSize: usize,
    lpStartAddress: *const c_void,
    lpParameter: *mut c_void,
) -> *mut c_void {
    if lpStartAddress.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ptr::null_mut();
    }

    let start = unsafe {
        std::mem::transmute::<*const c_void, extern "system" fn(*mut c_void)>(lpStartAddress)
    };
    let fiber = Box::new(FiberContext {
        start_routine: Some(start),
        parameter: lpParameter,
        has_run: false,
        converted_thread_fiber: false,
    });
    set_last_error(ERROR_SUCCESS);
    Box::into_raw(fiber).cast::<c_void>()
}

pub extern "win64" fn DeleteFiber(lpFiber: *mut c_void) {
    if lpFiber.is_null() {
        return;
    }

    let should_drop = CURRENT_FIBER.with(|current| current.get() != lpFiber.cast::<FiberContext>());
    if should_drop {
        unsafe {
            drop(Box::from_raw(lpFiber.cast::<FiberContext>()));
        }
    }
}

pub extern "win64" fn ConvertThreadToFiber(lpParameter: *mut c_void) -> *mut c_void {
    let existing = CURRENT_FIBER.with(|current| current.get());
    if !existing.is_null() {
        set_last_error(ERROR_SUCCESS);
        return existing.cast::<c_void>();
    }

    let fiber = Box::new(FiberContext {
        start_routine: None,
        parameter: lpParameter,
        has_run: true,
        converted_thread_fiber: true,
    });
    let fiber_ptr = Box::into_raw(fiber);
    CURRENT_FIBER.with(|current| current.set(fiber_ptr));
    set_last_error(ERROR_SUCCESS);
    fiber_ptr.cast::<c_void>()
}

pub extern "win64" fn ConvertFiberToThread() -> i32 {
    let current = CURRENT_FIBER.with(|slot| {
        let ptr = slot.get();
        slot.set(ptr::null_mut());
        ptr
    });

    if !current.is_null() {
        unsafe {
            if (*current).converted_thread_fiber {
                drop(Box::from_raw(current));
            }
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SwitchToFiber(lpFiber: *mut c_void) {
    if lpFiber.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return;
    }

    let fiber = lpFiber.cast::<FiberContext>();
    CURRENT_FIBER.with(|current| current.set(fiber));

    unsafe {
        if !(*fiber).has_run {
            if let Some(start) = (*fiber).start_routine {
                (*fiber).has_run = true;
                start((*fiber).parameter);
            }
        }
    }

    set_last_error(ERROR_SUCCESS);
}
