//! Thread and process environment state used by the Win32 runtime.

use std::{
    cell::Cell,
    env,
    ffi::c_void,
    ptr,
    sync::{Mutex, OnceLock},
};

use tracing::info;

use crate::{memory::heap, utils::handle::init_global_table};

pub const TLS_MINIMUM_AVAILABLE: usize = 64;
pub const TLS_EXPANSION_SLOTS: usize = 1024;
pub const TLS_SLOT_COUNT: usize = TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS;

#[repr(C)]
#[derive(Debug, Default)]
pub struct NtTib {
    pub exception_list: *mut u8,
    pub stack_base: *mut u8,
    pub stack_limit: *mut u8,
    pub sub_system_tib: *mut u8,
    pub fiber_data: *mut u8,
    pub arbitrary_user_pointer: *mut u8,
    pub self_ptr: *mut NtTib,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcessParameters {
    pub current_directory: *const u16,
    pub image_path_name: *const u16,
    pub command_line: *const u16,
    pub environment: *const u16,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub mutant: *mut c_void,
    pub image_base_address: *mut c_void,
    pub process_heap: usize,
    pub process_parameters: *mut ProcessParameters,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
}

#[repr(C, align(4096))]
#[derive(Debug)]
pub struct Teb {
    pub tib: NtTib,
    pub environment_pointer: *mut c_void,
    pub client_id_unique_process: usize,
    pub client_id_unique_thread: usize,
    pub active_rpc_handle: *mut c_void,
    pub thread_local_storage_pointer: *mut c_void,
    pub peb: *mut Peb,
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    _reserved1: [u8; 0x1410],
    pub tls_slots: [*mut c_void; TLS_MINIMUM_AVAILABLE],
    _reserved2: [u8; 0x3C00],
    pub tls_expansion_slots: [*mut c_void; TLS_EXPANSION_SLOTS],
}

const _: () = {
    assert!(std::mem::offset_of!(Teb, tib) == 0x00);
    assert!(std::mem::offset_of!(Teb, peb) == 0x60);
    assert!(std::mem::offset_of!(Teb, tls_slots) == 0x1480);
    assert!(std::mem::offset_of!(Teb, tls_expansion_slots) == 0x5280);
};

impl Default for Teb {
    fn default() -> Self {
        Self {
            tib: NtTib::default(),
            environment_pointer: ptr::null_mut(),
            client_id_unique_process: 0,
            client_id_unique_thread: 0,
            active_rpc_handle: ptr::null_mut(),
            thread_local_storage_pointer: ptr::null_mut(),
            peb: ptr::null_mut(),
            last_error_value: 0,
            count_of_owned_critical_sections: 0,
            _reserved1: [0; 0x1410],
            tls_slots: [ptr::null_mut(); TLS_MINIMUM_AVAILABLE],
            _reserved2: [0; 0x3C00],
            tls_expansion_slots: [ptr::null_mut(); TLS_EXPANSION_SLOTS],
        }
    }
}

#[derive(Debug)]
struct ProcessEnvironment {
    peb: Box<Peb>,
    _parameters: Box<ProcessParameters>,
    _current_directory: Box<[u16]>,
    _image_path_name: Box<[u16]>,
    _command_line: Box<[u16]>,
    _environment: Box<[u16]>,
}

unsafe impl Send for ProcessEnvironment {}
unsafe impl Sync for ProcessEnvironment {}

impl ProcessEnvironment {
    fn peb_ptr(&self) -> *mut Peb {
        (&*self.peb as *const Peb).cast_mut()
    }

    fn image_base(&self) -> usize {
        self.peb.image_base_address as usize
    }
}

thread_local! {
    static CURRENT_TEB: Cell<*mut Teb> = const { Cell::new(ptr::null_mut()) };
    static MANAGED_GUEST_THREAD: Cell<bool> = const { Cell::new(false) };
}

fn process_environment_cell() -> &'static OnceLock<ProcessEnvironment> {
    static PROCESS_ENV: OnceLock<ProcessEnvironment> = OnceLock::new();
    &PROCESS_ENV
}

fn managed_teb_registry() -> &'static Mutex<Vec<usize>> {
    static REGISTRY: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn register_managed_teb(teb_ptr: *mut Teb) {
    if teb_ptr.is_null() {
        return;
    }
    let mut registry = managed_teb_registry().lock().expect("managed TEB registry poisoned");
    let encoded = teb_ptr as usize;
    if !registry.iter().any(|entry| *entry == encoded) {
        registry.push(encoded);
    }
}

fn unregister_managed_teb(teb_ptr: *mut Teb) {
    if teb_ptr.is_null() {
        return;
    }
    let mut registry = managed_teb_registry().lock().expect("managed TEB registry poisoned");
    let encoded = teb_ptr as usize;
    registry.retain(|entry| *entry != encoded);
}

pub fn managed_teb_pointers() -> Vec<*mut Teb> {
    managed_teb_registry()
        .lock()
        .expect("managed TEB registry poisoned")
        .iter()
        .copied()
        .map(|ptr| ptr as *mut Teb)
        .collect()
}

pub fn teb_tls_value(teb_ptr: *mut Teb, index: usize) -> *mut c_void {
    if teb_ptr.is_null() || index >= TLS_SLOT_COUNT {
        return ptr::null_mut();
    }
    unsafe {
        let teb = &*teb_ptr;
        if index < TLS_MINIMUM_AVAILABLE {
            teb.tls_slots[index]
        } else {
            teb.tls_expansion_slots[index - TLS_MINIMUM_AVAILABLE]
        }
    }
}

pub fn set_teb_tls_value(teb_ptr: *mut Teb, index: usize, value: *mut c_void) -> bool {
    if teb_ptr.is_null() || index >= TLS_SLOT_COUNT {
        return false;
    }
    unsafe {
        let teb = &mut *teb_ptr;
        if index < TLS_MINIMUM_AVAILABLE {
            teb.tls_slots[index] = value;
        } else {
            teb.tls_expansion_slots[index - TLS_MINIMUM_AVAILABLE] = value;
        }
    }
    true
}

fn encode_wide(value: &str) -> Box<[u16]> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    wide.into_boxed_slice()
}

fn build_process_environment(image_base: usize) -> ProcessEnvironment {
    init_global_table();
    let process_heap = heap::get_process_heap();

    let cwd = env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ".".to_string());
    let image_path = env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "tuxexe".to_string());
    let command_line = env::args().collect::<Vec<_>>().join(" ");
    let environment =
        env::vars().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join("\u{0}");

    let current_directory = encode_wide(&cwd);
    let image_path_name = encode_wide(&image_path);
    let command_line = encode_wide(&command_line);
    let environment = encode_wide(&environment);

    let mut parameters = Box::new(ProcessParameters::default());
    parameters.current_directory = current_directory.as_ptr();
    parameters.image_path_name = image_path_name.as_ptr();
    parameters.command_line = command_line.as_ptr();
    parameters.environment = environment.as_ptr();

    let mut peb = Box::new(Peb::default());
    peb.image_base_address = image_base as *mut c_void;
    peb.process_heap = process_heap as usize;
    peb.process_parameters = (&mut *parameters) as *mut ProcessParameters;
    peb.number_of_processors =
        std::thread::available_parallelism().map(|count| count.get() as u32).unwrap_or(1);

    ProcessEnvironment {
        peb,
        _parameters: parameters,
        _current_directory: current_directory,
        _image_path_name: image_path_name,
        _command_line: command_line,
        _environment: environment,
    }
}

fn ensure_process_environment(image_base: usize) -> &'static ProcessEnvironment {
    process_environment_cell().get_or_init(|| build_process_environment(image_base))
}

thread_local! {
    static CURRENT_CACHED_TEB: std::cell::Cell<*mut Teb> = const { std::cell::Cell::new(ptr::null_mut()) };
    static CURRENT_CACHED_TID: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn current_thread_id() -> usize {
    let tid = CURRENT_CACHED_TID.get();
    if tid != 0 {
        return tid;
    }
    let new_tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
    CURRENT_CACHED_TID.set(new_tid);
    new_tid
}

fn stack_bounds() -> (*mut u8, *mut u8) {
    let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    let mut stack_base: *mut libc::c_void = std::ptr::null_mut();
    let mut stack_size: libc::size_t = 0;

    unsafe {
        libc::pthread_getattr_np(libc::pthread_self(), &mut attr);
        libc::pthread_attr_getstack(&attr, &mut stack_base, &mut stack_size);
        libc::pthread_attr_destroy(&mut attr);
    }

    // In Linux, stack_base returned by pthread_attr_getstack is the *lowest* address (the limit).
    // The top of the stack is stack_base + stack_size.
    //
    // WINDOWS COMPATIBILITY HACK:
    // MSVC `_chkstk` routine will read `TEB.StackLimit` (gs:0x10) and then loop
    // `r11 = r11 - 0x1000; mov byte [r11], 0` to manually trigger guard page exceptions
    // to ask the Windows kernel to commit more stack memory.
    // On Linux, this will just segfault because we don't have the Windows kernel
    // trapping these exceptions to grow the stack.
    //
    // The `_chkstk` loop does: `cmp r10, gs:0x10; jae exit_loop`.
    // If we set `TEB.StackLimit` to 0, `target_rsp >= limit`
    // will always be true, bypassing the MSVC `_chkstk` completely!
    let limit = stack_base as *mut u8;
    let base = (stack_base as usize + stack_size) as *mut u8;

    (base, limit)
}

fn apply_gs_base(teb: *mut Teb) -> Result<(), String> {
    CURRENT_CACHED_TEB.set(teb);
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        const ARCH_SET_GS: libc::c_int = 0x1001;
        let ret = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, teb as usize) };
        if ret != 0 {
            return Err(format!(
                "arch_prctl(ARCH_SET_GS) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

fn allocate_teb(peb_ptr: *mut Peb) -> *mut Teb {
    let (stack_base, stack_limit) = stack_bounds();
    let mut teb = Box::new(Teb::default());

    teb.tib.stack_base = stack_base;
    teb.tib.stack_limit = stack_limit;
    teb.tib.self_ptr = (&mut teb.tib) as *mut NtTib;
    teb.client_id_unique_process = std::process::id() as usize;
    teb.client_id_unique_thread = current_thread_id();
    teb.peb = peb_ptr;
    teb.thread_local_storage_pointer = teb.tls_slots.as_mut_ptr().cast::<c_void>();

    Box::into_raw(teb)
}

pub fn with_current_teb<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Teb) -> R,
{
    let mut ptr = current_teb_ptr();
    if ptr.is_null() {
        let _ = attach_spawned_thread();
        ptr = current_teb_ptr();
    }
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { f(&mut *ptr) })
    }
}

/// Temporarily replace the Windows-visible stack bounds for the current guest
/// thread. PE code entered through the isolated guest stack can inspect these
/// fields (notably `_chkstk` and exception/runtime helpers), so leaving the
/// host pthread bounds installed makes the guest observe an unrelated stack.
pub fn replace_current_stack_bounds(
    stack_base: *mut u8,
    stack_limit: *mut u8,
) -> Option<(*mut u8, *mut u8)> {
    with_current_teb(|teb| {
        let previous = (teb.tib.stack_base, teb.tib.stack_limit);
        teb.tib.stack_base = stack_base;
        teb.tib.stack_limit = stack_limit;
        previous
    })
}

pub fn current_teb_ptr() -> *mut Teb {
    let cached = CURRENT_CACHED_TEB.get();
    if !cached.is_null() {
        return cached;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut gs_base: usize = 0;
        const ARCH_GET_GS: libc::c_int = 0x1004;
        let res = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_GS, &mut gs_base as *mut usize) };
        if res == 0 && gs_base != 0 {
            let teb = gs_base as *mut Teb;
            if unsafe { !(*teb).peb.is_null() && (*teb).client_id_unique_thread == current_thread_id() } {
                CURRENT_CACHED_TEB.set(teb);
                return teb;
            }
        }
    }
    ptr::null_mut()
}

pub fn current_peb_ptr() -> *mut Peb {
    let teb = current_teb_ptr();
    if teb.is_null() {
        ptr::null_mut()
    } else {
        unsafe { (*teb).peb }
    }
}

pub fn is_managed_guest_thread() -> bool {
    !current_teb_ptr().is_null()
}

pub fn setup_teb(image_base: usize) -> Result<(), String> {
    if !current_teb_ptr().is_null() {
        return Ok(());
    }

    let process = ensure_process_environment(image_base);
    let teb_ptr = allocate_teb(process.peb_ptr());
    apply_gs_base(teb_ptr)?;

    register_managed_teb(teb_ptr);

    info!(
        teb = format_args!("{:p}", teb_ptr),
        peb = format_args!("{:p}", process.peb_ptr()),
        image_base = format_args!("0x{:x}", process.image_base()),
        "Initialized TEB/PEB for current thread"
    );

    Ok(())
}

pub fn attach_spawned_thread() -> Result<(), String> {
    if !current_teb_ptr().is_null() {
        return Ok(());
    }

    let process = ensure_process_environment(process_image_base());
    let teb_ptr = allocate_teb(process.peb_ptr());
    apply_gs_base(teb_ptr)?;

    register_managed_teb(teb_ptr);
    Ok(())
}

pub fn destroy_current_teb() {
    let teb_ptr = current_teb_ptr();
    CURRENT_CACHED_TEB.set(ptr::null_mut());
    if !teb_ptr.is_null() {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            const ARCH_SET_GS: libc::c_int = 0x1001;
            unsafe {
                let _ = libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, 0usize);
            }
        }
        unregister_managed_teb(teb_ptr);
        unsafe {
            drop(Box::from_raw(teb_ptr));
        }
    }
}

pub fn process_heap_handle() -> usize {
    ensure_process_environment(0).peb.process_heap
}

pub fn process_image_base() -> usize {
    ensure_process_environment(0).image_base()
}

/// A native library loaded by the host (DXVK, Vulkan drivers, PulseAudio,
/// etc.) is allowed to create pthreads as usual.  Routines in manually mapped
/// PE images *and* Mono's anonymous JIT pages require a Windows TEB and the
/// loader notifications that normally accompany `CreateThread`.
///
/// Applying this setup to every host pthread is actively harmful: native
/// worker threads inherit a guest GS base.  A PE-image-only check is too
/// narrow, however: Mono frequently passes a JIT-generated function as the
/// pthread start routine; JIT pages are not in our PE module registry but do
/// need the guest lifecycle.  `dladdr` identifies normal host ELF code, so an
/// address not owned by an ELF image is treated as guest/JIT code.
fn is_host_elf_address(address: usize) -> bool {
    if address == 0 {
        return false;
    }

    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    unsafe {
        libc::dladdr(address as *const c_void, &mut info) != 0 && !info.dli_fbase.is_null()
    }
}

fn requires_guest_thread_lifecycle(start_routine: usize) -> bool {
    crate::dll_manager::loader::module_base_for_address(start_routine).is_some()
        || !is_host_elf_address(start_routine)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> libc::c_int {
    struct ThreadArgs {
        start_routine: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
        requires_guest_lifecycle: bool,
    }

    extern "C" fn thread_entry(raw_arg: *mut c_void) -> *mut c_void {
        let args = unsafe { Box::from_raw(raw_arg as *mut ThreadArgs) };
        if args.requires_guest_lifecycle {
            if let Err(error) = attach_spawned_thread() {
                tracing::warn!(%error, "Failed to attach TEB for PE pthread");
            } else {
                crate::threading::tls::initialize_static_tls_for_current_thread();
                crate::threading::tls::invoke_thread_attach_callbacks();
                crate::dll_manager::loader::invoke_thread_attach_dll_mains();
            }
        }

        // `pthread_create` itself is a host ABI entry point, but callbacks
        // supplied by a manually mapped PE or Mono's anonymous JIT pages use
        // the Windows x64 ABI. Calling one through the C/SysV function pointer
        // above puts its argument in RDI instead of RCX and executes it on the
        // host pthread stack. Enter through the PE64 bridge after the guest
        // lifecycle is installed; native host callbacks retain their normal
        // pthread ABI and stack.
        let result = if args.requires_guest_lifecycle {
            match crate::runtime::guest_stack::invoke_thread(
                args.start_routine as usize,
                args.arg,
            ) {
                Ok(exit_code) => exit_code as usize as *mut c_void,
                Err(error) => {
                    tracing::warn!(%error, "Failed to enter guest pthread start routine");
                    std::ptr::null_mut()
                }
            }
        } else {
            (args.start_routine)(args.arg)
        };

        if args.requires_guest_lifecycle {
            destroy_current_teb();
        }

        result
    }

    let boxed_args = Box::new(ThreadArgs {
        start_routine,
        arg,
        requires_guest_lifecycle: requires_guest_thread_lifecycle(start_routine as usize),
    });
    let raw_args = Box::into_raw(boxed_args) as *mut c_void;

    static REAL_PTHREAD_CREATE: OnceLock<
        unsafe extern "C" fn(
            *mut libc::pthread_t,
            *const libc::pthread_attr_t,
            extern "C" fn(*mut c_void) -> *mut c_void,
            *mut c_void,
        ) -> libc::c_int,
    > = OnceLock::new();

    let real_fn = *REAL_PTHREAD_CREATE.get_or_init(|| unsafe {
        let symbol = libc::dlsym(libc::RTLD_NEXT, b"pthread_create\0".as_ptr().cast());
        std::mem::transmute(symbol)
    });

    let result = real_fn(thread, attr, thread_entry, raw_args);
    if result != 0 {
        // The wrapper owns the arguments until the child takes them.  A
        // failed pthread_create never calls thread_entry, so reclaim them
        // here instead of leaking one allocation per failed thread spawn.
        drop(Box::from_raw(raw_args as *mut ThreadArgs));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn setup_teb_creates_current_thread_state() {
        let _guard = serial_guard();
        setup_teb(0x1400_0000).expect("TEB setup should succeed");

        let teb_ptr = current_teb_ptr();
        assert!(!teb_ptr.is_null());

        let peb_ptr = current_peb_ptr();
        assert!(!peb_ptr.is_null());

        with_current_teb(|teb| {
            assert_eq!(teb.peb, peb_ptr);
            assert_ne!(teb.client_id_unique_thread, 0);
            let tib_ptr = (&teb.tib as *const NtTib).cast_mut();
            assert_eq!(teb.tib.self_ptr, tib_ptr);
        });
    }

    extern "C" fn native_test_thread_entry(_arg: *mut c_void) -> *mut c_void {
        std::ptr::null_mut()
    }

    #[test]
    fn host_thread_routine_does_not_receive_guest_lifecycle() {
        // This function lives in the Rust host executable, not a manually
        // mapped PE image. It models DXVK and driver worker entry points.
        assert!(!requires_guest_thread_lifecycle(native_test_thread_entry as usize));
    }

    #[test]
    fn anonymous_code_is_treated_as_guest_lifecycle() {
        // `dladdr` cannot associate an anonymous executable page (which is
        // how Mono exposes JIT entry points) with a host ELF image.
        assert!(!is_host_elf_address(0));
        assert!(requires_guest_thread_lifecycle(0));
    }

    #[test]
    fn spawned_thread_can_attach_and_destroy_teb() {
        let _guard = serial_guard();
        let handle = std::thread::spawn(|| {
            attach_spawned_thread().expect("spawned thread should attach");
            assert!(!current_teb_ptr().is_null());
            destroy_current_teb();
            assert!(current_teb_ptr().is_null());
        });

        handle.join().expect("test thread should join");
    }
}
