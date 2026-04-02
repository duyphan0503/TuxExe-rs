//! Thread and process environment state used by the Win32 runtime.

use std::{cell::Cell, env, ffi::c_void, ptr, sync::OnceLock};

use tracing::info;

use crate::{memory::heap, utils::handle::init_global_table};

pub const TLS_MINIMUM_AVAILABLE: usize = 64;
pub const TLS_EXPANSION_SLOTS: usize = 1024;
pub const TLS_SLOT_COUNT: usize = TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS;

const DEFAULT_STACK_WINDOW: usize = 8 * 1024 * 1024;

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
    pub tls_slots: [*mut c_void; TLS_MINIMUM_AVAILABLE],
    pub tls_expansion_slots: [*mut c_void; TLS_EXPANSION_SLOTS],
}

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
            tls_slots: [ptr::null_mut(); TLS_MINIMUM_AVAILABLE],
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

fn current_thread_id() -> usize {
    unsafe { libc::syscall(libc::SYS_gettid) as usize }
}

fn stack_bounds() -> (*mut u8, *mut u8) {
    let marker = 0_u8;
    let stack_base = (&marker as *const u8 as usize + 4096) as *mut u8;
    let stack_limit = (stack_base as usize).saturating_sub(DEFAULT_STACK_WINDOW) as *mut u8;
    (stack_base, stack_limit)
}

fn apply_gs_base(teb: *mut Teb) -> Result<(), String> {
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
    CURRENT_TEB.with(|slot| {
        let ptr = slot.get();
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { f(&mut *ptr) })
        }
    })
}

pub fn current_teb_ptr() -> *mut Teb {
    CURRENT_TEB.with(Cell::get)
}

pub fn current_peb_ptr() -> *mut Peb {
    with_current_teb(|teb| teb.peb).unwrap_or(ptr::null_mut())
}

pub fn is_managed_guest_thread() -> bool {
    MANAGED_GUEST_THREAD.with(Cell::get)
}

pub fn setup_teb(image_base: usize) -> Result<(), String> {
    if !current_teb_ptr().is_null() {
        return Ok(());
    }

    let process = ensure_process_environment(image_base);
    let teb_ptr = allocate_teb(process.peb_ptr());
    apply_gs_base(teb_ptr)?;

    CURRENT_TEB.with(|slot| slot.set(teb_ptr));
    MANAGED_GUEST_THREAD.with(|slot| slot.set(true));

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

    CURRENT_TEB.with(|slot| slot.set(teb_ptr));
    MANAGED_GUEST_THREAD.with(|slot| slot.set(true));
    Ok(())
}

pub fn destroy_current_teb() {
    CURRENT_TEB.with(|slot| {
        let ptr = slot.replace(ptr::null_mut());
        if !ptr.is_null() {
            unsafe {
                drop(Box::from_raw(ptr));
            }
        }
    });
    MANAGED_GUEST_THREAD.with(|slot| slot.set(false));
}

pub fn process_heap_handle() -> usize {
    ensure_process_environment(0).peb.process_heap
}

pub fn process_image_base() -> usize {
    ensure_process_environment(0).image_base()
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
