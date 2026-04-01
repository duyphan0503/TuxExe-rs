//! Thread Local Storage slots backed by the current thread's TEB.

use std::{
    ffi::c_void,
    sync::{Mutex, OnceLock},
};

use tracing::{info, trace, warn};

use crate::{
    pe_loader::{mapper::MappedImage, parser::ParsedPe},
    threading::teb::{self, TLS_MINIMUM_AVAILABLE, TLS_SLOT_COUNT},
};

pub const TLS_OUT_OF_INDEXES: u32 = u32::MAX;
pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

type TlsCallback = unsafe extern "win64" fn(*mut c_void, u32, *mut c_void);

#[derive(Debug, Clone, Default)]
struct RegisteredTlsCallbacks {
    image_base: usize,
    callbacks: Vec<usize>,
}

fn slot_allocator() -> &'static Mutex<Vec<bool>> {
    static ALLOCATOR: OnceLock<Mutex<Vec<bool>>> = OnceLock::new();
    ALLOCATOR.get_or_init(|| Mutex::new(vec![false; TLS_SLOT_COUNT]))
}

fn tls_callbacks_cell() -> &'static Mutex<Option<RegisteredTlsCallbacks>> {
    static CALLBACKS: OnceLock<Mutex<Option<RegisteredTlsCallbacks>>> = OnceLock::new();
    CALLBACKS.get_or_init(|| Mutex::new(None))
}

fn ensure_current_thread_teb() {
    if teb::current_teb_ptr().is_null() {
        let _ = teb::setup_teb(0);
    }
}

pub fn tls_alloc() -> u32 {
    let mut allocator = slot_allocator().lock().expect("TLS slot allocator poisoned");
    match allocator.iter().position(|used| !*used) {
        Some(index) => {
            allocator[index] = true;
            index as u32
        }
        None => TLS_OUT_OF_INDEXES,
    }
}

pub fn tls_free(index: u32) -> bool {
    let index = index as usize;
    if index >= TLS_SLOT_COUNT {
        return false;
    }

    let mut allocator = slot_allocator().lock().expect("TLS slot allocator poisoned");
    if !allocator[index] {
        return false;
    }

    allocator[index] = false;
    ensure_current_thread_teb();
    let _ = teb::with_current_teb(|teb| {
        if index < TLS_MINIMUM_AVAILABLE {
            teb.tls_slots[index] = std::ptr::null_mut();
        } else {
            teb.tls_expansion_slots[index - TLS_MINIMUM_AVAILABLE] = std::ptr::null_mut();
        }
    });

    true
}

pub fn tls_set_value(index: u32, value: *mut c_void) -> bool {
    let index = index as usize;
    if index >= TLS_SLOT_COUNT {
        return false;
    }

    ensure_current_thread_teb();
    teb::with_current_teb(|teb| {
        if index < TLS_MINIMUM_AVAILABLE {
            teb.tls_slots[index] = value;
        } else {
            teb.tls_expansion_slots[index - TLS_MINIMUM_AVAILABLE] = value;
        }
    })
    .is_some()
}

pub fn tls_get_value(index: u32) -> *mut c_void {
    let index = index as usize;
    if index >= TLS_SLOT_COUNT {
        return std::ptr::null_mut();
    }

    ensure_current_thread_teb();
    teb::with_current_teb(|teb| {
        if index < TLS_MINIMUM_AVAILABLE {
            teb.tls_slots[index]
        } else {
            teb.tls_expansion_slots[index - TLS_MINIMUM_AVAILABLE]
        }
    })
    .unwrap_or(std::ptr::null_mut())
}

fn read_pointer(mapped: &MappedImage, rva: usize, is_pe64: bool) -> Option<usize> {
    if is_pe64 {
        mapped.read_u64(rva).map(|value| value as usize)
    } else {
        mapped.read_u32(rva).map(|value| value as usize)
    }
}

pub fn register_tls_callbacks(pe: &ParsedPe, mapped: &MappedImage) -> Result<(), String> {
    let Some(directory) = pe.tls_dir.filter(|dir| dir.virtual_address != 0 && dir.size > 0) else {
        *tls_callbacks_cell().lock().expect("TLS callback registry poisoned") = None;
        return Ok(());
    };

    let callbacks_field_rva = if pe.is_pe64 {
        directory.virtual_address as usize + 24
    } else {
        directory.virtual_address as usize + 12
    };

    let callbacks_va = read_pointer(mapped, callbacks_field_rva, pe.is_pe64).ok_or_else(|| {
        format!("TLS directory callback pointer OOB at RVA 0x{callbacks_field_rva:x}")
    })?;

    if callbacks_va == 0 {
        *tls_callbacks_cell().lock().expect("TLS callback registry poisoned") = None;
        return Ok(());
    }

    let image_base = mapped.base_addr();
    let callbacks_rva = callbacks_va.checked_sub(image_base).ok_or_else(|| {
        format!("TLS callback table VA 0x{callbacks_va:x} is below image base 0x{image_base:x}")
    })?;

    let ptr_size = if pe.is_pe64 { 8 } else { 4 };
    let mut callbacks = Vec::new();
    let mut index = 0usize;

    loop {
        let entry_rva = callbacks_rva + index * ptr_size;
        let callback = read_pointer(mapped, entry_rva, pe.is_pe64)
            .ok_or_else(|| format!("TLS callback entry OOB at RVA 0x{entry_rva:x}"))?;
        if callback == 0 {
            break;
        }
        callbacks.push(callback);
        index += 1;
        if index > 256 {
            return Err("TLS callback table exceeded 256 entries without terminator".into());
        }
    }

    if callbacks.is_empty() {
        *tls_callbacks_cell().lock().expect("TLS callback registry poisoned") = None;
        return Ok(());
    }

    info!(
        count = callbacks.len(),
        image_base = format_args!("0x{image_base:x}"),
        "Registered PE TLS callbacks"
    );
    *tls_callbacks_cell().lock().expect("TLS callback registry poisoned") =
        Some(RegisteredTlsCallbacks { image_base, callbacks });
    Ok(())
}

fn invoke_registered_tls_callbacks(reason: u32) {
    let registered = tls_callbacks_cell().lock().expect("TLS callback registry poisoned").clone();

    let Some(registered) = registered else {
        return;
    };

    for callback in registered.callbacks {
        let callback_addr = callback;
        trace!(callback = format_args!("0x{callback_addr:x}"), reason, "Invoking PE TLS callback");
        let callback: TlsCallback = unsafe { std::mem::transmute(callback_addr) };
        let result = std::panic::catch_unwind(|| unsafe {
            callback(registered.image_base as *mut c_void, reason, std::ptr::null_mut());
        });
        if result.is_err() {
            warn!(
                callback = format_args!("0x{callback_addr:x}"),
                reason, "PE TLS callback panicked while executing"
            );
        }
    }
}

pub fn invoke_process_attach_callbacks() {
    invoke_registered_tls_callbacks(DLL_PROCESS_ATTACH);
}

pub fn invoke_thread_attach_callbacks() {
    invoke_registered_tls_callbacks(DLL_THREAD_ATTACH);
}

pub fn clear_registered_tls_callbacks() {
    *tls_callbacks_cell().lock().expect("TLS callback registry poisoned") = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threading::teb::TLS_EXPANSION_SLOTS;
    use crate::{
        pe_loader::{
            mapper::map_pe,
            parser::{tests::minimal_pe64_pub, DataDirectory, ParsedPe},
        },
        test_support::serial_guard,
    };
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static TLS_CALLBACK_REASON: AtomicU32 = AtomicU32::new(0);
    static TLS_CALLBACK_MODULE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "win64" fn test_tls_callback(
        module: *mut c_void,
        reason: u32,
        _reserved: *mut c_void,
    ) {
        TLS_CALLBACK_MODULE.store(module as usize, Ordering::SeqCst);
        TLS_CALLBACK_REASON.store(reason, Ordering::SeqCst);
    }

    #[test]
    fn tls_slots_store_thread_local_values() {
        let _guard = serial_guard();
        let slot = tls_alloc();
        assert_ne!(slot, TLS_OUT_OF_INDEXES);

        let value = 0x1234usize as *mut c_void;
        assert!(tls_set_value(slot, value));
        assert_eq!(tls_get_value(slot), value);
        assert!(tls_free(slot));
    }

    #[test]
    fn tls_values_are_isolated_per_thread() {
        let _guard = serial_guard();
        let slot = tls_alloc();
        assert_ne!(slot, TLS_OUT_OF_INDEXES);

        tls_set_value(slot, 0xaaaausize as *mut c_void);

        let handle = std::thread::spawn(move || {
            assert_eq!(tls_get_value(slot), std::ptr::null_mut());
            tls_set_value(slot, 0xbbbbusize as *mut c_void);
            assert_eq!(tls_get_value(slot), 0xbbbbusize as *mut c_void);
        });

        handle.join().expect("thread should finish cleanly");
        assert_eq!(tls_get_value(slot), 0xaaaausize as *mut c_void);
        assert!(tls_free(slot));
    }

    #[test]
    fn expansion_slots_are_supported() {
        let _guard = serial_guard();
        let mut allocated = Vec::new();
        for _ in 0..(TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS + 1) {
            allocated.push(tls_alloc());
        }

        assert_eq!(allocated.pop(), Some(TLS_OUT_OF_INDEXES));

        let expansion_slot = allocated[TLS_MINIMUM_AVAILABLE];
        assert!(tls_set_value(expansion_slot, 0xccccusize as *mut c_void));
        assert_eq!(tls_get_value(expansion_slot), 0xccccusize as *mut c_void);

        for slot in allocated {
            assert!(tls_free(slot));
        }
    }

    #[test]
    fn tls_callbacks_are_registered_and_invoked_for_process_attach() {
        let _guard = serial_guard();
        TLS_CALLBACK_REASON.store(0, Ordering::SeqCst);
        TLS_CALLBACK_MODULE.store(0, Ordering::SeqCst);

        let mut parsed = ParsedPe::from_bytes(minimal_pe64_pub()).expect("minimal PE should parse");
        parsed.tls_dir = Some(DataDirectory { virtual_address: 0x180, size: 40 });

        let mut mapped = map_pe(&parsed).expect("minimal PE should map");
        let image_base = mapped.base_addr();
        let callbacks_va = image_base + 0x1c0;

        mapped.write_u64(0x180 + 24, callbacks_va as u64).expect("TLS callback VA should fit");
        mapped
            .write_u64(0x1c0, test_tls_callback as usize as u64)
            .expect("TLS callback entry should fit");
        mapped.write_u64(0x1c8, 0).expect("TLS callback terminator should fit");

        register_tls_callbacks(&parsed, &mapped).expect("TLS callbacks should register");
        invoke_process_attach_callbacks();

        assert_eq!(TLS_CALLBACK_REASON.load(Ordering::SeqCst), DLL_PROCESS_ATTACH);
        assert_eq!(TLS_CALLBACK_MODULE.load(Ordering::SeqCst), image_base);
        clear_registered_tls_callbacks();
    }
}
