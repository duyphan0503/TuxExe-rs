//! Thread Local Storage slots backed by the current thread's TEB.

use std::{
    ffi::c_void,
    sync::{Mutex, OnceLock},
};

use tracing::{debug, info, trace, warn};

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

#[derive(Debug, Clone)]
struct RegisteredStaticTlsTemplate {
    image_base: usize,
    tls_index: u32,
    initial_data: Vec<u8>,
}

fn slot_allocator() -> &'static Mutex<Vec<bool>> {
    static ALLOCATOR: OnceLock<Mutex<Vec<bool>>> = OnceLock::new();
    ALLOCATOR.get_or_init(|| Mutex::new(vec![false; TLS_SLOT_COUNT]))
}

fn tls_callbacks_cell() -> &'static Mutex<Vec<RegisteredTlsCallbacks>> {
    static CALLBACKS: OnceLock<Mutex<Vec<RegisteredTlsCallbacks>>> = OnceLock::new();
    CALLBACKS.get_or_init(|| Mutex::new(Vec::new()))
}

fn static_tls_templates_cell() -> &'static Mutex<Vec<RegisteredStaticTlsTemplate>> {
    static TEMPLATES: OnceLock<Mutex<Vec<RegisteredStaticTlsTemplate>>> = OnceLock::new();
    TEMPLATES.get_or_init(|| Mutex::new(Vec::new()))
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

    let mut teb_ptr = teb::current_teb_ptr();
    if teb_ptr.is_null() {
        let _ = teb::attach_spawned_thread();
        teb_ptr = teb::current_teb_ptr();
    }
    if teb_ptr.is_null() {
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

pub fn tls_get_value(index: u32) -> *mut c_void {
    let index = index as usize;
    if index >= TLS_SLOT_COUNT {
        return std::ptr::null_mut();
    }

    let mut teb_ptr = teb::current_teb_ptr();
    if teb_ptr.is_null() {
        let _ = teb::attach_spawned_thread();
        teb_ptr = teb::current_teb_ptr();
    }
    if teb_ptr.is_null() {
        return std::ptr::null_mut();
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

fn read_pointer(mapped: &MappedImage, rva: usize, is_pe64: bool) -> Option<usize> {
    if is_pe64 {
        mapped.read_u64(rva).map(|value| value as usize)
    } else {
        mapped.read_u32(rva).map(|value| value as usize)
    }
}

fn tls_callback_addresses(pe: &ParsedPe, mapped: &MappedImage) -> Result<Vec<usize>, String> {
    let Some(directory) = pe.tls_dir.filter(|dir| dir.virtual_address != 0 && dir.size > 0) else {
        return Ok(Vec::new());
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
        return Ok(Vec::new());
    }

    let callbacks_rva = callbacks_va.checked_sub(mapped.base_addr()).ok_or_else(|| {
        format!(
            "TLS callback table VA 0x{callbacks_va:x} is below image base 0x{:x}",
            mapped.base_addr()
        )
    })?;
    let ptr_size = if pe.is_pe64 { 8 } else { 4 };
    let mut callbacks = Vec::new();
    for index in 0..=256 {
        let entry_rva = callbacks_rva
            .checked_add(index * ptr_size)
            .ok_or_else(|| "TLS callback table address overflow".to_string())?;
        let callback = read_pointer(mapped, entry_rva, pe.is_pe64)
            .ok_or_else(|| format!("TLS callback entry OOB at RVA 0x{entry_rva:x}"))?;
        if callback == 0 {
            return Ok(callbacks);
        }
        callbacks.push(callback);
    }

    Err("TLS callback table exceeded 256 entries without terminator".into())
}

pub fn initialize_static_tls(pe: &ParsedPe, mapped: &mut MappedImage) -> Result<(), String> {
    let Some(directory) = pe.tls_dir.filter(|dir| dir.virtual_address != 0 && dir.size > 0) else {
        return Ok(());
    };

    let directory_rva = directory.virtual_address as usize;
    let image_base = mapped.base_addr();

    let (start_raw_va, end_raw_va, address_of_index_va, size_of_zero_fill) =
        if pe.is_pe64 {
            let start_raw_va = mapped.read_u64(directory_rva).ok_or_else(|| {
                format!("TLS StartAddressOfRawData OOB at RVA 0x{directory_rva:x}")
            })? as usize;
            let end_raw_va = mapped.read_u64(directory_rva + 8).ok_or_else(|| {
                format!("TLS EndAddressOfRawData OOB at RVA 0x{:x}", directory_rva + 8)
            })? as usize;
            let address_of_index_va = mapped.read_u64(directory_rva + 16).ok_or_else(|| {
                format!("TLS AddressOfIndex OOB at RVA 0x{:x}", directory_rva + 16)
            })? as usize;
            let size_of_zero_fill = mapped.read_u32(directory_rva + 32).unwrap_or(0) as usize;
            (start_raw_va, end_raw_va, address_of_index_va, size_of_zero_fill)
        } else {
            let start_raw_va = mapped.read_u32(directory_rva).ok_or_else(|| {
                format!("TLS StartAddressOfRawData OOB at RVA 0x{directory_rva:x}")
            })? as usize;
            let end_raw_va = mapped.read_u32(directory_rva + 4).ok_or_else(|| {
                format!("TLS EndAddressOfRawData OOB at RVA 0x{:x}", directory_rva + 4)
            })? as usize;
            let address_of_index_va = mapped
                .read_u32(directory_rva + 8)
                .ok_or_else(|| format!("TLS AddressOfIndex OOB at RVA 0x{:x}", directory_rva + 8))?
                as usize;
            let size_of_zero_fill = mapped.read_u32(directory_rva + 16).unwrap_or(0) as usize;
            (start_raw_va, end_raw_va, address_of_index_va, size_of_zero_fill)
        };

    let raw_size = end_raw_va.checked_sub(start_raw_va).ok_or_else(|| {
        format!("TLS raw range invalid: start=0x{start_raw_va:x}, end=0x{end_raw_va:x}")
    })?;
    let total_size = raw_size.saturating_add(size_of_zero_fill);

    let tls_index = tls_alloc();
    if tls_index == TLS_OUT_OF_INDEXES {
        return Err("TLS slot allocator exhausted while initializing static TLS".into());
    }

    let address_of_index_rva = address_of_index_va.checked_sub(image_base).ok_or_else(|| {
        format!(
            "TLS AddressOfIndex VA 0x{address_of_index_va:x} is below image base 0x{image_base:x}"
        )
    })?;
    mapped
        .write_u32(address_of_index_rva, tls_index)
        .ok_or_else(|| format!("TLS AddressOfIndex write OOB at RVA 0x{address_of_index_rva:x}"))?;

    let mut initial_data = vec![0u8; total_size];
    if raw_size > 0 {
        let start_raw_rva = start_raw_va
            .checked_sub(image_base)
            .ok_or_else(|| format!("TLS StartAddressOfRawData VA 0x{start_raw_va:x} is below image base 0x{image_base:x}"))?;
        let template = mapped.slice_at(start_raw_rva, raw_size).ok_or_else(|| {
            format!("TLS raw template OOB at RVA 0x{start_raw_rva:x}, size=0x{raw_size:x}")
        })?;
        initial_data[..raw_size].copy_from_slice(template);
    }

    let template =
        RegisteredStaticTlsTemplate { image_base, tls_index, initial_data: initial_data.clone() };
    {
        let mut templates =
            static_tls_templates_cell().lock().expect("static TLS template registry poisoned");
        templates.push(template.clone());
    }

    let managed_tebs = teb::managed_teb_pointers();
    if managed_tebs.is_empty() {
        ensure_current_thread_teb();
        if let Some(current_teb) = teb::with_current_teb(|teb| teb as *mut teb::Teb) {
            assign_template_to_teb(&template, current_teb);
        }
    } else {
        for teb_ptr in managed_tebs {
            assign_template_to_teb(&template, teb_ptr);
        }
    }

    ensure_current_thread_teb();
    if tls_get_value(tls_index).is_null() {
        let tls_block_ptr = allocate_tls_block(&initial_data);
        if !tls_set_value(tls_index, tls_block_ptr) {
            return Err(format!("Failed to set TLS slot {} for current thread", tls_index));
        }
    }

    info!(
        image_base = format_args!("0x{image_base:x}"),
        tls_index,
        raw_size,
        size_of_zero_fill,
        total_size,
        "Initialized PE static TLS template for current thread"
    );

    Ok(())
}

fn allocate_tls_block(initial_data: &[u8]) -> *mut c_void {
    if initial_data.is_empty() {
        return std::ptr::null_mut();
    }
    let block = initial_data.to_vec().into_boxed_slice();
    Box::into_raw(block) as *mut c_void
}

fn assign_template_to_teb(template: &RegisteredStaticTlsTemplate, teb_ptr: *mut teb::Teb) {
    if teb_ptr.is_null() {
        return;
    }
    let index = template.tls_index as usize;
    if teb::teb_tls_value(teb_ptr, index).is_null() {
        let block = allocate_tls_block(&template.initial_data);
        let _ = teb::set_teb_tls_value(teb_ptr, index, block);
        debug!(
            teb = format_args!("{teb_ptr:p}"),
            image_base = format_args!("0x{:x}", template.image_base),
            tls_index = template.tls_index,
            size = template.initial_data.len(),
            "Assigned static TLS template to managed thread"
        );
    }
}

pub fn initialize_static_tls_for_current_thread() {
    let templates =
        static_tls_templates_cell().lock().expect("static TLS template registry poisoned").clone();

    if templates.is_empty() {
        return;
    }

    ensure_current_thread_teb();
    for template in templates {
        if tls_get_value(template.tls_index).is_null() {
            let block = allocate_tls_block(&template.initial_data);
            let _ = tls_set_value(template.tls_index, block);
            trace!(
                image_base = format_args!("0x{:x}", template.image_base),
                tls_index = template.tls_index,
                size = template.initial_data.len(),
                "Initialized static TLS template for attached thread"
            );
        } else {
            trace!(
                image_base = format_args!("0x{:x}", template.image_base),
                tls_index = template.tls_index,
                "Skipped static TLS init for attached thread (slot already set)"
            );
        }
    }
}

pub fn register_tls_callbacks(pe: &ParsedPe, mapped: &MappedImage) -> Result<(), String> {
    let callbacks = tls_callback_addresses(pe, mapped)?;
    if callbacks.is_empty() {
        return Ok(());
    }

    let image_base = mapped.base_addr();
    info!(
        count = callbacks.len(),
        image_base = format_args!("0x{image_base:x}"),
        "Registered PE TLS callbacks"
    );
    let mut registered = tls_callbacks_cell().lock().expect("TLS callback registry poisoned");
    if let Some(existing) = registered.iter_mut().find(|entry| entry.image_base == image_base) {
        existing.callbacks = callbacks;
    } else {
        registered.push(RegisteredTlsCallbacks { image_base, callbacks });
    }
    Ok(())
}

/// Execute callbacks belonging to a loaded PE image. Dependency callbacks
/// cannot use the single main-image registry because loading another DLL would
/// replace it before its PROCESS_ATTACH phase runs.
pub fn invoke_tls_callbacks_for(
    pe: &ParsedPe,
    mapped: &MappedImage,
    reason: u32,
) -> Result<(), String> {
    let callbacks = tls_callback_addresses(pe, mapped)?;
    if callbacks.is_empty() {
        return Ok(());
    }

    debug!(
        count = callbacks.len(),
        image_base = format_args!("0x{:x}", mapped.base_addr()),
        "Executing PE TLS PROCESS_ATTACH callbacks"
    );

    for callback_addr in callbacks {
        trace!(
            callback = format_args!("0x{callback_addr:x}"),
            reason,
            image_base = format_args!("0x{:x}", mapped.base_addr()),
            "Invoking PE TLS callback"
        );
        crate::runtime::guest_stack::invoke_status(
            callback_addr,
            mapped.base_addr() as *mut c_void,
            reason,
            std::ptr::null_mut(),
        )
        .map_err(|error| format!("TLS callback stack transition failed: {error}"))?;
    }
    Ok(())
}

fn invoke_registered_tls_callbacks(reason: u32) {
    let registered = tls_callbacks_cell().lock().expect("TLS callback registry poisoned").clone();

    for module in registered {
        for callback_addr in module.callbacks {
            trace!(
                callback = format_args!("0x{callback_addr:x}"),
                image_base = format_args!("0x{:x}", module.image_base),
                reason,
                "Invoking PE TLS callback"
            );
            let callback: TlsCallback = unsafe { std::mem::transmute(callback_addr) };
            let result = std::panic::catch_unwind(|| unsafe {
                callback(module.image_base as *mut c_void, reason, std::ptr::null_mut());
            });
            if result.is_err() {
                warn!(
                    callback = format_args!("0x{callback_addr:x}"),
                    reason, "PE TLS callback panicked while executing"
                );
            }
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
    tls_callbacks_cell().lock().expect("TLS callback registry poisoned").clear();
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
            .write_u64(0x1c0, test_tls_callback as *const () as usize as u64)
            .expect("TLS callback entry should fit");
        mapped.write_u64(0x1c8, 0).expect("TLS callback terminator should fit");

        register_tls_callbacks(&parsed, &mapped).expect("TLS callbacks should register");
        invoke_process_attach_callbacks();

        assert_eq!(TLS_CALLBACK_REASON.load(Ordering::SeqCst), DLL_PROCESS_ATTACH);
        assert_eq!(TLS_CALLBACK_MODULE.load(Ordering::SeqCst), image_base);
        clear_registered_tls_callbacks();
    }
}
