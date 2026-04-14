#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! HeapCreate/HeapAlloc/HeapFree emulation backed by tracked libc allocations.

use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{OnceLock, RwLock},
};
use tracing::warn;

use crate::{
    runtime::telemetry,
    utils::handle::{global_table, init_global_table, Handle, HandleObject},
};

pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

#[derive(Debug)]
pub struct HeapHandleObject {
    pub handle: Handle,
    pub is_process_heap: bool,
}

impl HandleObject for HeapHandleObject {
    fn type_name(&self) -> &'static str {
        "HeapHandle"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Default)]
struct HeapRecord {
    initial_size: usize,
    maximum_size: usize,
    allocations: HashMap<usize, usize>,
}

#[derive(Debug, Default)]
struct HeapManager {
    process_heap: Option<Handle>,
    heaps: HashMap<Handle, HeapRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnknownPtrMode {
    Strict,
    Quarantine,
}

fn unknown_ptr_mode() -> UnknownPtrMode {
    match std::env::var("TUXEXE_HEAP_UNKNOWN_PTR_MODE") {
        Ok(value) if value.eq_ignore_ascii_case("strict") => UnknownPtrMode::Strict,
        // Compatibility default: some games pass foreign allocator pointers to HeapReAlloc.
        // Quarantine mode avoids crashing host libc::realloc on untracked pointers.
        _ => UnknownPtrMode::Quarantine,
    }
}

fn alloc_raw_with_flags(flags: u32, size: usize) -> *mut c_void {
    unsafe {
        if (flags & HEAP_ZERO_MEMORY) != 0 {
            libc::calloc(1, size)
        } else {
            libc::malloc(size)
        }
    }
}

fn should_quarantine_unknown_ptr(ptr: *mut c_void) -> bool {
    let addr = ptr as usize;
    // Very low values are obvious sentinels/invalid pointers from guest code.
    if addr < 0x1_0000 {
        return true;
    }

    // Non-canonical x86_64 virtual addresses cannot be valid host pointers.
    // Linux user-space canonical range upper bound used by this runtime.
    if addr >= 0x0000_8000_0000_0000usize {
        return true;
    }

    false
}

fn heap_manager() -> &'static RwLock<HeapManager> {
    static HEAPS: OnceLock<RwLock<HeapManager>> = OnceLock::new();
    HEAPS.get_or_init(|| RwLock::new(HeapManager::default()))
}

pub fn get_process_heap() -> Handle {
    init_global_table();

    if let Some(handle) = heap_manager().read().expect("heap manager poisoned").process_heap {
        return handle;
    }

    let handle =
        global_table().alloc(Box::new(HeapHandleObject { handle: 0, is_process_heap: true }));

    let mut manager = heap_manager().write().expect("heap manager poisoned");
    manager.process_heap = Some(handle);
    manager.heaps.insert(handle, HeapRecord::default());
    handle
}

pub fn heap_create(_options: u32, initial_size: usize, maximum_size: usize) -> Handle {
    init_global_table();
    let handle =
        global_table().alloc(Box::new(HeapHandleObject { handle: 0, is_process_heap: false }));

    heap_manager()
        .write()
        .expect("heap manager poisoned")
        .heaps
        .insert(handle, HeapRecord { initial_size, maximum_size, allocations: HashMap::new() });

    handle
}

pub fn heap_alloc(heap: Handle, flags: u32, bytes: usize) -> *mut c_void {
    let size = bytes.max(1);
    let mut manager = heap_manager().write().expect("heap manager poisoned");
    let Some(record) = manager.heaps.get_mut(&heap) else {
        warn!(heap, bytes = size, flags, "HeapAlloc on unknown heap handle");
        return std::ptr::null_mut();
    };

    let ptr = unsafe {
        if flags & HEAP_ZERO_MEMORY != 0 {
            libc::calloc(1, size)
        } else {
            libc::malloc(size)
        }
    };

    if ptr.is_null() {
        warn!(heap, bytes = size, flags, "HeapAlloc returned null");
        return std::ptr::null_mut();
    }

    record.allocations.insert(ptr as usize, size);
    ptr
}

pub fn heap_free(heap: Handle, _flags: u32, memory: *mut c_void) -> i32 {
    if memory.is_null() {
        return 1;
    }

    let mut manager = heap_manager().write().expect("heap manager poisoned");
    let Some(record) = manager.heaps.get_mut(&heap) else {
        telemetry::record(format!("heap_free_unknown_heap heap=0x{heap:x} ptr=0x{:x}", memory as usize));
        return 0;
    };

    if record.allocations.remove(&(memory as usize)).is_none() {
        telemetry::record(format!(
            "heap_free_unknown_ptr heap=0x{heap:x} ptr=0x{:x}",
            memory as usize
        ));
        // Compatibility-first behavior: some engines free pointers from mixed allocators.
        // Treat as no-op success to avoid cascading startup failures.
        warn!(
            heap,
            ptr = memory as usize,
            "HeapFree on unknown allocation; treating as no-op success"
        );
        return 1;
    }

    unsafe {
        libc::free(memory);
    }
    1
}

pub fn heap_size(heap: Handle, _flags: u32, memory: *const c_void) -> usize {
    if memory.is_null() {
        return usize::MAX;
    }

    heap_manager()
        .read()
        .expect("heap manager poisoned")
        .heaps
        .get(&heap)
        .and_then(|record| record.allocations.get(&(memory as usize)).copied())
        .unwrap_or(usize::MAX)
}

pub fn heap_realloc(heap: Handle, flags: u32, memory: *mut c_void, bytes: usize) -> *mut c_void {
    if memory.is_null() {
        return heap_alloc(heap, flags, bytes);
    }

    let size = bytes.max(1);
    let mut manager = heap_manager().write().expect("heap manager poisoned");
    let Some(record) = manager.heaps.get_mut(&heap) else {
        telemetry::record(format!(
            "heap_realloc_unknown_heap heap=0x{heap:x} ptr=0x{:x} bytes={size}",
            memory as usize
        ));
        warn!(heap, bytes = size, flags, "HeapReAlloc on unknown heap handle");
        return std::ptr::null_mut();
    };

    let Some(old_size) = record.allocations.get(&(memory as usize)).copied() else {
        telemetry::record(format!(
            "heap_realloc_unknown_ptr heap=0x{heap:x} ptr=0x{:x} bytes={size}",
            memory as usize
        ));

        match unknown_ptr_mode() {
            UnknownPtrMode::Strict => {
                warn!(
                    heap,
                    ptr = memory as usize,
                    bytes = size,
                    "HeapReAlloc on unknown allocation; rejecting unsafe realloc fallback"
                );
                return std::ptr::null_mut();
            }
            UnknownPtrMode::Quarantine => {
                if should_quarantine_unknown_ptr(memory) {
                    if std::env::var("TUXEXE_HEAP_REJECT_OBVIOUS_UNKNOWN_PTR")
                        .ok()
                        .is_some_and(|v| v == "1")
                    {
                        telemetry::record(format!(
                            "heap_realloc_quarantine_reject heap=0x{heap:x} ptr=0x{:x} bytes={size}",
                            memory as usize
                        ));
                        warn!(
                            heap,
                            ptr = memory as usize,
                            bytes = size,
                            "HeapReAlloc on obviously invalid pointer; rejecting per TUXEXE_HEAP_REJECT_OBVIOUS_UNKNOWN_PTR=1"
                        );
                        return std::ptr::null_mut();
                    }

                    telemetry::record(format!(
                        "heap_realloc_quarantine_synthetic heap=0x{heap:x} ptr=0x{:x} bytes={size}",
                        memory as usize
                    ));
                    warn!(
                        heap,
                        ptr = memory as usize,
                        bytes = size,
                        "HeapReAlloc on obviously invalid pointer; providing synthetic quarantine allocation"
                    );
                    let ptr = alloc_raw_with_flags(flags, size);
                    if ptr.is_null() {
                        telemetry::record(format!(
                            "heap_realloc_quarantine_null heap=0x{heap:x} ptr=0x{:x} bytes={size}",
                            memory as usize
                        ));
                        return std::ptr::null_mut();
                    }
                    record.allocations.insert(ptr as usize, size);
                    return ptr;
                }

                warn!(
                    heap,
                    ptr = memory as usize,
                    bytes = size,
                    "HeapReAlloc on unknown allocation; using quarantine alloc path"
                );
                let ptr = alloc_raw_with_flags(flags, size);
                if ptr.is_null() {
                    telemetry::record(format!(
                        "heap_realloc_quarantine_null heap=0x{heap:x} ptr=0x{:x} bytes={size}",
                        memory as usize
                    ));
                    return std::ptr::null_mut();
                }
                record.allocations.insert(ptr as usize, size);
                return ptr;
            }
        }
    };

    let ptr = unsafe { libc::realloc(memory, size) };
    if ptr.is_null() {
        telemetry::record(format!(
            "heap_realloc_null heap=0x{heap:x} ptr=0x{:x} old={old_size} new={size}",
            memory as usize
        ));
        warn!(heap, bytes = size, flags, old_size, "HeapReAlloc returned null");
        return std::ptr::null_mut();
    }

    record.allocations.remove(&(memory as usize));
    record.allocations.insert(ptr as usize, size);

    if (flags & HEAP_ZERO_MEMORY) != 0 && size > old_size {
        unsafe {
            std::ptr::write_bytes((ptr as *mut u8).add(old_size), 0, size - old_size);
        }
    }

    ptr
}

pub fn heap_destroy(heap: Handle) -> i32 {
    let process_heap = get_process_heap();
    if heap == process_heap {
        return 0;
    }

    let record = {
        let mut manager = heap_manager().write().expect("heap manager poisoned");
        manager.heaps.remove(&heap)
    };

    let Some(record) = record else {
        return 0;
    };

    for ptr in record.allocations.keys() {
        unsafe {
            libc::free(*ptr as *mut c_void);
        }
    }

    global_table().close_handle(heap);
    1
}

pub fn heap_contains(heap: Handle, ptr: *mut c_void) -> bool {
    heap_manager()
        .read()
        .expect("heap manager poisoned")
        .heaps
        .get(&heap)
        .map(|record| record.allocations.contains_key(&(ptr as usize)))
        .unwrap_or(false)
}

pub fn heap_info(heap: Handle) -> Option<(usize, usize, usize)> {
    heap_manager()
        .read()
        .expect("heap manager poisoned")
        .heaps
        .get(&heap)
        .map(|record| (record.initial_size, record.maximum_size, record.allocations.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn process_heap_is_stable() {
        let _guard = serial_guard();
        let first = get_process_heap();
        let second = get_process_heap();
        assert_eq!(first, second);
    }

    #[test]
    fn custom_heap_alloc_and_free_round_trip() {
        let _guard = serial_guard();
        let heap = heap_create(0, 1024, 4096);
        assert_ne!(heap, 0);

        let ptr = heap_alloc(heap, 0, 128);
        assert!(!ptr.is_null());
        assert!(heap_contains(heap, ptr));

        assert_eq!(heap_free(heap, 0, ptr), 1);
        assert!(!heap_contains(heap, ptr));
        assert_eq!(heap_destroy(heap), 1);
    }

    #[test]
    fn zero_memory_heap_allocation_is_cleared() {
        let _guard = serial_guard();
        let heap = get_process_heap();
        let ptr = heap_alloc(heap, HEAP_ZERO_MEMORY, 32);
        assert!(!ptr.is_null());

        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, 32) };
        assert!(bytes.iter().all(|byte| *byte == 0));

        assert_eq!(heap_free(heap, 0, ptr), 1);
    }

    #[test]
    fn heap_realloc_updates_tracked_size() {
        let _guard = serial_guard();
        let heap = get_process_heap();
        let ptr = heap_alloc(heap, 0, 16);
        assert!(!ptr.is_null());

        let grown = heap_realloc(heap, 0, ptr, 64);
        assert!(!grown.is_null());
        assert_eq!(heap_size(heap, 0, grown), 64);

        assert_eq!(heap_free(heap, 0, grown), 1);
    }

    #[test]
    fn heap_realloc_unknown_pointer_is_rejected() {
        let _guard = serial_guard();
        std::env::set_var("TUXEXE_HEAP_UNKNOWN_PTR_MODE", "strict");
        let heap = get_process_heap();

        let bogus = 0x1234usize as *mut c_void;
        let grown = heap_realloc(heap, 0, bogus, 64);
        assert!(grown.is_null());
        std::env::remove_var("TUXEXE_HEAP_UNKNOWN_PTR_MODE");
    }

    #[test]
    fn heap_realloc_unknown_heap_is_rejected() {
        let _guard = serial_guard();
        let ptr = unsafe { libc::malloc(16) };
        assert!(!ptr.is_null());

        let grown = heap_realloc(0xDEAD_BEEFu32, 0, ptr, 32);
        assert!(grown.is_null());

        unsafe { libc::free(ptr) };
    }

    #[test]
    fn quarantine_rejects_non_canonical_unknown_pointer() {
        let _guard = serial_guard();
        std::env::remove_var("TUXEXE_HEAP_UNKNOWN_PTR_MODE");
        std::env::set_var("TUXEXE_HEAP_REJECT_OBVIOUS_UNKNOWN_PTR", "1");
        let heap = get_process_heap();

        let bogus = 0x0ae64_b77e_88c8_000usize as *mut c_void;
        let grown = heap_realloc(heap, 0, bogus, 64);
        assert!(grown.is_null());

        std::env::remove_var("TUXEXE_HEAP_REJECT_OBVIOUS_UNKNOWN_PTR");
    }

    #[test]
    fn quarantine_allocates_for_non_canonical_unknown_pointer_by_default() {
        let _guard = serial_guard();
        std::env::remove_var("TUXEXE_HEAP_UNKNOWN_PTR_MODE");
        std::env::remove_var("TUXEXE_HEAP_REJECT_OBVIOUS_UNKNOWN_PTR");
        let heap = get_process_heap();

        let bogus = 0x0ae64_b77e_88c8_000usize as *mut c_void;
        let grown = heap_realloc(heap, 0, bogus, 64);
        assert!(!grown.is_null());
        assert_eq!(heap_size(heap, 0, grown), 64);
        assert_eq!(heap_free(heap, 0, grown), 1);
    }
}
