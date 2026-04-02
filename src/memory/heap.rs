#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! HeapCreate/HeapAlloc/HeapFree emulation backed by tracked libc allocations.

use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{OnceLock, RwLock},
};
use tracing::warn;

use crate::utils::handle::{global_table, init_global_table, Handle, HandleObject};

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
        return 0;
    };

    if record.allocations.remove(&(memory as usize)).is_none() {
        return 0;
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
        warn!(heap, bytes = size, flags, "HeapReAlloc on unknown heap handle");
        return std::ptr::null_mut();
    };

    let Some(old_size) = record.allocations.get(&(memory as usize)).copied() else {
        warn!(heap, ptr = memory as usize, "HeapReAlloc on unknown allocation");
        return std::ptr::null_mut();
    };

    let ptr = unsafe { libc::realloc(memory, size) };
    if ptr.is_null() {
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
}
