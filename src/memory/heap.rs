#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! HeapCreate/HeapAlloc/HeapFree emulation backed by the host process heap.

use std::{
    ffi::c_void,
    sync::{OnceLock, RwLock},
};

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
struct HeapManager {
    process_heap: Option<Handle>,
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
    handle
}

pub fn heap_create(_options: u32, _initial_size: usize, _maximum_size: usize) -> Handle {
    init_global_table();
    global_table().alloc(Box::new(HeapHandleObject { handle: 0, is_process_heap: false }))
}

static ALLOCATED_PTRS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<usize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

#[inline(always)]
pub fn heap_alloc(_heap: Handle, flags: u32, bytes: usize) -> *mut c_void {
    let size = if bytes == 0 { 1 } else { bytes };
    let ptr = unsafe {
        if flags & HEAP_ZERO_MEMORY != 0 {
            libc::calloc(1, size)
        } else {
            libc::malloc(size)
        }
    };
    if !ptr.is_null() {
        ALLOCATED_PTRS.lock().unwrap().insert(ptr as usize);
    }
    ptr
}

#[inline(always)]
pub fn heap_free(_heap: Handle, _flags: u32, memory: *mut c_void) -> i32 {
    if memory.is_null() {
        return 1;
    }
    let was_present = ALLOCATED_PTRS.lock().unwrap().remove(&(memory as usize));
    if was_present {
        unsafe { libc::free(memory) };
    }
    1
}

pub fn heap_size(_heap: Handle, _flags: u32, memory: *const c_void) -> usize {
    if memory.is_null() {
        return usize::MAX;
    }
    unsafe { libc::malloc_usable_size(memory.cast_mut()) }
}

pub fn heap_realloc(_heap: Handle, flags: u32, memory: *mut c_void, bytes: usize) -> *mut c_void {
    if memory.is_null() {
        return heap_alloc(_heap, flags, bytes);
    }

    let size = if bytes == 0 { 1 } else { bytes };
    let mut set = ALLOCATED_PTRS.lock().unwrap();
    let was_present = set.remove(&(memory as usize));
    if !was_present {
        drop(set);
        return heap_alloc(_heap, flags, size);
    }

    let old_size = unsafe { libc::malloc_usable_size(memory) };
    let new_ptr = unsafe {
        if flags & HEAP_ZERO_MEMORY != 0 {
            libc::calloc(1, size)
        } else {
            libc::malloc(size)
        }
    };
    if !new_ptr.is_null() {
        if old_size > 0 {
            unsafe {
                libc::memcpy(new_ptr, memory, old_size.min(size));
            }
        }
        unsafe {
            libc::free(memory);
        }
        set.insert(new_ptr as usize);
    }
    new_ptr
}

pub fn heap_destroy(heap: Handle) -> i32 {
    let process_heap = get_process_heap();
    if heap == process_heap {
        return 0;
    }
    global_table().close_handle(heap);
    1
}

pub fn heap_contains(_heap: Handle, ptr: *mut c_void) -> bool {
    !ptr.is_null()
}

pub fn heap_info(_heap: Handle) -> Option<(usize, usize, usize)> {
    Some((0, 0, 0))
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
        assert!(heap_size(heap, 0, grown) >= 64);

        assert_eq!(heap_free(heap, 0, grown), 1);
    }
}
