#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery emulation.

use std::{
    collections::BTreeMap,
    ffi::c_void,
    ptr,
    sync::{OnceLock, RwLock},
};

use tracing::trace;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_DECOMMIT: u32 = 0x4000;
pub const MEM_RELEASE: u32 = 0x8000;

pub const MEM_PRIVATE: u32 = 0x20000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationInfo {
    pub base_address: usize,
    pub size: usize,
    pub allocation_type: u32,
    pub protect: u32,
    pub state: u32,
    pub type_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub type_flags: u32,
}

fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if raw <= 0 {
            4096
        } else {
            raw as usize
        }
    })
}

fn allocation_registry() -> &'static RwLock<BTreeMap<usize, AllocationInfo>> {
    static REGISTRY: OnceLock<RwLock<BTreeMap<usize, AllocationInfo>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(BTreeMap::new()))
}

fn align_up(value: usize) -> usize {
    let page = page_size();
    if value == 0 {
        page
    } else {
        let rem = value % page;
        if rem == 0 {
            value
        } else {
            value + (page - rem)
        }
    }
}

fn align_down(value: usize) -> usize {
    value - (value % page_size())
}

fn page_protect_to_native(protect: u32) -> libc::c_int {
    match protect {
        PAGE_NOACCESS => libc::PROT_NONE,
        PAGE_READONLY => libc::PROT_READ,
        PAGE_READWRITE => libc::PROT_READ | libc::PROT_WRITE,
        PAGE_EXECUTE => libc::PROT_EXEC,
        PAGE_EXECUTE_READ => libc::PROT_READ | libc::PROT_EXEC,
        PAGE_EXECUTE_READWRITE => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

fn find_allocation(address: usize) -> Option<AllocationInfo> {
    let guard = allocation_registry().read().expect("virtual allocation registry poisoned");
    let (_, info) = guard.range(..=address).next_back()?;
    if address < info.base_address + info.size {
        Some(info.clone())
    } else {
        None
    }
}

pub fn query_allocation(address: usize) -> Option<AllocationInfo> {
    find_allocation(address)
}

pub fn virtual_alloc(
    address: *mut c_void,
    size: usize,
    allocation_type: u32,
    protect: u32,
) -> *mut c_void {
    if size == 0 || allocation_type & (MEM_RESERVE | MEM_COMMIT) == 0 {
        return ptr::null_mut();
    }

    let aligned_size = align_up(size);
    let requested = address as usize;

    if allocation_type & MEM_RESERVE != 0 {
        let native_protect = if allocation_type & MEM_COMMIT != 0 {
            page_protect_to_native(protect)
        } else {
            libc::PROT_NONE
        };

        let mapped = unsafe {
            libc::mmap(
                address,
                aligned_size,
                native_protect,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mapped == libc::MAP_FAILED {
            return ptr::null_mut();
        }

        let actual = mapped as usize;
        let state = if allocation_type & MEM_COMMIT != 0 { MEM_COMMIT } else { MEM_RESERVE };

        allocation_registry().write().expect("virtual allocation registry poisoned").insert(
            actual,
            AllocationInfo {
                base_address: actual,
                size: aligned_size,
                allocation_type,
                protect: if state == MEM_COMMIT { protect } else { PAGE_NOACCESS },
                state,
                type_flags: MEM_PRIVATE,
            },
        );

        trace!(
            requested = format_args!("0x{requested:x}"),
            actual = format_args!("0x{actual:x}"),
            size = aligned_size,
            allocation_type,
            protect,
            "VirtualAlloc reserved new region"
        );
        return mapped;
    }

    let Some(mut info) = find_allocation(requested) else {
        let mapped = unsafe {
            libc::mmap(
                address,
                aligned_size,
                page_protect_to_native(protect),
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mapped == libc::MAP_FAILED {
            return ptr::null_mut();
        }

        let actual = mapped as usize;
        allocation_registry().write().expect("virtual allocation registry poisoned").insert(
            actual,
            AllocationInfo {
                base_address: actual,
                size: aligned_size,
                allocation_type,
                protect,
                state: MEM_COMMIT,
                type_flags: MEM_PRIVATE,
            },
        );
        return mapped;
    };

    let commit_address = if requested == 0 { info.base_address } else { align_down(requested) };
    let commit_size = if requested == 0 {
        info.size
    } else {
        align_up(aligned_size + (requested - commit_address))
    };

    let ret = unsafe {
        libc::mprotect(commit_address as *mut c_void, commit_size, page_protect_to_native(protect))
    };
    if ret != 0 {
        return ptr::null_mut();
    }

    info.state = MEM_COMMIT;
    info.protect = protect;
    allocation_registry()
        .write()
        .expect("virtual allocation registry poisoned")
        .insert(info.base_address, info);

    trace!(
        address = format_args!("0x{commit_address:x}"),
        size = commit_size,
        protect,
        "VirtualAlloc committed existing region"
    );
    commit_address as *mut c_void
}

pub fn virtual_free(address: *mut c_void, size: usize, free_type: u32) -> i32 {
    if address.is_null() {
        return 0;
    }

    let key = address as usize;
    let Some(mut info) = find_allocation(key) else {
        return 0;
    };

    if free_type & MEM_RELEASE != 0 {
        let release_size = if size == 0 { info.size } else { align_up(size) };
        let status = unsafe { libc::munmap(info.base_address as *mut c_void, release_size) };
        if status != 0 {
            return 0;
        }

        allocation_registry()
            .write()
            .expect("virtual allocation registry poisoned")
            .remove(&info.base_address);
        return 1;
    }

    if free_type & MEM_DECOMMIT != 0 {
        let decommit_size = if size == 0 { info.size } else { align_up(size) };
        let decommit_base = align_down(key);
        let status =
            unsafe { libc::mprotect(decommit_base as *mut c_void, decommit_size, libc::PROT_NONE) };
        if status != 0 {
            return 0;
        }

        info.state = MEM_RESERVE;
        info.protect = PAGE_NOACCESS;
        allocation_registry()
            .write()
            .expect("virtual allocation registry poisoned")
            .insert(info.base_address, info);
        return 1;
    }

    0
}

pub fn virtual_protect(
    address: *mut c_void,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if address.is_null() || size == 0 {
        return 0;
    }

    let aligned_address = align_down(address as usize);
    let aligned_size = align_up(size + ((address as usize) - aligned_address));
    let Some(mut info) = find_allocation(aligned_address) else {
        return 0;
    };

    let previous = info.protect;
    let status = unsafe {
        libc::mprotect(
            aligned_address as *mut c_void,
            aligned_size,
            page_protect_to_native(new_protect),
        )
    };
    if status != 0 {
        return 0;
    }

    if !old_protect.is_null() {
        unsafe {
            *old_protect = previous;
        }
    }

    info.protect = new_protect;
    info.state = MEM_COMMIT;
    allocation_registry()
        .write()
        .expect("virtual allocation registry poisoned")
        .insert(info.base_address, info);
    1
}

pub fn virtual_query(
    address: *const c_void,
    buffer: *mut MemoryBasicInformation,
    length: usize,
) -> usize {
    if address.is_null()
        || buffer.is_null()
        || length < std::mem::size_of::<MemoryBasicInformation>()
    {
        return 0;
    }

    let Some(info) = find_allocation(address as usize) else {
        return 0;
    };

    unsafe {
        *buffer = MemoryBasicInformation {
            base_address: info.base_address as *mut c_void,
            allocation_base: info.base_address as *mut c_void,
            allocation_protect: info.protect,
            region_size: info.size,
            state: info.state,
            protect: info.protect,
            type_flags: info.type_flags,
        };
    }

    std::mem::size_of::<MemoryBasicInformation>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn reserve_commit_protect_and_release_round_trip() {
        let _guard = serial_guard();
        let ptr = virtual_alloc(ptr::null_mut(), 4096, MEM_RESERVE, PAGE_NOACCESS);
        assert!(!ptr.is_null());

        let info = query_allocation(ptr as usize).expect("allocation should exist");
        assert_eq!(info.state, MEM_RESERVE);
        assert_eq!(info.protect, PAGE_NOACCESS);

        let committed = virtual_alloc(ptr, 4096, MEM_COMMIT, PAGE_READWRITE);
        assert_eq!(committed, ptr);

        unsafe {
            *(ptr as *mut u32) = 0xfeed_beef;
            assert_eq!(*(ptr as *mut u32), 0xfeed_beef);
        }

        let mut old = 0;
        assert_eq!(virtual_protect(ptr, 4096, PAGE_READONLY, &mut old), 1);
        assert_eq!(old, PAGE_READWRITE);

        let mut mbi = MemoryBasicInformation::default();
        assert_eq!(
            virtual_query(ptr, &mut mbi, std::mem::size_of::<MemoryBasicInformation>()),
            std::mem::size_of::<MemoryBasicInformation>()
        );
        assert_eq!(mbi.state, MEM_COMMIT);
        assert_eq!(mbi.protect, PAGE_READONLY);

        assert_eq!(virtual_free(ptr, 0, MEM_RELEASE), 1);
        assert!(query_allocation(ptr as usize).is_none());
    }

    #[test]
    fn decommit_preserves_mapping_but_marks_reserved() {
        let _guard = serial_guard();
        let ptr = virtual_alloc(ptr::null_mut(), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        assert!(!ptr.is_null());

        assert_eq!(virtual_free(ptr, 4096, MEM_DECOMMIT), 1);
        let info = query_allocation(ptr as usize).expect("allocation should still exist");
        assert_eq!(info.state, MEM_RESERVE);
        assert_eq!(info.protect, PAGE_NOACCESS);

        assert_eq!(virtual_free(ptr, 0, MEM_RELEASE), 1);
    }
}
