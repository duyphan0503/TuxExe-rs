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
pub const MEM_FREE: u32 = 0x10000;

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
    pub allocation_base: usize,
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

fn host_mapping_cache() -> &'static RwLock<Vec<AllocationInfo>> {
    static CACHE: OnceLock<RwLock<Vec<AllocationInfo>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(Vec::new()))
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

fn allocation_bounds(
    registry: &BTreeMap<usize, AllocationInfo>,
    allocation_base: usize,
) -> Option<(usize, usize)> {
    let mut start = usize::MAX;
    let mut end = 0usize;

    for info in registry.values().filter(|info| info.allocation_base == allocation_base) {
        start = start.min(info.base_address);
        end = end.max(info.base_address.checked_add(info.size)?);
    }

    (start == allocation_base && end > start).then_some((start, end))
}

fn allocation_covers_range(
    registry: &BTreeMap<usize, AllocationInfo>,
    allocation_base: usize,
    range_start: usize,
    range_end: usize,
) -> bool {
    if range_start >= range_end {
        return false;
    }

    let mut cursor = range_start;
    for info in registry.values().filter(|info| info.allocation_base == allocation_base) {
        let Some(info_end) = info.base_address.checked_add(info.size) else {
            return false;
        };
        if info_end <= cursor {
            continue;
        }
        if info.base_address > cursor {
            return false;
        }
        cursor = info_end;
        if cursor >= range_end {
            return true;
        }
    }

    false
}

/// Split every tracked segment intersecting `range` and apply its new Windows
/// state.  A reservation must retain its uncommitted segments: callers such
/// as Boehm GC enumerate regions through VirtualQuery and will dereference
/// every range advertised as MEM_COMMIT/PAGE_READWRITE.
fn update_allocation_range(
    registry: &mut BTreeMap<usize, AllocationInfo>,
    allocation_base: usize,
    range_start: usize,
    range_end: usize,
    state: u32,
    protect: u32,
) -> bool {
    if !allocation_covers_range(registry, allocation_base, range_start, range_end) {
        return false;
    }

    let keys: Vec<usize> = registry
        .iter()
        .filter_map(|(base, info)| {
            let end = info.base_address.checked_add(info.size)?;
            (info.allocation_base == allocation_base
                && info.base_address < range_end
                && range_start < end)
                .then_some(*base)
        })
        .collect();

    for key in keys {
        let Some(info) = registry.remove(&key) else {
            return false;
        };
        let info_end = info.base_address + info.size;
        let changed_start = info.base_address.max(range_start);
        let changed_end = info_end.min(range_end);

        if info.base_address < changed_start {
            registry.insert(
                info.base_address,
                AllocationInfo { size: changed_start - info.base_address, ..info.clone() },
            );
        }

        registry.insert(
            changed_start,
            AllocationInfo {
                base_address: changed_start,
                size: changed_end - changed_start,
                state,
                protect,
                ..info.clone()
            },
        );

        if changed_end < info_end {
            registry.insert(
                changed_end,
                AllocationInfo { base_address: changed_end, size: info_end - changed_end, ..info },
            );
        }
    }

    true
}

/// Return the Linux mapping containing `address` when it was not created by
/// `VirtualAlloc`.  The loader, guest stack and JIT code are all backed by
/// native mappings, but are still observable through Windows `VirtualQuery`.
fn parse_host_mappings() -> Option<Vec<AllocationInfo>> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut mappings = Vec::new();

    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else { continue };
        let Some(permissions) = fields.next() else { continue };
        let Some((start, end)) = range.split_once('-') else { continue };
        let Ok(base_address) = usize::from_str_radix(start, 16) else { continue };
        let Ok(end_address) = usize::from_str_radix(end, 16) else { continue };
        if end_address <= base_address {
            continue;
        }

        let readable = permissions.as_bytes().first() == Some(&b'r');
        let writable = permissions.as_bytes().get(1) == Some(&b'w');
        let executable = permissions.as_bytes().get(2) == Some(&b'x');
        let protect = match (readable, writable, executable) {
            (false, false, false) => PAGE_NOACCESS,
            (false, false, true) => PAGE_EXECUTE,
            (true, false, false) => PAGE_READONLY,
            (true, false, true) => PAGE_EXECUTE_READ,
            (_, true, true) => PAGE_EXECUTE_READWRITE,
            (_, true, false) => PAGE_READWRITE,
        };

        let state = if protect == PAGE_NOACCESS { MEM_RESERVE } else { MEM_COMMIT };
        mappings.push(AllocationInfo {
            base_address,
            allocation_base: base_address,
            size: end_address - base_address,
            allocation_type: state,
            protect,
            state,
            type_flags: MEM_PRIVATE,
        });
    }

    Some(mappings)
}

fn mapping_containing(mappings: &[AllocationInfo], address: usize) -> Option<AllocationInfo> {
    mappings
        .iter()
        .find(|mapping| {
            mapping
                .base_address
                .checked_add(mapping.size)
                .is_some_and(|end| (mapping.base_address..end).contains(&address))
        })
        .cloned()
}

fn free_region_containing(mappings: &[AllocationInfo], address: usize) -> Option<AllocationInfo> {
    const USER_ADDRESS_LIMIT: usize = 0x0000_8000_0000_0000;
    if address >= USER_ADDRESS_LIMIT {
        return None;
    }

    let mut free_start = 0usize;
    for mapping in mappings {
        if address < mapping.base_address {
            return (free_start < mapping.base_address).then_some(AllocationInfo {
                base_address: free_start,
                allocation_base: 0,
                size: mapping.base_address - free_start,
                allocation_type: 0,
                protect: 0,
                state: MEM_FREE,
                type_flags: 0,
            });
        }
        free_start = free_start.max(mapping.base_address.checked_add(mapping.size)?);
    }

    (free_start < USER_ADDRESS_LIMIT).then_some(AllocationInfo {
        base_address: free_start,
        allocation_base: 0,
        size: USER_ADDRESS_LIMIT - free_start,
        allocation_type: 0,
        protect: 0,
        state: MEM_FREE,
        type_flags: 0,
    })
}

fn invalidate_host_mapping_cache() {
    if let Ok(mut cache) = host_mapping_cache().write() {
        cache.clear();
    }
}

/// Return the Linux mapping containing `address` when it was not created by
/// `VirtualAlloc`.  `/proc/self/maps` is a slow filesystem parse and Mono
/// probes memory layout heavily, so refresh the process snapshot when an
/// address is not in the active snapshot.
fn find_host_mapping(address: usize) -> Option<AllocationInfo> {
    {
        let cache = host_mapping_cache().read().expect("host mapping cache poisoned");
        if let Some(hit) = mapping_containing(&cache, address) {
            return Some(hit);
        }
    }

    let mappings = parse_host_mappings()?;
    let found = mapping_containing(&mappings, address)
        .or_else(|| free_region_containing(&mappings, address));
    *host_mapping_cache().write().expect("host mapping cache poisoned") = mappings;
    found
}

/// Publish a native mapping that was created outside `VirtualAlloc` to the
/// guest-visible virtual-memory model.  This is used for launcher-managed
/// stacks, whose guard page and allocation base must remain observable via
/// `VirtualQuery` even when Linux coalesces adjacent anonymous VMAs.
pub fn register_native_allocation(
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    size: usize,
    protect: u32,
) -> bool {
    if base_address.is_null() || allocation_base.is_null() || size == 0 {
        return false;
    }

    let base_address = base_address as usize;
    let allocation_base = allocation_base as usize;
    let Some(end) = base_address.checked_add(size) else {
        return false;
    };
    if allocation_base > base_address || end <= base_address {
        return false;
    }

    allocation_registry().write().expect("virtual allocation registry poisoned").insert(
        base_address,
        AllocationInfo {
            base_address,
            allocation_base,
            size,
            allocation_type: MEM_RESERVE | MEM_COMMIT,
            protect,
            state: MEM_COMMIT,
            type_flags: MEM_PRIVATE,
        },
    );
    invalidate_host_mapping_cache();
    true
}

pub fn unregister_native_allocation(base_address: *mut c_void) {
    if !base_address.is_null() {
        allocation_registry()
            .write()
            .expect("virtual allocation registry poisoned")
            .remove(&(base_address as usize));
        invalidate_host_mapping_cache();
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

    // Case 1: address is NULL -> System chooses address, reserves and optionally commits
    if requested == 0 {
        let native_protect = if allocation_type & MEM_COMMIT != 0 {
            page_protect_to_native(protect)
        } else {
            libc::PROT_NONE
        };

        let mapped = unsafe {
            libc::mmap(
                ptr::null_mut(),
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
                allocation_base: actual,
                size: aligned_size,
                allocation_type,
                protect: if state == MEM_COMMIT { protect } else { PAGE_NOACCESS },
                state,
                type_flags: MEM_PRIVATE,
            },
        );
        invalidate_host_mapping_cache();

        trace!(
            actual = format_args!("0x{actual:x}"),
            size = aligned_size,
            allocation_type,
            protect,
            "VirtualAlloc reserved new region"
        );
        return mapped;
    }

    // Case 2: address != NULL and MEM_RESERVE is requested
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
                allocation_base: actual,
                size: aligned_size,
                allocation_type,
                protect: if state == MEM_COMMIT { protect } else { PAGE_NOACCESS },
                state,
                type_flags: MEM_PRIVATE,
            },
        );
        invalidate_host_mapping_cache();

        trace!(
            requested = format_args!("0x{requested:x}"),
            actual = format_args!("0x{actual:x}"),
            size = aligned_size,
            allocation_type,
            protect,
            "VirtualAlloc reserved at requested address"
        );
        return mapped;
    }

    // Case 3: address != NULL and ONLY MEM_COMMIT (commit within existing region)
    let commit_address = align_down(requested);
    let commit_size = align_up(size + (requested - commit_address));
    let Some(commit_end) = commit_address.checked_add(commit_size) else {
        return ptr::null_mut();
    };

    if let Some(info) = find_allocation(requested) {
        {
            let registry = allocation_registry().read().expect("virtual allocation registry poisoned");
            if !allocation_covers_range(&registry, info.allocation_base, commit_address, commit_end) {
                return ptr::null_mut();
            }
        }

        let ret = unsafe {
            libc::mprotect(commit_address as *mut c_void, commit_size, page_protect_to_native(protect))
        };
        if ret != 0 {
            return ptr::null_mut();
        }

        if !update_allocation_range(
            &mut allocation_registry().write().expect("virtual allocation registry poisoned"),
            info.allocation_base,
            commit_address,
            commit_end,
            MEM_COMMIT,
            protect,
        ) {
            return ptr::null_mut();
        }
        invalidate_host_mapping_cache();

        trace!(
            address = format_args!("0x{commit_address:x}"),
            size = commit_size,
            protect,
            "VirtualAlloc committed existing region"
        );
        return commit_address as *mut c_void;
    }

    // If not in VirtualAlloc registry, check if it's within host mapped range
    if let Some(host_info) = find_host_mapping(requested) {
        if host_info.state != MEM_FREE {
            let ret = unsafe {
                libc::mprotect(commit_address as *mut c_void, commit_size, page_protect_to_native(protect))
            };
            if ret == 0 {
                invalidate_host_mapping_cache();
                return commit_address as *mut c_void;
            }
        }
    }

    ptr::null_mut()
}

pub fn virtual_free(address: *mut c_void, size: usize, free_type: u32) -> i32 {
    if address.is_null() {
        return 0;
    }

    let key = address as usize;
    let Some(info) = find_allocation(key) else {
        return 0;
    };

    if free_type & MEM_RELEASE != 0 {
        if size != 0 || key != info.allocation_base {
            return 0;
        }
        let Some((allocation_base, allocation_end)) = allocation_bounds(
            &allocation_registry().read().expect("virtual allocation registry poisoned"),
            info.allocation_base,
        ) else {
            return 0;
        };
        let release_size = allocation_end - allocation_base;
        let status = unsafe { libc::munmap(allocation_base as *mut c_void, release_size) };
        if status != 0 {
            return 0;
        }

        allocation_registry()
            .write()
            .expect("virtual allocation registry poisoned")
            .retain(|_, entry| entry.allocation_base != allocation_base);
        invalidate_host_mapping_cache();
        return 1;
    }

    if free_type & MEM_DECOMMIT != 0 {
        let decommit_size = if size == 0 { info.size } else { align_up(size) };
        let decommit_base = align_down(key);
        let Some(decommit_end) = decommit_base.checked_add(decommit_size) else {
            return 0;
        };
        {
            let registry =
                allocation_registry().read().expect("virtual allocation registry poisoned");
            if !allocation_covers_range(
                &registry,
                info.allocation_base,
                decommit_base,
                decommit_end,
            ) {
                return 0;
            }
        }
        let status =
            unsafe { libc::mprotect(decommit_base as *mut c_void, decommit_size, libc::PROT_NONE) };
        if status != 0 {
            return 0;
        }

        let res = i32::from(update_allocation_range(
            &mut allocation_registry().write().expect("virtual allocation registry poisoned"),
            info.allocation_base,
            decommit_base,
            decommit_end,
            MEM_RESERVE,
            PAGE_NOACCESS,
        ));
        invalidate_host_mapping_cache();
        return res;
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
    let Some(info) = find_allocation(aligned_address) else {
        return 0;
    };

    let previous = info.protect;
    let Some(aligned_end) = aligned_address.checked_add(aligned_size) else {
        return 0;
    };
    {
        let registry = allocation_registry().read().expect("virtual allocation registry poisoned");
        if !allocation_covers_range(&registry, info.allocation_base, aligned_address, aligned_end) {
            return 0;
        }
    }

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

    let res = i32::from(update_allocation_range(
        &mut allocation_registry().write().expect("virtual allocation registry poisoned"),
        info.allocation_base,
        aligned_address,
        aligned_end,
        MEM_COMMIT,
        new_protect,
    ));
    invalidate_host_mapping_cache();
    res
}

pub fn virtual_query(
    address: *const c_void,
    buffer: *mut MemoryBasicInformation,
    length: usize,
) -> usize {
    if buffer.is_null() || length < std::mem::size_of::<MemoryBasicInformation>() {
        return 0;
    }

    let Some(info) =
        find_allocation(address as usize).or_else(|| find_host_mapping(address as usize))
    else {
        return 0;
    };

    unsafe {
        *buffer = MemoryBasicInformation {
            base_address: info.base_address as *mut c_void,
            allocation_base: info.allocation_base as *mut c_void,
            allocation_protect: info.protect,
            region_size: info.size,
            state: info.state,
            protect: info.protect,
            type_flags: info.type_flags,
        };
    }

    trace!(
        address = format_args!("0x{:x}", address as usize),
        base = format_args!("0x{:x}", info.base_address),
        allocation_base = format_args!("0x{:x}", info.allocation_base),
        size = info.size,
        state = info.state,
        protect = info.protect,
        "VirtualQuery resolved region"
    );

    std::mem::size_of::<MemoryBasicInformation>()
}

pub fn try_handle_page_fault(addr: usize) -> bool {
    if addr < 0x10000 || addr >= 0x0000_8000_0000_0000 {
        return false;
    }
    let page_sz = page_size();
    let page_base = addr & !(page_sz - 1);
    if let Some(info) = find_allocation(addr) {
        if info.state == MEM_RESERVE || info.protect == PAGE_NOACCESS {
            let ret = unsafe {
                libc::mprotect(page_base as *mut c_void, page_sz, libc::PROT_READ | libc::PROT_WRITE)
            };
            if ret == 0 {
                let _ = update_allocation_range(
                    &mut allocation_registry().write().expect("virtual allocation registry poisoned"),
                    info.allocation_base,
                    page_base,
                    page_base + page_sz,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                );
                return true;
            }
        }
    }

    // Fallback for native runtime memory (Mono BDWGC card table write barriers & guard pages)
    let ret = unsafe {
        libc::mprotect(page_base as *mut c_void, page_sz, libc::PROT_READ | libc::PROT_WRITE)
    };
    ret == 0
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

    #[test]
    fn committing_part_of_reservation_keeps_other_pages_reserved() {
        let _guard = serial_guard();
        let page = page_size();
        let reservation = virtual_alloc(ptr::null_mut(), page * 3, MEM_RESERVE, PAGE_NOACCESS);
        assert!(!reservation.is_null());

        let middle = unsafe { reservation.cast::<u8>().add(page) }.cast::<c_void>();
        assert_eq!(virtual_alloc(middle, page, MEM_COMMIT, PAGE_READWRITE), middle);

        let mut mbi = MemoryBasicInformation::default();
        for (address, expected_state, expected_protect) in [
            (reservation, MEM_RESERVE, PAGE_NOACCESS),
            (middle, MEM_COMMIT, PAGE_READWRITE),
            (unsafe { middle.cast::<u8>().add(page) }.cast::<c_void>(), MEM_RESERVE, PAGE_NOACCESS),
        ] {
            assert_eq!(
                virtual_query(address, &mut mbi, std::mem::size_of::<MemoryBasicInformation>()),
                std::mem::size_of::<MemoryBasicInformation>()
            );
            assert_eq!(mbi.state, expected_state);
            assert_eq!(mbi.protect, expected_protect);
            assert_eq!(mbi.allocation_base, reservation);
        }

        assert_eq!(virtual_free(reservation, 0, MEM_RELEASE), 1);
    }

    #[test]
    fn query_observes_native_stack_mapping() {
        let marker = 0_u8;
        let mut mbi = MemoryBasicInformation::default();

        assert_eq!(
            virtual_query(
                (&marker as *const u8).cast(),
                &mut mbi,
                std::mem::size_of::<MemoryBasicInformation>(),
            ),
            std::mem::size_of::<MemoryBasicInformation>()
        );
        assert!((mbi.base_address as usize..mbi.base_address as usize + mbi.region_size)
            .contains(&(&marker as *const u8 as usize)));
        assert_eq!(mbi.state, MEM_COMMIT);
    }

    #[test]
    fn registered_native_region_preserves_allocation_base() {
        let _guard = serial_guard();
        let page = page_size();
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        assert_eq!(unsafe { libc::mprotect(mapping, page, libc::PROT_NONE) }, 0);

        let usable = unsafe { mapping.cast::<u8>().add(page) }.cast::<c_void>();
        assert!(register_native_allocation(mapping, mapping, page, PAGE_NOACCESS));
        assert!(register_native_allocation(usable, mapping, page, PAGE_READWRITE));

        let mut mbi = MemoryBasicInformation::default();
        assert_eq!(
            virtual_query(usable, &mut mbi, std::mem::size_of::<MemoryBasicInformation>()),
            std::mem::size_of::<MemoryBasicInformation>()
        );
        assert_eq!(mbi.base_address, usable);
        assert_eq!(mbi.allocation_base, mapping);
        assert_eq!(mbi.protect, PAGE_READWRITE);

        assert_eq!(
            virtual_query(mapping, &mut mbi, std::mem::size_of::<MemoryBasicInformation>()),
            std::mem::size_of::<MemoryBasicInformation>()
        );
        assert_eq!(mbi.base_address, mapping);
        assert_eq!(mbi.allocation_base, mapping);
        assert_eq!(mbi.protect, PAGE_NOACCESS);

        unregister_native_allocation(mapping);
        unregister_native_allocation(usable);
        assert_eq!(unsafe { libc::munmap(mapping, page * 2) }, 0);
    }

    #[test]
    fn unmapped_address_reports_mem_free_region() {
        let mappings = [
            AllocationInfo {
                base_address: 0x1000,
                allocation_base: 0x1000,
                size: 0x1000,
                allocation_type: MEM_COMMIT,
                protect: PAGE_READWRITE,
                state: MEM_COMMIT,
                type_flags: MEM_PRIVATE,
            },
            AllocationInfo {
                base_address: 0x4000,
                allocation_base: 0x4000,
                size: 0x1000,
                allocation_type: MEM_COMMIT,
                protect: PAGE_READWRITE,
                state: MEM_COMMIT,
                type_flags: MEM_PRIVATE,
            },
        ];

        let free = free_region_containing(&mappings, 0x2fff).expect("free region");
        assert_eq!(free.base_address, 0x2000);
        assert_eq!(free.size, 0x2000);
        assert_eq!(free.allocation_base, 0);
        assert_eq!(free.state, MEM_FREE);
        assert_eq!(free.protect, 0);
    }
}
