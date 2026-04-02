#![allow(non_snake_case)]

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use crate::{
    memory::{
        heap,
        virtual_alloc::{self, MemoryBasicInformation},
    },
    nt_kernel::file::FileHandle,
    utils::handle::{global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE},
};

const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

const FILE_MAP_WRITE: u32 = 0x0002;
const FILE_MAP_READ: u32 = 0x0004;
const FILE_MAP_EXECUTE: u32 = 0x0020;

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_INVALID_PARAMETER: u32 = 87;

const GMEM_ZEROINIT: u32 = 0x0040;

#[derive(Debug)]
struct FileMappingHandle {
    duplicated_fd: Option<i32>,
    max_size: usize,
    page_protect: u32,
    mapped_views: Mutex<Vec<(usize, usize)>>,
}

impl HandleObject for FileMappingHandle {
    fn type_name(&self) -> &'static str {
        "FileMappingHandle"
    }

    fn close(&mut self) {
        let mut views = self.mapped_views.lock().expect("mapping views mutex poisoned");
        for (addr, size) in views.drain(..) {
            if take_registered_view(addr).is_some() {
                unsafe {
                    libc::munmap(addr as *mut c_void, size);
                }
            }
        }

        if let Some(fd) = self.duplicated_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn set_last_error(code: u32) {
    super::error::set_last_error(code);
}

fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        4096
    } else {
        size as usize
    }
}

fn protection_from_page_flags(page_protect: u32) -> Option<i32> {
    match page_protect {
        PAGE_READONLY => Some(libc::PROT_READ),
        PAGE_READWRITE => Some(libc::PROT_READ | libc::PROT_WRITE),
        PAGE_EXECUTE_READ => Some(libc::PROT_READ | libc::PROT_EXEC),
        PAGE_EXECUTE_READWRITE => Some(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC),
        _ => None,
    }
}

fn protection_from_view_access(desired_access: u32, page_protect: u32) -> Option<i32> {
    if desired_access == 0 {
        return protection_from_page_flags(page_protect);
    }

    let mut prot = 0;
    if (desired_access & FILE_MAP_READ) != 0 {
        prot |= libc::PROT_READ;
    }
    if (desired_access & FILE_MAP_WRITE) != 0 {
        prot |= libc::PROT_WRITE;
    }
    if (desired_access & FILE_MAP_EXECUTE) != 0 {
        prot |= libc::PROT_EXEC;
    }

    if prot == 0 {
        protection_from_page_flags(page_protect)
    } else {
        Some(prot)
    }
}

fn registered_views() -> &'static Mutex<std::collections::HashMap<usize, usize>> {
    static REGISTRY: OnceLock<Mutex<std::collections::HashMap<usize, usize>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn register_view(addr: usize, len: usize) {
    let mut registry = registered_views().lock().expect("mapping registry mutex poisoned");
    registry.insert(addr, len);
}

fn take_registered_view(addr: usize) -> Option<usize> {
    let mut registry = registered_views().lock().expect("mapping registry mutex poisoned");
    registry.remove(&addr)
}

fn create_mapping_size(
    fd: Option<i32>,
    max_size_high: u32,
    max_size_low: u32,
) -> Result<usize, u32> {
    let declared = ((max_size_high as u64) << 32) | (max_size_low as u64);
    if declared > 0 {
        return usize::try_from(declared).map_err(|_| ERROR_INVALID_PARAMETER);
    }

    if let Some(fd) = fd {
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(fd, &mut stat_buf) };
        if rc != 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        if stat_buf.st_size <= 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        usize::try_from(stat_buf.st_size).map_err(|_| ERROR_INVALID_PARAMETER)
    } else {
        Err(ERROR_INVALID_PARAMETER)
    }
}

pub extern "win64" fn VirtualAlloc(
    lpAddress: *mut c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut c_void {
    virtual_alloc::virtual_alloc(lpAddress, dwSize, flAllocationType, flProtect)
}

pub extern "win64" fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32 {
    virtual_alloc::virtual_free(lpAddress, dwSize, dwFreeType)
}

pub extern "win64" fn VirtualProtect(
    lpAddress: *mut c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> i32 {
    virtual_alloc::virtual_protect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
}

pub extern "win64" fn VirtualQuery(
    lpAddress: *const c_void,
    lpBuffer: *mut c_void,
    dwLength: usize,
) -> usize {
    virtual_alloc::virtual_query(lpAddress, lpBuffer.cast::<MemoryBasicInformation>(), dwLength)
}

pub extern "win64" fn HeapCreate(
    flOptions: u32,
    dwInitialSize: usize,
    dwMaximumSize: usize,
) -> Handle {
    heap::heap_create(flOptions, dwInitialSize, dwMaximumSize)
}

pub extern "win64" fn HeapAlloc(hHeap: Handle, dwFlags: u32, dwBytes: usize) -> *mut c_void {
    heap::heap_alloc(hHeap, dwFlags, dwBytes)
}

pub extern "win64" fn HeapFree(hHeap: Handle, dwFlags: u32, lpMem: *mut c_void) -> i32 {
    heap::heap_free(hHeap, dwFlags, lpMem)
}

pub extern "win64" fn HeapReAlloc(
    hHeap: Handle,
    dwFlags: u32,
    lpMem: *mut c_void,
    dwBytes: usize,
) -> *mut c_void {
    heap::heap_realloc(hHeap, dwFlags, lpMem, dwBytes)
}

pub extern "win64" fn HeapSize(hHeap: Handle, dwFlags: u32, lpMem: *const c_void) -> usize {
    heap::heap_size(hHeap, dwFlags, lpMem)
}

pub extern "win64" fn HeapDestroy(hHeap: Handle) -> i32 {
    heap::heap_destroy(hHeap)
}

pub extern "win64" fn GetProcessHeap() -> Handle {
    heap::get_process_heap()
}

pub extern "win64" fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> *mut c_void {
    let heap = heap::get_process_heap();
    let mut heap_flags = 0;
    if (uFlags & GMEM_ZEROINIT) != 0 {
        heap_flags |= heap::HEAP_ZERO_MEMORY;
    }

    let ptr = heap::heap_alloc(heap, heap_flags, dwBytes);
    if ptr.is_null() {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    ptr
}

pub extern "win64" fn GlobalFree(hMem: *mut c_void) -> *mut c_void {
    if hMem.is_null() {
        set_last_error(ERROR_SUCCESS);
        return std::ptr::null_mut();
    }

    let heap = heap::get_process_heap();
    if heap::heap_free(heap, 0, hMem) != 0 {
        set_last_error(ERROR_SUCCESS);
        std::ptr::null_mut()
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        hMem
    }
}

pub extern "win64" fn GlobalLock(hMem: *mut c_void) -> *mut c_void {
    if hMem.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return std::ptr::null_mut();
    }

    let heap = heap::get_process_heap();
    if heap::heap_contains(heap, hMem) {
        set_last_error(ERROR_SUCCESS);
        hMem
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        std::ptr::null_mut()
    }
}

pub extern "win64" fn GlobalUnlock(hMem: *mut c_void) -> i32 {
    if hMem.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let heap = heap::get_process_heap();
    if heap::heap_contains(heap, hMem) {
        // Windows commonly returns FALSE for fixed blocks with NO_ERROR.
        set_last_error(ERROR_SUCCESS);
        0
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        0
    }
}

pub extern "win64" fn GlobalReAlloc(hMem: *mut c_void, dwBytes: usize, uFlags: u32) -> *mut c_void {
    if hMem.is_null() {
        return GlobalAlloc(uFlags, dwBytes);
    }

    let heap = heap::get_process_heap();
    let mut heap_flags = 0;
    if (uFlags & GMEM_ZEROINIT) != 0 {
        heap_flags |= heap::HEAP_ZERO_MEMORY;
    }

    let ptr = heap::heap_realloc(heap, heap_flags, hMem, dwBytes);
    if ptr.is_null() {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    ptr
}

pub extern "win64" fn GlobalSize(hMem: *const c_void) -> usize {
    if hMem.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    let heap = heap::get_process_heap();
    let size = heap::heap_size(heap, 0, hMem);
    if size == usize::MAX {
        set_last_error(ERROR_INVALID_HANDLE);
        0
    } else {
        set_last_error(ERROR_SUCCESS);
        size
    }
}

pub extern "win64" fn GlobalFlags(hMem: *mut c_void) -> u32 {
    if hMem.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return u32::MAX;
    }

    let heap = heap::get_process_heap();
    if heap::heap_contains(heap, hMem) {
        set_last_error(ERROR_SUCCESS);
        0
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        u32::MAX
    }
}

pub extern "win64" fn GlobalHandle(pMem: *const c_void) -> *mut c_void {
    if pMem.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return std::ptr::null_mut();
    }

    let heap = heap::get_process_heap();
    let ptr = pMem as *mut c_void;
    if heap::heap_contains(heap, ptr) {
        set_last_error(ERROR_SUCCESS);
        ptr
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        std::ptr::null_mut()
    }
}

pub extern "win64" fn LocalAlloc(uFlags: u32, uBytes: usize) -> *mut c_void {
    GlobalAlloc(uFlags, uBytes)
}

pub extern "win64" fn LocalReAlloc(hMem: *mut c_void, uBytes: usize, uFlags: u32) -> *mut c_void {
    GlobalReAlloc(hMem, uBytes, uFlags)
}

pub extern "win64" fn LocalLock(hMem: *mut c_void) -> *mut c_void {
    GlobalLock(hMem)
}

pub extern "win64" fn LocalUnlock(hMem: *mut c_void) -> i32 {
    GlobalUnlock(hMem)
}

pub extern "win64" fn LocalSize(hMem: *const c_void) -> usize {
    GlobalSize(hMem)
}

pub extern "win64" fn LocalFlags(hMem: *mut c_void) -> u32 {
    GlobalFlags(hMem)
}

pub extern "win64" fn LocalHandle(pMem: *const c_void) -> *mut c_void {
    GlobalHandle(pMem)
}

pub extern "win64" fn LocalFree(hMem: *mut c_void) -> *mut c_void {
    GlobalFree(hMem)
}

pub extern "win64" fn CreateFileMappingA(
    hFile: Handle,
    _lpFileMappingAttributes: *mut c_void,
    flProtect: u32,
    dwMaximumSizeHigh: u32,
    dwMaximumSizeLow: u32,
    _lpName: *const i8,
) -> Handle {
    init_global_table();

    let Some(_base_prot) = protection_from_page_flags(flProtect) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };

    let duplicated_fd = if hFile == INVALID_HANDLE_VALUE {
        None
    } else {
        let mut fd = None;
        global_table().with(hFile, |obj| {
            if let Some(file) = obj.as_any().downcast_ref::<FileHandle>() {
                fd = Some(file.fd);
            }
        });

        let Some(source_fd) = fd else {
            set_last_error(ERROR_INVALID_HANDLE);
            return INVALID_HANDLE_VALUE;
        };

        let duplicated = unsafe { libc::dup(source_fd) };
        if duplicated < 0 {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return INVALID_HANDLE_VALUE;
        }
        Some(duplicated)
    };

    let max_size = match create_mapping_size(duplicated_fd, dwMaximumSizeHigh, dwMaximumSizeLow) {
        Ok(size) => size,
        Err(code) => {
            if let Some(fd) = duplicated_fd {
                unsafe {
                    libc::close(fd);
                }
            }
            set_last_error(code);
            return INVALID_HANDLE_VALUE;
        }
    };

    let mapping_handle = global_table().alloc(Box::new(FileMappingHandle {
        duplicated_fd,
        max_size,
        page_protect: flProtect,
        mapped_views: Mutex::new(Vec::new()),
    }));

    set_last_error(ERROR_SUCCESS);
    mapping_handle
}

pub extern "win64" fn CreateFileMappingW(
    hFile: Handle,
    lpFileMappingAttributes: *mut c_void,
    flProtect: u32,
    dwMaximumSizeHigh: u32,
    dwMaximumSizeLow: u32,
    _lpName: *const u16,
) -> Handle {
    CreateFileMappingA(
        hFile,
        lpFileMappingAttributes,
        flProtect,
        dwMaximumSizeHigh,
        dwMaximumSizeLow,
        std::ptr::null(),
    )
}

pub extern "win64" fn MapViewOfFile(
    hFileMappingObject: Handle,
    dwDesiredAccess: u32,
    dwFileOffsetHigh: u32,
    dwFileOffsetLow: u32,
    dwNumberOfBytesToMap: usize,
) -> *mut c_void {
    init_global_table();

    let mut duplicated_fd = None;
    let mut max_size = 0usize;
    let mut page_protect = 0u32;
    let mut views_mutex_ptr: *const Mutex<Vec<(usize, usize)>> = std::ptr::null();

    global_table().with(hFileMappingObject, |obj| {
        if let Some(mapping) = obj.as_any().downcast_ref::<FileMappingHandle>() {
            duplicated_fd = mapping.duplicated_fd;
            max_size = mapping.max_size;
            page_protect = mapping.page_protect;
            views_mutex_ptr = &mapping.mapped_views;
        }
    });

    if views_mutex_ptr.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return std::ptr::null_mut();
    }

    let offset = ((dwFileOffsetHigh as u64) << 32) | (dwFileOffsetLow as u64);
    let Ok(offset_usize) = usize::try_from(offset) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    if (offset_usize % page_size()) != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    let view_size = if dwNumberOfBytesToMap == 0 {
        max_size.saturating_sub(offset_usize)
    } else {
        dwNumberOfBytesToMap
    };

    if view_size == 0
        || offset_usize > max_size
        || offset_usize.saturating_add(view_size) > max_size
    {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }

    let Some(prot) = protection_from_view_access(dwDesiredAccess, page_protect) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    };

    let (flags, fd) = if let Some(fd) = duplicated_fd {
        (libc::MAP_SHARED, fd)
    } else {
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)
    };

    let mapped = unsafe {
        libc::mmap(std::ptr::null_mut(), view_size, prot, flags, fd, offset as libc::off_t)
    };

    if mapped == libc::MAP_FAILED {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return std::ptr::null_mut();
    }

    register_view(mapped as usize, view_size);
    let views = unsafe { &*views_mutex_ptr };
    views.lock().expect("mapping views mutex poisoned").push((mapped as usize, view_size));
    set_last_error(ERROR_SUCCESS);
    mapped
}

pub extern "win64" fn UnmapViewOfFile(lpBaseAddress: *const c_void) -> i32 {
    if lpBaseAddress.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let addr = lpBaseAddress as usize;
    let Some(size) = take_registered_view(addr) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let rc = unsafe { libc::munmap(addr as *mut c_void, size) };
    if rc == 0 {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        set_last_error(ERROR_INVALID_PARAMETER);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use crate::win32::kernel32::file::{close_handle, create_file_a};

    #[test]
    fn maps_backed_file_and_persists_changes() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("mapped.bin");
        std::fs::write(&path, [0u8; 16]).expect("seed mapped file");

        let path_c = std::ffi::CString::new(path.to_string_lossy().to_string()).expect("cstring");
        let file_handle =
            create_file_a(path_c.as_ptr(), 0xC000_0000, 0, std::ptr::null_mut(), 3, 0, 0);
        assert_ne!(file_handle, INVALID_HANDLE_VALUE);

        let mapping = CreateFileMappingA(
            file_handle,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(mapping, INVALID_HANDLE_VALUE);

        let view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0);
        assert!(!view.is_null());

        unsafe {
            std::ptr::copy_nonoverlapping(b"phase10".as_ptr(), view.cast::<u8>(), 7);
        }

        assert_eq!(UnmapViewOfFile(view), 1);
        assert_eq!(close_handle(mapping), 1);
        assert_eq!(close_handle(file_handle), 1);

        let bytes = std::fs::read(path).expect("read mapped file");
        assert_eq!(&bytes[..7], b"phase10");
    }

    #[test]
    fn maps_anonymous_backing_store() {
        let _guard = serial_guard();
        let mapping = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            4096,
            std::ptr::null(),
        );
        assert_ne!(mapping, INVALID_HANDLE_VALUE);

        let view = MapViewOfFile(mapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 4096);
        assert!(!view.is_null());

        unsafe {
            *(view as *mut u8) = 0x5A;
            assert_eq!(*(view as *const u8), 0x5A);
        }

        assert_eq!(UnmapViewOfFile(view), 1);
        assert_eq!(close_handle(mapping), 1);
    }

    #[test]
    fn global_alloc_lock_size_and_free_round_trip() {
        let _guard = serial_guard();
        let ptr = GlobalAlloc(GMEM_ZEROINIT, 64);
        assert!(!ptr.is_null());

        let locked = GlobalLock(ptr);
        assert_eq!(locked, ptr);
        assert_eq!(GlobalSize(ptr), 64);

        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, 64) };
        assert!(bytes.iter().all(|b| *b == 0));

        assert_eq!(GlobalUnlock(ptr), 0);
        assert!(GlobalFree(ptr).is_null());
    }

    #[test]
    fn global_realloc_grows_allocation() {
        let _guard = serial_guard();
        let ptr = GlobalAlloc(0, 16);
        assert!(!ptr.is_null());

        let grown = GlobalReAlloc(ptr, 128, 0);
        assert!(!grown.is_null());
        assert_eq!(GlobalSize(grown), 128);

        assert!(GlobalFree(grown).is_null());
    }

    #[test]
    fn local_alloc_lock_size_and_free_round_trip() {
        let _guard = serial_guard();
        let ptr = LocalAlloc(GMEM_ZEROINIT, 32);
        assert!(!ptr.is_null());

        assert_eq!(LocalLock(ptr), ptr);
        assert_eq!(LocalSize(ptr), 32);
        assert_eq!(LocalFlags(ptr), 0);
        assert_eq!(LocalHandle(ptr), ptr);
        assert_eq!(LocalUnlock(ptr), 0);
        assert!(LocalFree(ptr).is_null());
    }
}
