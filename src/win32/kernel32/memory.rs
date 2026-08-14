#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::{
    memory::{
        heap,
        virtual_alloc::{self, MemoryBasicInformation},
    },
    nt_kernel::file::FileHandle,
    utils::handle::{global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE},
    utils::wide_string::from_wide_ptr,
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
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ALREADY_EXISTS: u32 = 183;

const GMEM_ZEROINIT: u32 = 0x0040;

#[derive(Debug)]
struct FileMappingState {
    duplicated_fd: Option<i32>,
    max_size: usize,
    page_protect: u32,
}

impl Drop for FileMappingState {
    fn drop(&mut self) {
        if let Some(fd) = self.duplicated_fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

#[derive(Debug)]
struct FileMappingHandle {
    state: Arc<FileMappingState>,
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
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn named_file_mappings() -> &'static Mutex<HashMap<String, Weak<FileMappingState>>> {
    static MAPPINGS: OnceLock<Mutex<HashMap<String, Weak<FileMappingState>>>> = OnceLock::new();
    MAPPINGS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn allocate_file_mapping_handle(state: Arc<FileMappingState>) -> Handle {
    global_table()
        .alloc(Box::new(FileMappingHandle { state, mapped_views: Mutex::new(Vec::new()) }))
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
    let ptr = heap::heap_alloc(hHeap, dwFlags, dwBytes);
    if ptr.is_null() {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    }
    ptr
}

pub extern "win64" fn HeapFree(hHeap: Handle, dwFlags: u32, lpMem: *mut c_void) -> i32 {
    let ok = heap::heap_free(hHeap, dwFlags, lpMem);
    if ok == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    ok
}

pub extern "win64" fn HeapReAlloc(
    hHeap: Handle,
    dwFlags: u32,
    lpMem: *mut c_void,
    dwBytes: usize,
) -> *mut c_void {
    let ptr = heap::heap_realloc(hHeap, dwFlags, lpMem, dwBytes);
    if ptr.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    ptr
}

pub extern "win64" fn HeapSize(hHeap: Handle, dwFlags: u32, lpMem: *const c_void) -> usize {
    let size = heap::heap_size(hHeap, dwFlags, lpMem);
    if size == usize::MAX {
        set_last_error(ERROR_INVALID_PARAMETER);
    } else {
        set_last_error(ERROR_SUCCESS);
    }
    size
}

pub extern "win64" fn IsBadReadPtr(lp: *const c_void, _ucb: usize) -> i32 {
    if lp.is_null() { 1 } else { 0 }
}

pub extern "win64" fn IsBadWritePtr(lp: *mut c_void, _ucb: usize) -> i32 {
    if lp.is_null() { 1 } else { 0 }
}

pub extern "win64" fn IsBadCodePtr(lpfn: *const c_void) -> i32 {
    if lpfn.is_null() { 1 } else { 0 }
}

pub extern "win64" fn IsBadStringPtrA(lpsz: *const c_char, _ucchMax: usize) -> i32 {
    if lpsz.is_null() { 1 } else { 0 }
}

pub extern "win64" fn IsBadStringPtrW(lpsz: *const u16, _ucchMax: usize) -> i32 {
    if lpsz.is_null() { 1 } else { 0 }
}

pub extern "win64" fn HeapDestroy(hHeap: Handle) -> i32 {
    heap::heap_destroy(hHeap)
}

pub extern "win64" fn GetProcessHeap() -> Handle {
    heap::get_process_heap()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn HeapQueryInformation(
    _h_heap: Handle,
    _heap_information_class: u32,
    heap_information: *mut c_void,
    heap_information_length: usize,
    return_length: *mut usize,
) -> i32 {
    if !return_length.is_null() {
        unsafe {
            *return_length = 0;
        }
    }

    if !heap_information.is_null() && heap_information_length > 0 {
        unsafe {
            std::ptr::write_bytes(heap_information.cast::<u8>(), 0, heap_information_length);
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn HeapSetInformation(
    _h_heap: Handle,
    _heap_information_class: u32,
    _heap_information: *mut c_void,
    _heap_information_length: usize,
) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
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
    lp_name: *const i8,
) -> Handle {
    init_global_table();

    let name = if lp_name.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(lp_name) }.to_string_lossy().to_ascii_lowercase())
    };
    if let Some(name) = name.as_deref() {
        let mut mappings = named_file_mappings().lock().expect("named mapping registry poisoned");
        if let Some(state) = mappings.get(name).and_then(Weak::upgrade) {
            set_last_error(ERROR_ALREADY_EXISTS);
            return allocate_file_mapping_handle(state);
        }
        mappings.remove(name);
    }

    let Some(_base_prot) = protection_from_page_flags(flProtect) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };

    let mut duplicated_fd = if hFile == INVALID_HANDLE_VALUE {
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

    if duplicated_fd.is_none() {
        let fd = unsafe {
            libc::memfd_create(
                b"tuxexe-file-mapping\0".as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC,
            )
        };
        if fd < 0 || unsafe { libc::ftruncate(fd, max_size as libc::off_t) } != 0 {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return INVALID_HANDLE_VALUE;
        }
        duplicated_fd = Some(fd);
    }

    let state = Arc::new(FileMappingState { duplicated_fd, max_size, page_protect: flProtect });
    if let Some(name) = name {
        named_file_mappings()
            .lock()
            .expect("named mapping registry poisoned")
            .insert(name, Arc::downgrade(&state));
    }
    let mapping_handle = allocate_file_mapping_handle(state);

    set_last_error(ERROR_SUCCESS);
    mapping_handle
}

pub extern "win64" fn CreateFileMappingW(
    hFile: Handle,
    lpFileMappingAttributes: *mut c_void,
    flProtect: u32,
    dwMaximumSizeHigh: u32,
    dwMaximumSizeLow: u32,
    lp_name: *const u16,
) -> Handle {
    let name = if lp_name.is_null() {
        None
    } else {
        match unsafe { from_wide_ptr(lp_name) } {
            Ok(name) => match CString::new(name) {
                Ok(name) => Some(name),
                Err(_) => {
                    set_last_error(ERROR_INVALID_PARAMETER);
                    return INVALID_HANDLE_VALUE;
                }
            },
            Err(_) => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return INVALID_HANDLE_VALUE;
            }
        }
    };
    CreateFileMappingA(
        hFile,
        lpFileMappingAttributes,
        flProtect,
        dwMaximumSizeHigh,
        dwMaximumSizeLow,
        name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr()),
    )
}

pub extern "win64" fn OpenFileMappingA(
    _desired_access: u32,
    _inherit_handle: i32,
    name: *const i8,
) -> Handle {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().to_ascii_lowercase();
    let state = named_file_mappings()
        .lock()
        .expect("named mapping registry poisoned")
        .get(name.as_str())
        .and_then(Weak::upgrade);
    let Some(state) = state else {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    init_global_table();
    let handle = allocate_file_mapping_handle(state);
    set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn OpenFileMappingW(
    desired_access: u32,
    inherit_handle: i32,
    name: *const u16,
) -> Handle {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Ok(name) = (unsafe { from_wide_ptr(name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Ok(name) = CString::new(name) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    OpenFileMappingA(desired_access, inherit_handle, name.as_ptr())
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
            duplicated_fd = mapping.state.duplicated_fd;
            max_size = mapping.state.max_size;
            page_protect = mapping.state.page_protect;
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

pub extern "win64" fn FlushViewOfFile(base_address: *const c_void, bytes_to_flush: usize) -> i32 {
    if base_address.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let address = base_address as usize;
    let registered = registered_views().lock().expect("mapping registry mutex poisoned");
    let Some(&view_size) = registered.get(&address) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let length = if bytes_to_flush == 0 { view_size } else { bytes_to_flush };
    if length > view_size {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let result = unsafe { libc::msync(base_address.cast_mut(), length, libc::MS_SYNC) };
    if result == 0 {
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
    fn opens_named_mapping_with_shared_backing_store() {
        let _guard = serial_guard();
        let name = CString::new("TuxExe-Named-Mapping-Test").expect("mapping name");
        let mapping = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            4096,
            name.as_ptr(),
        );
        assert_ne!(mapping, INVALID_HANDLE_VALUE);
        let opened = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, 0, name.as_ptr());
        assert_ne!(opened, 0);

        let writer = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 4096);
        let reader = MapViewOfFile(opened, FILE_MAP_READ, 0, 0, 4096);
        assert!(!writer.is_null() && !reader.is_null());
        unsafe {
            *(writer.cast::<u8>()) = 0xA5;
            assert_eq!(*(reader.cast::<u8>()), 0xA5);
        }
        assert_eq!(UnmapViewOfFile(writer), 1);
        assert_eq!(UnmapViewOfFile(reader), 1);
        assert_eq!(close_handle(mapping), 1);
        assert_eq!(close_handle(opened), 1);
    }

    #[test]
    fn global_alloc_lock_size_and_free_round_trip() {
        let _guard = serial_guard();
        let ptr = GlobalAlloc(GMEM_ZEROINIT, 64);
        assert!(!ptr.is_null());

        let locked = GlobalLock(ptr);
        assert_eq!(locked, ptr);
        assert!(GlobalSize(ptr) >= 64);

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
        assert!(GlobalSize(grown) >= 128);

        assert!(GlobalFree(grown).is_null());
    }

    #[test]
    fn local_alloc_lock_size_and_free_round_trip() {
        let _guard = serial_guard();
        let ptr = LocalAlloc(GMEM_ZEROINIT, 32);
        assert!(!ptr.is_null());

        assert_eq!(LocalLock(ptr), ptr);
        assert!(LocalSize(ptr) >= 32);
        assert_eq!(LocalFlags(ptr), 0);
        assert_eq!(LocalHandle(ptr), ptr);
        assert_eq!(LocalUnlock(ptr), 0);
        assert!(LocalFree(ptr).is_null());
    }
}
