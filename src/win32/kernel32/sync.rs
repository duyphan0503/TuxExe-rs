#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::type_complexity)]

use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{Arc, Condvar, Mutex, OnceLock, RwLock},
};

use crate::{nt_kernel::sync as nt_sync, utils::handle::Handle};

#[derive(Debug, Default)]
struct CriticalSectionState {
    owner_tid: Option<u32>,
    recursion_count: u32,
}

fn critical_sections(
) -> &'static RwLock<HashMap<usize, Arc<(Mutex<CriticalSectionState>, Condvar)>>> {
    static TABLE: OnceLock<RwLock<HashMap<usize, Arc<(Mutex<CriticalSectionState>, Condvar)>>>> =
        OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(HashMap::new()))
}

#[derive(Debug, Default, Clone, Copy)]
struct SListState {
    head: usize,
    depth: u16,
}

fn slist_states() -> &'static RwLock<HashMap<usize, SListState>> {
    static TABLE: OnceLock<RwLock<HashMap<usize, SListState>>> = OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(HashMap::new()))
}

unsafe fn slist_entry_next(entry: *mut c_void) -> usize {
    // SAFETY: SLIST_ENTRY starts with a single pointer-sized `Next` field.
    unsafe { *(entry.cast::<usize>()) }
}

unsafe fn set_slist_entry_next(entry: *mut c_void, next: usize) {
    // SAFETY: SLIST_ENTRY starts with a single pointer-sized `Next` field.
    unsafe {
        *(entry.cast::<usize>()) = next;
    }
}

fn current_thread_id() -> u32 {
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

fn get_or_create_critical_section(ptr: *mut c_void) -> Arc<(Mutex<CriticalSectionState>, Condvar)> {
    let key = ptr as usize;

    if let Some(entry) =
        critical_sections().read().expect("critical section table poisoned").get(&key)
    {
        return Arc::clone(entry);
    }

    let entry = Arc::new((Mutex::new(CriticalSectionState::default()), Condvar::new()));
    critical_sections()
        .write()
        .expect("critical section table poisoned")
        .insert(key, Arc::clone(&entry));
    entry
}

pub extern "win64" fn InitializeCriticalSection(lpCriticalSection: *mut c_void) {
    if !lpCriticalSection.is_null() {
        let _ = get_or_create_critical_section(lpCriticalSection);
    }
}

pub extern "win64" fn InitializeCriticalSectionAndSpinCount(
    lpCriticalSection: *mut c_void,
    _dwSpinCount: u32,
) -> i32 {
    InitializeCriticalSection(lpCriticalSection);
    1
}

pub extern "win64" fn InitializeCriticalSectionEx(
    lpCriticalSection: *mut c_void,
    _dwSpinCount: u32,
    _flags: u32,
) -> i32 {
    InitializeCriticalSection(lpCriticalSection);
    1
}

pub extern "win64" fn InitializeSListHead(list_head: *mut c_void) {
    if list_head.is_null() {
        return;
    }

    let key = list_head as usize;
    slist_states().write().expect("slist table poisoned").insert(key, SListState::default());
}

pub extern "win64" fn InterlockedPushEntrySList(
    list_head: *mut c_void,
    list_entry: *mut c_void,
) -> *mut c_void {
    if list_head.is_null() || list_entry.is_null() {
        return std::ptr::null_mut();
    }

    let key = list_head as usize;
    let mut guard = slist_states().write().expect("slist table poisoned");
    let state = guard.entry(key).or_default();
    let previous_head = state.head;

    // SAFETY: list_entry points to caller-owned SLIST_ENTRY storage.
    unsafe {
        set_slist_entry_next(list_entry, previous_head);
    }

    state.head = list_entry as usize;
    state.depth = state.depth.saturating_add(1);

    previous_head as *mut c_void
}

pub extern "win64" fn InterlockedPopEntrySList(list_head: *mut c_void) -> *mut c_void {
    if list_head.is_null() {
        return std::ptr::null_mut();
    }

    let key = list_head as usize;
    let mut guard = slist_states().write().expect("slist table poisoned");
    let state = guard.entry(key).or_default();
    if state.head == 0 {
        return std::ptr::null_mut();
    }

    let head = state.head as *mut c_void;
    // SAFETY: `head` was previously pushed as a SLIST_ENTRY node.
    let next = unsafe { slist_entry_next(head) };
    state.head = next;
    if state.depth > 0 {
        state.depth -= 1;
    }

    head
}

pub extern "win64" fn InterlockedFlushSList(list_head: *mut c_void) -> *mut c_void {
    if list_head.is_null() {
        return std::ptr::null_mut();
    }

    let key = list_head as usize;
    let mut guard = slist_states().write().expect("slist table poisoned");
    let state = guard.entry(key).or_default();
    let old_head = state.head as *mut c_void;
    state.head = 0;
    state.depth = 0;
    old_head
}

pub extern "win64" fn QueryDepthSList(list_head: *mut c_void) -> u16 {
    if list_head.is_null() {
        return 0;
    }

    let key = list_head as usize;
    slist_states().read().expect("slist table poisoned").get(&key).map_or(0, |s| s.depth)
}

pub extern "win64" fn EnterCriticalSection(lpCriticalSection: *mut c_void) {
    if lpCriticalSection.is_null() {
        return;
    }

    let entry = get_or_create_critical_section(lpCriticalSection);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("critical section state poisoned");
    let current_tid = current_thread_id();

    while matches!(guard.owner_tid, Some(owner) if owner != current_tid) {
        guard = condvar.wait(guard).expect("critical section state poisoned");
    }

    guard.owner_tid = Some(current_tid);
    guard.recursion_count = guard.recursion_count.saturating_add(1);
}

pub extern "win64" fn LeaveCriticalSection(lpCriticalSection: *mut c_void) {
    if lpCriticalSection.is_null() {
        return;
    }

    let entry = get_or_create_critical_section(lpCriticalSection);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("critical section state poisoned");
    if guard.owner_tid != Some(current_thread_id()) {
        return;
    }

    if guard.recursion_count > 0 {
        guard.recursion_count -= 1;
    }

    if guard.recursion_count == 0 {
        guard.owner_tid = None;
        condvar.notify_one();
    }
}

pub extern "win64" fn DeleteCriticalSection(lpCriticalSection: *mut c_void) {
    if lpCriticalSection.is_null() {
        return;
    }

    critical_sections()
        .write()
        .expect("critical section table poisoned")
        .remove(&(lpCriticalSection as usize));
}

pub extern "win64" fn WaitForSingleObject(hHandle: Handle, dwMilliseconds: u32) -> u32 {
    nt_sync::wait_for_single_object(hHandle, dwMilliseconds)
}

pub extern "win64" fn WaitForMultipleObjects(
    nCount: u32,
    lpHandles: *const usize,
    bWaitAll: i32,
    dwMilliseconds: u32,
) -> u32 {
    if lpHandles.is_null() || nCount == 0 {
        return nt_sync::WAIT_FAILED;
    }

    let raw_handles = unsafe { std::slice::from_raw_parts(lpHandles, nCount as usize) };
    let handles = raw_handles.iter().map(|value| *value as Handle).collect::<Vec<_>>();
    nt_sync::wait_for_multiple_objects(&handles, bWaitAll != 0, dwMilliseconds)
}

pub extern "win64" fn WaitForSingleObjectEx(
    hHandle: Handle,
    dwMilliseconds: u32,
    _bAlertable: i32,
) -> u32 {
    WaitForSingleObject(hHandle, dwMilliseconds)
}

pub extern "win64" fn WaitForMultipleObjectsEx(
    nCount: u32,
    lpHandles: *const usize,
    bWaitAll: i32,
    dwMilliseconds: u32,
    _bAlertable: i32,
) -> u32 {
    WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds)
}

pub extern "win64" fn CreateMutexA(
    _lpMutexAttributes: *const c_void,
    bInitialOwner: i32,
    _lpName: *const i8,
) -> Handle {
    nt_sync::create_mutex(bInitialOwner != 0)
}

pub extern "win64" fn CreateMutexW(
    _lpMutexAttributes: *const c_void,
    bInitialOwner: i32,
    _lpName: *const u16,
) -> Handle {
    nt_sync::create_mutex(bInitialOwner != 0)
}

pub extern "win64" fn ReleaseMutex(hMutex: Handle) -> i32 {
    nt_sync::release_mutex(hMutex)
}

pub extern "win64" fn CreateEventA(
    _lpEventAttributes: *const c_void,
    bManualReset: i32,
    bInitialState: i32,
    _lpName: *const i8,
) -> Handle {
    nt_sync::create_event(bManualReset != 0, bInitialState != 0)
}

pub extern "win64" fn CreateEventW(
    _lpEventAttributes: *const c_void,
    bManualReset: i32,
    bInitialState: i32,
    _lpName: *const u16,
) -> Handle {
    nt_sync::create_event(bManualReset != 0, bInitialState != 0)
}

pub extern "win64" fn CreateEventExW(
    _lpEventAttributes: *const c_void,
    _lpName: *const u16,
    _dwFlags: u32,
    _dwDesiredAccess: u32,
) -> Handle {
    // Default to auto-reset, nonsignaled.
    nt_sync::create_event(false, false)
}

pub extern "win64" fn SetEvent(hEvent: Handle) -> i32 {
    nt_sync::set_event(hEvent)
}

pub extern "win64" fn ResetEvent(hEvent: Handle) -> i32 {
    nt_sync::reset_event(hEvent)
}

pub extern "win64" fn CreateSemaphoreA(
    _lpSemaphoreAttributes: *const c_void,
    lInitialCount: i32,
    lMaximumCount: i32,
    _lpName: *const i8,
) -> Handle {
    nt_sync::create_semaphore(lInitialCount, lMaximumCount)
}

pub extern "win64" fn CreateSemaphoreW(
    _lpSemaphoreAttributes: *const c_void,
    lInitialCount: i32,
    lMaximumCount: i32,
    _lpName: *const u16,
) -> Handle {
    nt_sync::create_semaphore(lInitialCount, lMaximumCount)
}

pub extern "win64" fn CreateSemaphoreExW(
    _lpSemaphoreAttributes: *const c_void,
    lInitialCount: i32,
    lMaximumCount: i32,
    _lpName: *const u16,
    _dwFlags: u32,
    _dwDesiredAccess: u32,
) -> Handle {
    nt_sync::create_semaphore(lInitialCount, lMaximumCount)
}

pub extern "win64" fn ReleaseSemaphore(
    hSemaphore: Handle,
    lReleaseCount: i32,
    lpPreviousCount: *mut i32,
) -> i32 {
    nt_sync::release_semaphore(hSemaphore, lReleaseCount, lpPreviousCount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use std::time::Duration;

    #[test]
    fn critical_section_is_recursive_on_same_thread() {
        let _guard = serial_guard();
        let mut storage = [0_u8; 64];
        let ptr = storage.as_mut_ptr().cast::<c_void>();

        InitializeCriticalSection(ptr);
        EnterCriticalSection(ptr);
        EnterCriticalSection(ptr);
        LeaveCriticalSection(ptr);
        LeaveCriticalSection(ptr);
        DeleteCriticalSection(ptr);
    }

    #[test]
    fn critical_section_variants_report_success() {
        let _guard = serial_guard();
        let mut storage = [0_u8; 64];
        let ptr = storage.as_mut_ptr().cast::<c_void>();

        assert_eq!(InitializeCriticalSectionAndSpinCount(ptr, 0), 1);
        assert_eq!(InitializeCriticalSectionEx(ptr, 0, 0), 1);
        DeleteCriticalSection(ptr);
    }

    #[test]
    fn wait_for_multiple_objects_returns_first_signaled_index() {
        let _guard = serial_guard();
        let first = nt_sync::create_event(false, false);
        let second = nt_sync::create_event(false, false);
        assert_ne!(first, 0);
        assert_ne!(second, 0);

        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            nt_sync::set_event(second);
        });

        let handles = [first as usize, second as usize];
        let result = WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 1000);
        worker.join().expect("worker should finish");
        assert_eq!(result, nt_sync::WAIT_OBJECT_0 + 1);
    }

    #[test]
    fn wait_for_multiple_objects_accepts_pointer_sized_thread_handles() {
        let _guard = serial_guard();

        unsafe extern "win64" fn worker(arg: *mut c_void) -> u32 {
            arg as usize as u32
        }

        let first = crate::nt_kernel::thread::create_thread(
            std::ptr::null(),
            0,
            worker as *const c_void,
            1usize as *mut c_void,
            0,
            std::ptr::null_mut(),
        );
        let second = crate::nt_kernel::thread::create_thread(
            std::ptr::null(),
            0,
            worker as *const c_void,
            2usize as *mut c_void,
            0,
            std::ptr::null_mut(),
        );

        let handles = [first as usize, second as usize];
        let result = WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 1, 1000);
        assert_eq!(result, nt_sync::WAIT_OBJECT_0);
    }

    #[test]
    fn slist_push_pop_flush_and_depth_round_trip() {
        let _guard = serial_guard();

        let mut head = [0_u64; 2];
        let mut entry1 = [0_usize; 1];
        let mut entry2 = [0_usize; 1];
        let list_head = head.as_mut_ptr().cast::<c_void>();

        InitializeSListHead(list_head);
        assert_eq!(QueryDepthSList(list_head), 0);
        assert!(InterlockedPopEntrySList(list_head).is_null());

        let prev1 = InterlockedPushEntrySList(list_head, entry1.as_mut_ptr().cast::<c_void>());
        assert!(prev1.is_null());
        assert_eq!(QueryDepthSList(list_head), 1);

        let prev2 = InterlockedPushEntrySList(list_head, entry2.as_mut_ptr().cast::<c_void>());
        assert_eq!(prev2, entry1.as_mut_ptr().cast::<c_void>());
        assert_eq!(QueryDepthSList(list_head), 2);

        let pop1 = InterlockedPopEntrySList(list_head);
        assert_eq!(pop1, entry2.as_mut_ptr().cast::<c_void>());
        assert_eq!(QueryDepthSList(list_head), 1);

        let flushed = InterlockedFlushSList(list_head);
        assert_eq!(flushed, entry1.as_mut_ptr().cast::<c_void>());
        assert_eq!(QueryDepthSList(list_head), 0);
        assert!(InterlockedPopEntrySList(list_head).is_null());
    }
}
