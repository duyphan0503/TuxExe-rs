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
}
