#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::type_complexity)]

use std::{
    collections::{HashMap, VecDeque},
    ffi::{c_void, CStr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, OnceLock, RwLock,
    },
    time::{Duration, Instant},
};

use crate::{
    nt_kernel::sync as nt_sync,
    utils::{
        handle::{global_table, Handle, HandleObject, INVALID_HANDLE_VALUE},
        wide_string::from_wide_ptr,
    },
};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ALREADY_EXISTS: u32 = 183;
const CREATE_WAITABLE_TIMER_MANUAL_RESET: u32 = 0x0000_0001;

#[repr(C)]
#[derive(Debug)]
struct TimerQueueHandleObject;

type WaitOrTimerCallback = unsafe extern "system" fn(*mut c_void, i32);

#[repr(C)]
#[derive(Debug)]
struct TimerQueueTimerHandleObject {
    cancelled: AtomicBool,
    callback: Option<WaitOrTimerCallback>,
    parameter: usize,
}

#[derive(Debug)]
struct WaitRegistrationHandleObject {
    cancelled: AtomicBool,
}

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

#[derive(Debug, Default)]
struct SrwLockState {
    exclusive_owner: Option<u32>,
    shared_holders: HashMap<u32, u32>,
}

#[derive(Debug, Default)]
struct ConditionVariableState {
    generation: u64,
}

fn srw_locks() -> &'static RwLock<HashMap<usize, Arc<(Mutex<SrwLockState>, Condvar)>>> {
    static TABLE: OnceLock<RwLock<HashMap<usize, Arc<(Mutex<SrwLockState>, Condvar)>>>> =
        OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn condition_variables(
) -> &'static RwLock<HashMap<usize, Arc<(Mutex<ConditionVariableState>, Condvar)>>> {
    static TABLE: OnceLock<RwLock<HashMap<usize, Arc<(Mutex<ConditionVariableState>, Condvar)>>>> =
        OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(HashMap::new()))
}

#[derive(Debug, Default, Clone, Copy)]
struct SListState {
    head: usize,
    depth: u16,
    sequence: u64,
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

/// Persist the x64 `SLIST_HEADER` alongside the host-side lock.  Windows
/// callers are allowed to inspect this header directly (and Mono does so in
/// its allocator fast paths), so keeping the state only in a Rust map turns a
/// successful `InterlockedPushEntrySList` into a later use of an uninitialised
/// free-list pointer.  On 64-bit user mode Windows the `Header16` view is in
/// use: word 0 is `Depth|Sequence`; word 1 is
/// `HeaderType|Init|Reserved:2|NextEntry:60`.  `NextEntry` is the original
/// 16-byte-aligned pointer, stored in bits 4..63 (the low four bits are the
/// flags), rather than a pointer compressed by four bits.
unsafe fn write_slist_header(list_head: *mut c_void, state: SListState) {
    const HEADER_TYPE_BIT: u64 = 1;
    const INIT_BIT: u64 = 1 << 1;

    // Header16 reserves the upper 48 bits of word 0 for the sequence.
    let first = (state.depth as u64) | (state.sequence << 16);
    let second = (state.head as u64 & !0xf) | HEADER_TYPE_BIT | INIT_BIT;
    unsafe {
        list_head.cast::<u64>().write_unaligned(first);
        list_head.cast::<u8>().add(8).cast::<u64>().write_unaligned(second);
    }
}

/// Read the guest-visible x64 `SLIST_HEADER` back into its logical form.
///
/// Mono emits lock-free SList operations directly in JIT code, so the header
/// can change without passing through our exported Interlocked* functions.
/// Treating the Rust side table as authoritative in that situation loses
/// entries that Mono has just linked and eventually exposes a stale/free-list
/// pointer to its allocator.  The header must therefore be the source of
/// truth whenever an exported SList function is entered.
unsafe fn read_slist_header(list_head: *mut c_void) -> SListState {
    let first = unsafe { list_head.cast::<u64>().read_unaligned() };
    let second = unsafe { list_head.cast::<u8>().add(8).cast::<u64>().read_unaligned() };

    SListState {
        head: (second & !0xf) as usize,
        depth: first as u16,
        sequence: first >> 16,
    }
}

fn current_thread_id() -> u32 {
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

#[derive(Debug, Clone, Copy)]
struct IoCompletionPacket {
    bytes_transferred: u32,
    completion_key: usize,
    overlapped: usize,
}

#[derive(Debug, Default)]
struct IoCompletionPortState {
    queue: VecDeque<IoCompletionPacket>,
}

#[derive(Debug)]
struct IoCompletionPortHandleObject {
    state: Arc<(Mutex<IoCompletionPortState>, Condvar)>,
}

impl IoCompletionPortHandleObject {
    fn new() -> Self {
        Self { state: Arc::new((Mutex::new(IoCompletionPortState::default()), Condvar::new())) }
    }

    fn post(&self, packet: IoCompletionPacket) {
        let (lock, condvar) = &*self.state;
        let mut guard = lock.lock().expect("iocp state poisoned");
        guard.queue.push_back(packet);
        condvar.notify_one();
    }

    fn dequeue(&self, timeout_ms: u32) -> Option<IoCompletionPacket> {
        let (lock, condvar) = &*self.state;
        let mut guard = lock.lock().expect("iocp state poisoned");

        if let Some(packet) = guard.queue.pop_front() {
            return Some(packet);
        }

        if timeout_ms == nt_sync::INFINITE {
            while guard.queue.is_empty() {
                guard = condvar.wait(guard).expect("iocp state poisoned");
            }
            return guard.queue.pop_front();
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while guard.queue.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, timeout) =
                condvar.wait_timeout(guard, remaining).expect("iocp state poisoned");
            guard = next;
            if timeout.timed_out() && guard.queue.is_empty() {
                return None;
            }
        }
        guard.queue.pop_front()
    }
}

impl HandleObject for IoCompletionPortHandleObject {
    fn type_name(&self) -> &'static str {
        "IoCompletionPortHandle"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HandleObject for TimerQueueHandleObject {
    fn type_name(&self) -> &'static str {
        "TimerQueueHandle"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HandleObject for TimerQueueTimerHandleObject {
    fn type_name(&self) -> &'static str {
        "TimerQueueTimerHandle"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HandleObject for WaitRegistrationHandleObject {
    fn type_name(&self) -> &'static str {
        "WaitRegistrationHandle"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn spawn_timer_queue_worker(timer_handle: Handle, due_time_ms: u32, period_ms: u32) {
    std::thread::spawn(move || {
        if due_time_ms > 0 {
            std::thread::sleep(Duration::from_millis(due_time_ms as u64));
        }

        loop {
            let keep_running = global_table()
                .with(timer_handle, |obj| {
                    obj.as_any()
                        .downcast_ref::<TimerQueueTimerHandleObject>()
                        .map(|timer| {
                            if timer.cancelled.load(Ordering::Acquire) {
                                return false;
                            }

                            if let Some(callback) = timer.callback {
                                unsafe {
                                    callback(timer.parameter as *mut c_void, 1);
                                }
                            }
                            true
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            if !keep_running || period_ms == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(period_ms as u64));
        }
    });
}

fn get_or_create_srw_lock(ptr: *mut c_void) -> Arc<(Mutex<SrwLockState>, Condvar)> {
    let key = ptr as usize;

    if let Some(entry) = srw_locks().read().expect("srw lock table poisoned").get(&key) {
        return Arc::clone(entry);
    }

    let entry = Arc::new((Mutex::new(SrwLockState::default()), Condvar::new()));
    srw_locks().write().expect("srw lock table poisoned").insert(key, Arc::clone(&entry));
    entry
}

fn get_or_create_critical_section(
    ptr: *mut c_void,
) -> Arc<(Mutex<CriticalSectionState>, Condvar)> {
    let key = ptr as usize;
    if let Some(entry) = critical_sections()
        .read()
        .expect("critical section table poisoned")
        .get(&key)
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

fn get_or_create_condition_variable(
    ptr: *mut c_void,
) -> Arc<(Mutex<ConditionVariableState>, Condvar)> {
    let key = ptr as usize;
    if let Some(entry) =
        condition_variables().read().expect("condition variable table poisoned").get(&key)
    {
        return Arc::clone(entry);
    }

    let entry = Arc::new((Mutex::new(ConditionVariableState::default()), Condvar::new()));
    condition_variables()
        .write()
        .expect("condition variable table poisoned")
        .insert(key, Arc::clone(&entry));
    entry
}

pub fn reset_srw_lock(ptr: *mut c_void) {
    if !ptr.is_null() {
        srw_locks().write().expect("srw lock table poisoned").remove(&(ptr as usize));
    }
}

pub fn reset_condition_variable(ptr: *mut c_void) {
    if !ptr.is_null() {
        condition_variables()
            .write()
            .expect("condition variable table poisoned")
            .remove(&(ptr as usize));
    }
}

pub fn sleep_condition_variable_with_unlock<F>(
    condition_variable: *mut c_void,
    timeout_ms: u32,
    unlock: F,
) -> bool
where
    F: FnOnce(),
{
    if condition_variable.is_null() {
        return false;
    }

    let entry = get_or_create_condition_variable(condition_variable);
    let (lock, condvar) = &*entry;
    let guard = lock.lock().expect("condition variable state poisoned");
    let generation = guard.generation;

    // Hold the condition state mutex while releasing the caller's lock. A
    // waker increments this generation under the same mutex, so it cannot be
    // lost in the release-to-wait gap.
    unlock();

    if timeout_ms == nt_sync::INFINITE {
        drop(
            condvar
                .wait_while(guard, |state| state.generation == generation)
                .expect("condition variable state poisoned"),
        );
        return true;
    }

    let timeout = Duration::from_millis(timeout_ms as u64);
    let (guard, _) = condvar
        .wait_timeout_while(guard, timeout, |state| state.generation == generation)
        .expect("condition variable state poisoned");
    guard.generation != generation
}

pub fn sleep_condition_variable(condition_variable: *mut c_void, timeout_ms: u32) -> bool {
    sleep_condition_variable_with_unlock(condition_variable, timeout_ms, || {})
}

pub fn wake_condition_variable(condition_variable: *mut c_void, wake_all: bool) {
    if condition_variable.is_null() {
        return;
    }

    let entry = get_or_create_condition_variable(condition_variable);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("condition variable state poisoned");
    guard.generation = guard.generation.wrapping_add(1);
    drop(guard);
    if wake_all {
        condvar.notify_all();
    } else {
        condvar.notify_one();
    }
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
    let state = SListState::default();
    slist_states().write().expect("slist table poisoned").insert(key, state);
    unsafe { write_slist_header(list_head, state) };
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
    // The table is only a host-side lock.  Do not use its previous value:
    // native/JIT SList instructions may have updated this guest header since
    // our last call.
    let state = guard.entry(key).or_insert_with(|| unsafe { read_slist_header(list_head) });
    *state = unsafe { read_slist_header(list_head) };
    let previous_head = state.head;

    // SAFETY: list_entry points to caller-owned SLIST_ENTRY storage.
    unsafe {
        set_slist_entry_next(list_entry, previous_head);
    }

    state.head = list_entry as usize;
    state.depth = state.depth.saturating_add(1);
    state.sequence = state.sequence.wrapping_add(1);
    unsafe { write_slist_header(list_head, *state) };

    previous_head as *mut c_void
}

pub extern "win64" fn InterlockedPopEntrySList(list_head: *mut c_void) -> *mut c_void {
    if list_head.is_null() {
        return std::ptr::null_mut();
    }

    let key = list_head as usize;
    let mut guard = slist_states().write().expect("slist table poisoned");
    let state = guard.entry(key).or_insert_with(|| unsafe { read_slist_header(list_head) });
    *state = unsafe { read_slist_header(list_head) };
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
    state.sequence = state.sequence.wrapping_add(1);
    unsafe { write_slist_header(list_head, *state) };

    head
}

pub extern "win64" fn InterlockedFlushSList(list_head: *mut c_void) -> *mut c_void {
    if list_head.is_null() {
        return std::ptr::null_mut();
    }

    let key = list_head as usize;
    let mut guard = slist_states().write().expect("slist table poisoned");
    let state = guard.entry(key).or_insert_with(|| unsafe { read_slist_header(list_head) });
    *state = unsafe { read_slist_header(list_head) };
    let old_head = state.head as *mut c_void;
    state.head = 0;
    state.depth = 0;
    state.sequence = state.sequence.wrapping_add(1);
    unsafe { write_slist_header(list_head, *state) };
    old_head
}

pub extern "win64" fn QueryDepthSList(list_head: *mut c_void) -> u16 {
    if list_head.is_null() {
        return 0;
    }

    // Keep this consistent with Mono's inlined lock-free operations as well.
    unsafe { read_slist_header(list_head).depth }
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

pub extern "win64" fn TryEnterCriticalSection(lpCriticalSection: *mut c_void) -> i32 {
    if lpCriticalSection.is_null() {
        return 0;
    }

    let entry = get_or_create_critical_section(lpCriticalSection);
    let (lock, _) = &*entry;
    let Ok(mut guard) = lock.try_lock() else {
        return 0;
    };

    let current_tid = current_thread_id();
    if matches!(guard.owner_tid, Some(owner) if owner != current_tid) {
        return 0;
    }

    guard.owner_tid = Some(current_tid);
    guard.recursion_count = guard.recursion_count.saturating_add(1);
    1
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
    if !lpCriticalSection.is_null() {
        critical_sections()
            .write()
            .expect("critical section table poisoned")
            .remove(&(lpCriticalSection as usize));
    }
}

pub extern "win64" fn AcquireSRWLockExclusive(SRWLock: *mut c_void) {
    if SRWLock.is_null() {
        return;
    }

    let entry = get_or_create_srw_lock(SRWLock);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("srw lock state poisoned");
    let current_tid = current_thread_id();

    while guard.exclusive_owner.is_some() || !guard.shared_holders.is_empty() {
        guard = condvar.wait(guard).expect("srw lock state poisoned");
    }

    guard.exclusive_owner = Some(current_tid);
}

pub extern "win64" fn TryAcquireSRWLockExclusive(SRWLock: *mut c_void) -> i32 {
    if SRWLock.is_null() {
        return 0;
    }

    let entry = get_or_create_srw_lock(SRWLock);
    let (lock, _) = &*entry;
    let mut guard = lock.lock().expect("srw lock state poisoned");
    if guard.exclusive_owner.is_some() || !guard.shared_holders.is_empty() {
        return 0;
    }

    guard.exclusive_owner = Some(current_thread_id());
    1
}

pub extern "win64" fn ReleaseSRWLockExclusive(SRWLock: *mut c_void) {
    if SRWLock.is_null() {
        return;
    }

    let entry = get_or_create_srw_lock(SRWLock);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("srw lock state poisoned");
    if guard.exclusive_owner == Some(current_thread_id()) {
        guard.exclusive_owner = None;
        condvar.notify_one();
    }
}

pub extern "win64" fn AcquireSRWLockShared(SRWLock: *mut c_void) {
    if SRWLock.is_null() {
        return;
    }

    let entry = get_or_create_srw_lock(SRWLock);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("srw lock state poisoned");
    while guard.exclusive_owner.is_some() {
        guard = condvar.wait(guard).expect("srw lock state poisoned");
    }
    let tid = current_thread_id();
    *guard.shared_holders.entry(tid).or_default() += 1;
}

pub extern "win64" fn ReleaseSRWLockShared(SRWLock: *mut c_void) {
    if SRWLock.is_null() {
        return;
    }

    let entry = get_or_create_srw_lock(SRWLock);
    let (lock, condvar) = &*entry;
    let mut guard = lock.lock().expect("srw lock state poisoned");
    let tid = current_thread_id();
    if let Some(depth) = guard.shared_holders.get_mut(&tid) {
        *depth -= 1;
        if *depth == 0 {
            guard.shared_holders.remove(&tid);
            condvar.notify_all();
        }
    }
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

pub extern "win64" fn SignalObjectAndWait(
    hObjectToSignal: Handle,
    hObjectToWaitOn: Handle,
    dwMilliseconds: u32,
    bAlertable: i32,
) -> u32 {
    let signaled = nt_sync::set_event(hObjectToSignal) == 1
        || nt_sync::release_mutex(hObjectToSignal) == 1
        || nt_sync::release_semaphore(hObjectToSignal, 1, std::ptr::null_mut()) == 1;

    if !signaled {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return nt_sync::WAIT_FAILED;
    }

    WaitForSingleObjectEx(hObjectToWaitOn, dwMilliseconds, bAlertable)
}

pub extern "win64" fn CreateMutexA(
    _lpMutexAttributes: *const c_void,
    bInitialOwner: i32,
    lpName: *const i8,
) -> Handle {
    let name = if lpName.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(lpName) }.to_str() {
            Ok(name) => Some(name),
            Err(_) => {
                crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    };
    let (handle, _existed) = nt_sync::create_named_mutex(name, bInitialOwner != 0);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn CreateMutexW(
    _lpMutexAttributes: *const c_void,
    bInitialOwner: i32,
    lpName: *const u16,
) -> Handle {
    let name = if lpName.is_null() {
        None
    } else {
        match unsafe { from_wide_ptr(lpName) } {
            Ok(name) => Some(name),
            Err(_) => {
                crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    };
    let (handle, _existed) = nt_sync::create_named_mutex(name.as_deref(), bInitialOwner != 0);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn OpenMutexW(
    _desired_access: u32,
    _inherit_handle: i32,
    name: *const u16,
) -> Handle {
    if name.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Ok(name) = (unsafe { from_wide_ptr(name) }) else {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    match nt_sync::open_named_mutex(&name) {
        Some(handle) => {
            crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
            handle
        }
        None => {
            crate::win32::kernel32::error::set_last_error(ERROR_FILE_NOT_FOUND);
            0
        }
    }
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

pub extern "win64" fn OpenEventA(
    _dwDesiredAccess: u32,
    _bInheritHandle: i32,
    _lpName: *const i8,
) -> Handle {
    // Named kernel object namespace is not implemented yet.
    // Return a valid event handle so startup compatibility checks can proceed.
    let handle = nt_sync::create_event(false, false);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn OpenEventW(
    _dwDesiredAccess: u32,
    _bInheritHandle: i32,
    _lpName: *const u16,
) -> Handle {
    let handle = nt_sync::create_event(false, false);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn CreateWaitableTimerA(
    _lpTimerAttributes: *const c_void,
    bManualReset: i32,
    _lpTimerName: *const i8,
) -> Handle {
    let handle = nt_sync::create_event(bManualReset != 0, false);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn CreateWaitableTimerExW(
    _lpTimerAttributes: *const c_void,
    _lpTimerName: *const u16,
    dwFlags: u32,
    _dwDesiredAccess: u32,
) -> Handle {
    let manual_reset = (dwFlags & CREATE_WAITABLE_TIMER_MANUAL_RESET) != 0;
    let handle = nt_sync::create_event(manual_reset, false);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn SetWaitableTimer(
    hTimer: Handle,
    lpDueTime: *const i64,
    lPeriod: i32,
    _pfnCompletionRoutine: *const c_void,
    _lpArgToCompletionRoutine: *const c_void,
    _fResume: i32,
) -> i32 {
    if lpDueTime.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let due_time = unsafe { *lpDueTime };
    let initial_delay_ms = if due_time < 0 { ((-due_time) as u64) / 10_000 } else { 0 };

    // Validate handle up front.
    if nt_sync::set_event(hTimer) == 0 && nt_sync::reset_event(hTimer) == 0 {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    // Reset before arming to mimic unsignaled timer state.
    let _ = nt_sync::reset_event(hTimer);

    std::thread::spawn(move || {
        if initial_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(initial_delay_ms));
        }
        let _ = nt_sync::set_event(hTimer);

        if lPeriod > 0 {
            let period = Duration::from_millis(lPeriod as u64);
            loop {
                std::thread::sleep(period);
                if nt_sync::set_event(hTimer) == 0 {
                    break;
                }
            }
        }
    });

    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
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
    lpName: *const u16,
) -> Handle {
    let name = if lpName.is_null() {
        None
    } else {
        match unsafe { from_wide_ptr(lpName) } {
            Ok(name) => Some(name),
            Err(_) => {
                crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    };
    let (handle, existed) =
        nt_sync::create_named_semaphore(name.as_deref(), lInitialCount, lMaximumCount);
    crate::win32::kernel32::error::set_last_error(if existed {
        ERROR_ALREADY_EXISTS
    } else {
        ERROR_SUCCESS
    });
    handle
}

pub extern "win64" fn OpenSemaphoreW(
    _desired_access: u32,
    _inherit_handle: i32,
    name: *const u16,
) -> Handle {
    if name.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Ok(name) = (unsafe { from_wide_ptr(name) }) else {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    match nt_sync::open_named_semaphore(&name) {
        Some(handle) => {
            crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
            handle
        }
        None => {
            crate::win32::kernel32::error::set_last_error(ERROR_FILE_NOT_FOUND);
            0
        }
    }
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

pub extern "win64" fn CreateTimerQueue() -> Handle {
    let handle = global_table().alloc(Box::new(TimerQueueHandleObject));
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    handle
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CreateTimerQueueTimer(
    phNewTimer: *mut Handle,
    _TimerQueue: Handle,
    Callback: *const c_void,
    Parameter: *mut c_void,
    DueTime: u32,
    Period: u32,
    _Flags: u32,
) -> i32 {
    if phNewTimer.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let callback = if Callback.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*const c_void, WaitOrTimerCallback>(Callback) })
    };

    let timer_handle = global_table().alloc(Box::new(TimerQueueTimerHandleObject {
        cancelled: AtomicBool::new(false),
        callback,
        parameter: Parameter as usize,
    }));

    unsafe {
        *phNewTimer = timer_handle;
    }
    spawn_timer_queue_worker(timer_handle, DueTime, Period);
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn ChangeTimerQueueTimer(
    _TimerQueue: Handle,
    Timer: Handle,
    _DueTime: u32,
    _Period: u32,
) -> i32 {
    let ok = global_table()
        .with(Timer, |obj| obj.as_any().is::<TimerQueueTimerHandleObject>())
        .unwrap_or(false);
    if !ok {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DeleteTimerQueueTimer(
    _TimerQueue: Handle,
    Timer: Handle,
    _CompletionEvent: Handle,
) -> i32 {
    let ok = global_table()
        .with(Timer, |obj| {
            obj.as_any().downcast_ref::<TimerQueueTimerHandleObject>().map(|timer| {
                timer.cancelled.store(true, Ordering::Release);
                true
            })
        })
        .flatten()
        .unwrap_or(false);

    if !ok {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn RegisterWaitForSingleObject(
    phNewWaitObject: *mut Handle,
    hObject: Handle,
    Callback: *const c_void,
    Context: *mut c_void,
    dwMilliseconds: u32,
    _dwFlags: u32,
) -> i32 {
    if phNewWaitObject.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let callback = if Callback.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*const c_void, WaitOrTimerCallback>(Callback) })
    };

    let wait_handle = global_table()
        .alloc(Box::new(WaitRegistrationHandleObject { cancelled: AtomicBool::new(false) }));
    unsafe {
        *phNewWaitObject = wait_handle;
    }

    let context = Context as usize;
    std::thread::spawn(move || {
        let wait_result = WaitForSingleObject(hObject, dwMilliseconds);
        let timed_out = (wait_result == nt_sync::WAIT_TIMEOUT) as i32;
        let cancelled = global_table()
            .with(wait_handle, |obj| {
                obj.as_any()
                    .downcast_ref::<WaitRegistrationHandleObject>()
                    .map(|reg| reg.cancelled.load(Ordering::Acquire))
                    .unwrap_or(true)
            })
            .unwrap_or(true);
        if cancelled {
            return;
        }

        if let Some(cb) = callback {
            unsafe {
                cb(context as *mut c_void, timed_out);
            }
        }
    });

    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn UnregisterWait(WaitHandle: Handle) -> i32 {
    let ok = global_table()
        .with(WaitHandle, |obj| {
            obj.as_any().downcast_ref::<WaitRegistrationHandleObject>().map(|reg| {
                reg.cancelled.store(true, Ordering::Release);
                true
            })
        })
        .flatten()
        .unwrap_or(false);

    if !ok {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn UnregisterWaitEx(WaitHandle: Handle, _CompletionEvent: Handle) -> i32 {
    UnregisterWait(WaitHandle)
}

pub extern "win64" fn CreateIoCompletionPort(
    _file_handle: Handle,
    existing_completion_port: Handle,
    _completion_key: usize,
    _number_of_concurrent_threads: u32,
) -> Handle {
    if existing_completion_port != 0 && existing_completion_port != INVALID_HANDLE_VALUE {
        crate::win32::kernel32::error::set_last_error(0);
        return existing_completion_port;
    }

    let handle = global_table().alloc(Box::new(IoCompletionPortHandleObject::new()));
    crate::win32::kernel32::error::set_last_error(0);
    handle
}

pub extern "win64" fn PostQueuedCompletionStatus(
    completion_port: Handle,
    dw_number_of_bytes_transferred: u32,
    dw_completion_key: usize,
    lp_overlapped: *mut c_void,
) -> i32 {
    let ok = global_table().with(completion_port, |obj| {
        obj.as_any()
            .downcast_ref::<IoCompletionPortHandleObject>()
            .map(|port| {
                port.post(IoCompletionPacket {
                    bytes_transferred: dw_number_of_bytes_transferred,
                    completion_key: dw_completion_key,
                    overlapped: lp_overlapped as usize,
                });
                true
            })
            .unwrap_or(false)
    });

    if ok == Some(true) {
        crate::win32::kernel32::error::set_last_error(0);
        1
    } else {
        crate::win32::kernel32::error::set_last_error(6); // ERROR_INVALID_HANDLE
        0
    }
}

pub extern "win64" fn GetQueuedCompletionStatus(
    completion_port: Handle,
    lp_number_of_bytes_transferred: *mut u32,
    lp_completion_key: *mut usize,
    lp_overlapped: *mut *mut c_void,
    dw_milliseconds: u32,
) -> i32 {
    let packet = global_table().with(completion_port, |obj| {
        obj.as_any()
            .downcast_ref::<IoCompletionPortHandleObject>()
            .and_then(|port| port.dequeue(dw_milliseconds))
    });

    let Some(Some(packet)) = packet else {
        if packet.is_none() {
            crate::win32::kernel32::error::set_last_error(6); // ERROR_INVALID_HANDLE
        } else {
            crate::win32::kernel32::error::set_last_error(nt_sync::WAIT_TIMEOUT);
        }
        if !lp_overlapped.is_null() {
            unsafe {
                *lp_overlapped = std::ptr::null_mut();
            }
        }
        return 0;
    };

    if !lp_number_of_bytes_transferred.is_null() {
        unsafe {
            *lp_number_of_bytes_transferred = packet.bytes_transferred;
        }
    }
    if !lp_completion_key.is_null() {
        unsafe {
            *lp_completion_key = packet.completion_key;
        }
    }
    if !lp_overlapped.is_null() {
        unsafe {
            *lp_overlapped = packet.overlapped as *mut c_void;
        }
    }
    crate::win32::kernel32::error::set_last_error(0);
    1
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
    fn critical_section_excludes_another_thread_until_release() {
        let _guard = serial_guard();
        let mut storage = [0_u8; 64];
        let ptr = storage.as_mut_ptr().cast::<c_void>();
        InitializeCriticalSection(ptr);
        EnterCriticalSection(ptr);

        let ptr_value = ptr as usize;
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let ptr = ptr_value as *mut c_void;
            result_tx.send(TryEnterCriticalSection(ptr)).expect("send contention result");
            continue_rx.recv().expect("wait for release");
            let acquired = TryEnterCriticalSection(ptr);
            if acquired != 0 {
                LeaveCriticalSection(ptr);
            }
            result_tx.send(acquired).expect("send post-release result");
        });

        assert_eq!(result_rx.recv().expect("receive contention result"), 0);
        LeaveCriticalSection(ptr);
        continue_tx.send(()).expect("release worker");
        assert_eq!(result_rx.recv().expect("receive post-release result"), 1);
        worker.join().expect("critical-section worker should finish");
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
        // Windows requires SLIST_ENTRY storage to be 16-byte aligned because
        // the low four Header16 bits are reserved for SList metadata.
        let mut entry1 = [0_u128; 1];
        let mut entry2 = [0_u128; 1];
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

    #[test]
    fn slist_operations_publish_the_windows_header() {
        let _guard = serial_guard();
        let mut header = [u8::MAX; 16];
        let list_head = header.as_mut_ptr().cast::<c_void>();
        let mut entry = [0u128; 1];

        InitializeSListHead(list_head);
        assert_eq!(unsafe { list_head.cast::<u64>().read_unaligned() }, 0);
        assert_eq!(
            unsafe { list_head.cast::<u8>().add(8).cast::<u64>().read_unaligned() },
            0b11u64
        );

        InterlockedPushEntrySList(list_head, entry.as_mut_ptr().cast());
        let packed_depth = unsafe { list_head.cast::<u64>().read_unaligned() };
        let packed_next = unsafe { list_head.cast::<u8>().add(8).cast::<u64>().read_unaligned() };
        assert_eq!(packed_depth as u16, 1);
        assert_eq!(packed_next & !0xf, entry.as_ptr() as usize as u64);
        assert_eq!(packed_next & 0xf, 0b11);

        assert_eq!(InterlockedPopEntrySList(list_head), entry.as_mut_ptr().cast());
        assert_eq!(unsafe { list_head.cast::<u64>().read_unaligned() } as u16, 0);
        assert_eq!(
            unsafe { list_head.cast::<u8>().add(8).cast::<u64>().read_unaligned() },
            0b11
        );
    }

    #[test]
    fn try_acquire_srw_lock_tracks_exclusive_ownership() {
        let _guard = serial_guard();
        let mut storage = 0_usize;
        let lock = (&mut storage as *mut usize).cast::<c_void>();

        assert_eq!(TryAcquireSRWLockExclusive(lock), 1);
        assert_eq!(TryAcquireSRWLockExclusive(lock), 0);
        ReleaseSRWLockExclusive(lock);
        assert_eq!(TryAcquireSRWLockExclusive(lock), 1);
        ReleaseSRWLockExclusive(lock);

        reset_srw_lock(lock);
        assert_eq!(TryAcquireSRWLockExclusive(lock), 1);
        ReleaseSRWLockExclusive(lock);
    }

    #[test]
    fn condition_variable_wakes_waiter_and_reports_timeout() {
        let _guard = serial_guard();
        let mut storage = 0_usize;
        let condition = (&mut storage as *mut usize).cast::<c_void>();

        let condition_for_worker = condition as usize;
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            wake_condition_variable(condition_for_worker as *mut c_void, false);
        });
        assert!(sleep_condition_variable(condition, 1_000));
        worker.join().expect("condition variable worker should finish");
        assert!(!sleep_condition_variable(condition, 1));
    }
}
