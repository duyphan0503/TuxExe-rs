//! Waitable synchronization primitives backed by host mutexes/condvars.

use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
use tracing::warn;

use crate::{
    nt_kernel::thread,
    utils::handle::{global_table, init_global_table, Handle, HandleObject},
};

pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_ABANDONED_0: u32 = 0x80;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
pub const INFINITE: u32 = 0xFFFF_FFFF;

/// Reserved by the TuxExe-flavoured DXVK build for the DXGI frame-latency
/// waitable object. It has no host kernel counterpart; DXVK signals it after
/// each frame, so exposing it as immediately signalled is the compatible
/// fallback until native handle duplication is implemented cross-ABI.
pub const DXVK_FRAME_LATENCY_HANDLE: Handle = 0xd7a1_0001;

#[derive(Debug)]
struct MutexState {
    owner_tid: Option<u32>,
    recursion_count: u32,
}

#[derive(Debug)]
pub struct MutexHandleObject {
    state: Arc<(Mutex<MutexState>, Condvar)>,
}

impl MutexHandleObject {
    fn new(initial_owner: bool) -> Self {
        let owner = if initial_owner { Some(thread::current_os_thread_id()) } else { None };
        Self {
            state: Arc::new((
                Mutex::new(MutexState {
                    owner_tid: owner,
                    recursion_count: if initial_owner { 1 } else { 0 },
                }),
                Condvar::new(),
            )),
        }
    }

    fn from_state(state: Arc<(Mutex<MutexState>, Condvar)>) -> Self {
        Self { state }
    }

    fn release(&self) -> i32 {
        let (lock, condvar) = &*self.state;
        let mut guard = lock.lock().expect("mutex state poisoned");
        if guard.owner_tid != Some(thread::current_os_thread_id()) {
            return 0;
        }

        if guard.recursion_count > 0 {
            guard.recursion_count -= 1;
        }
        if guard.recursion_count == 0 {
            guard.owner_tid = None;
            condvar.notify_one();
        }
        1
    }
}

fn named_mutexes() -> &'static Mutex<HashMap<String, std::sync::Weak<(Mutex<MutexState>, Condvar)>>>
{
    static MUTEXES: std::sync::OnceLock<
        Mutex<HashMap<String, std::sync::Weak<(Mutex<MutexState>, Condvar)>>>,
    > = std::sync::OnceLock::new();
    MUTEXES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn wait_on_mutex_state(state: Arc<(Mutex<MutexState>, Condvar)>, timeout_ms: u32) -> u32 {
    let (lock, condvar) = &*state;
    let mut guard = lock.lock().expect("mutex state poisoned");
    let current_tid = thread::current_os_thread_id();

    let acquired = if timeout_ms == INFINITE {
        while matches!(guard.owner_tid, Some(owner) if owner != current_tid) {
            guard = condvar.wait(guard).expect("mutex state poisoned");
        }
        true
    } else {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while matches!(guard.owner_tid, Some(owner) if owner != current_tid) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, timeout) =
                condvar.wait_timeout(guard, remaining).expect("mutex state poisoned");
            guard = next;
            if timeout.timed_out() {
                break;
            }
        }

        !matches!(guard.owner_tid, Some(owner) if owner != current_tid)
    };

    if !acquired {
        return WAIT_TIMEOUT;
    }

    guard.owner_tid = Some(current_tid);
    guard.recursion_count = guard.recursion_count.saturating_add(1);
    WAIT_OBJECT_0
}

impl HandleObject for MutexHandleObject {
    fn type_name(&self) -> &'static str {
        "MutexHandle"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
struct EventState {
    manual_reset: bool,
    signaled: bool,
}

#[derive(Debug)]
pub struct EventHandleObject {
    state: Arc<(Mutex<EventState>, Condvar)>,
}

impl EventHandleObject {
    fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self {
            state: Arc::new((
                Mutex::new(EventState { manual_reset, signaled: initial_state }),
                Condvar::new(),
            )),
        }
    }

    fn set(&self) -> i32 {
        let (lock, condvar) = &*self.state;
        let mut guard = lock.lock().expect("event state poisoned");
        guard.signaled = true;
        condvar.notify_all();
        1
    }

    fn reset(&self) -> i32 {
        let (lock, _) = &*self.state;
        let mut guard = lock.lock().expect("event state poisoned");
        guard.signaled = false;
        1
    }
}

fn wait_on_event_state(state: Arc<(Mutex<EventState>, Condvar)>, timeout_ms: u32) -> u32 {
    let (lock, condvar) = &*state;
    let mut guard = lock.lock().expect("event state poisoned");

    let signaled = if timeout_ms == INFINITE {
        while !guard.signaled {
            guard = condvar.wait(guard).expect("event state poisoned");
        }
        true
    } else {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while !guard.signaled {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, timeout) =
                condvar.wait_timeout(guard, remaining).expect("event state poisoned");
            guard = next;
            if timeout.timed_out() {
                break;
            }
        }
        guard.signaled
    };

    if !signaled {
        return WAIT_TIMEOUT;
    }

    if !guard.manual_reset {
        guard.signaled = false;
    }

    WAIT_OBJECT_0
}

impl HandleObject for EventHandleObject {
    fn type_name(&self) -> &'static str {
        "EventHandle"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
struct SemaphoreState {
    count: i32,
    max_count: i32,
}

#[derive(Debug)]
pub struct SemaphoreHandleObject {
    state: Arc<(Mutex<SemaphoreState>, Condvar)>,
}

impl SemaphoreHandleObject {
    fn new(initial_count: i32, maximum_count: i32) -> Self {
        Self {
            state: Arc::new((
                Mutex::new(SemaphoreState { count: initial_count, max_count: maximum_count }),
                Condvar::new(),
            )),
        }
    }

    fn from_state(state: Arc<(Mutex<SemaphoreState>, Condvar)>) -> Self {
        Self { state }
    }

    fn release(&self, release_count: i32, previous_count: *mut i32) -> i32 {
        let (lock, condvar) = &*self.state;
        let mut guard = lock.lock().expect("semaphore state poisoned");
        if release_count <= 0 || guard.count + release_count > guard.max_count {
            return 0;
        }

        if !previous_count.is_null() {
            unsafe {
                *previous_count = guard.count;
            }
        }

        guard.count += release_count;
        condvar.notify_all();
        1
    }
}

fn named_semaphores(
) -> &'static Mutex<HashMap<String, std::sync::Weak<(Mutex<SemaphoreState>, Condvar)>>> {
    static SEMAPHORES: std::sync::OnceLock<
        Mutex<HashMap<String, std::sync::Weak<(Mutex<SemaphoreState>, Condvar)>>>,
    > = std::sync::OnceLock::new();
    SEMAPHORES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn wait_on_semaphore_state(state: Arc<(Mutex<SemaphoreState>, Condvar)>, timeout_ms: u32) -> u32 {
    let (lock, condvar) = &*state;
    let mut guard = lock.lock().expect("semaphore state poisoned");

    let acquired = if timeout_ms == INFINITE {
        while guard.count <= 0 {
            guard = condvar.wait(guard).expect("semaphore state poisoned");
        }
        true
    } else {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while guard.count <= 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, timeout) =
                condvar.wait_timeout(guard, remaining).expect("semaphore state poisoned");
            guard = next;
            if timeout.timed_out() {
                break;
            }
        }

        guard.count > 0
    };

    if !acquired {
        return WAIT_TIMEOUT;
    }

    guard.count -= 1;
    WAIT_OBJECT_0
}

impl HandleObject for SemaphoreHandleObject {
    fn type_name(&self) -> &'static str {
        "SemaphoreHandle"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn create_mutex(initial_owner: bool) -> Handle {
    init_global_table();
    global_table().alloc(Box::new(MutexHandleObject::new(initial_owner)))
}

/// Returns `(handle, already_existed)`. Named kernel objects share state but
/// every open receives an independently closeable handle.
pub fn create_named_mutex(name: Option<&str>, initial_owner: bool) -> (Handle, bool) {
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return (create_mutex(initial_owner), false);
    };
    init_global_table();
    let key = name.to_ascii_lowercase();
    let mut named = named_mutexes().lock().expect("named mutex registry poisoned");
    let (state, existed) = match named.get(&key).and_then(std::sync::Weak::upgrade) {
        Some(state) => (state, true),
        None => {
            let state = MutexHandleObject::new(initial_owner).state;
            named.insert(key, Arc::downgrade(&state));
            (state, false)
        }
    };
    let handle = global_table().alloc(Box::new(MutexHandleObject::from_state(state)));
    (handle, existed)
}

pub fn open_named_mutex(name: &str) -> Option<Handle> {
    init_global_table();
    let key = name.to_ascii_lowercase();
    let state = named_mutexes()
        .lock()
        .expect("named mutex registry poisoned")
        .get(&key)
        .and_then(std::sync::Weak::upgrade)?;
    Some(global_table().alloc(Box::new(MutexHandleObject::from_state(state))))
}

pub fn create_event(manual_reset: bool, initial_state: bool) -> Handle {
    init_global_table();
    global_table().alloc(Box::new(EventHandleObject::new(manual_reset, initial_state)))
}

pub fn create_semaphore(initial_count: i32, maximum_count: i32) -> Handle {
    // Be permissive like Windows compatibility layers: some games pass
    // out-of-range values during probing and expect a usable semaphore.
    let mut normalized_initial = initial_count;
    let mut normalized_max = maximum_count;
    if normalized_max <= 0 {
        normalized_max = i32::MAX;
    }
    if normalized_initial < 0 {
        normalized_initial = 0;
    }
    if normalized_initial > normalized_max {
        normalized_initial = normalized_max;
    }
    if normalized_initial != initial_count || normalized_max != maximum_count {
        warn!(
            initial_count,
            maximum_count,
            normalized_initial,
            normalized_max,
            "Normalized CreateSemaphore arguments"
        );
    }

    init_global_table();
    global_table().alloc(Box::new(SemaphoreHandleObject::new(normalized_initial, normalized_max)))
}

pub fn create_named_semaphore(
    name: Option<&str>,
    initial_count: i32,
    maximum_count: i32,
) -> (Handle, bool) {
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return (create_semaphore(initial_count, maximum_count), false);
    };
    let mut normalized_initial = initial_count.max(0);
    let normalized_max = maximum_count.max(1);
    normalized_initial = normalized_initial.min(normalized_max);
    init_global_table();
    let key = name.to_ascii_lowercase();
    let mut named = named_semaphores().lock().expect("named semaphore registry poisoned");
    let (state, existed) = match named.get(&key).and_then(std::sync::Weak::upgrade) {
        Some(state) => (state, true),
        None => {
            let state = SemaphoreHandleObject::new(normalized_initial, normalized_max).state;
            named.insert(key, Arc::downgrade(&state));
            (state, false)
        }
    };
    let handle = global_table().alloc(Box::new(SemaphoreHandleObject::from_state(state)));
    (handle, existed)
}

pub fn open_named_semaphore(name: &str) -> Option<Handle> {
    init_global_table();
    let key = name.to_ascii_lowercase();
    let state = named_semaphores()
        .lock()
        .expect("named semaphore registry poisoned")
        .get(&key)
        .and_then(std::sync::Weak::upgrade)?;
    Some(global_table().alloc(Box::new(SemaphoreHandleObject::from_state(state))))
}

pub fn release_mutex(handle: Handle) -> i32 {
    global_table()
        .with(handle, |object| {
            object.as_any().downcast_ref::<MutexHandleObject>().map(MutexHandleObject::release)
        })
        .flatten()
        .unwrap_or(0)
}

pub fn set_event(handle: Handle) -> i32 {
    global_table()
        .with(handle, |object| {
            object.as_any().downcast_ref::<EventHandleObject>().map(EventHandleObject::set)
        })
        .flatten()
        .unwrap_or(0)
}

pub fn reset_event(handle: Handle) -> i32 {
    global_table()
        .with(handle, |object| {
            object.as_any().downcast_ref::<EventHandleObject>().map(EventHandleObject::reset)
        })
        .flatten()
        .unwrap_or(0)
}

pub fn release_semaphore(handle: Handle, release_count: i32, previous_count: *mut i32) -> i32 {
    global_table()
        .with(handle, |object| {
            object
                .as_any()
                .downcast_ref::<SemaphoreHandleObject>()
                .map(|semaphore| semaphore.release(release_count, previous_count))
        })
        .flatten()
        .unwrap_or(0)
}

pub fn is_signaled(handle: Handle) -> Result<bool, ()> {
    if handle == DXVK_FRAME_LATENCY_HANDLE {
        return Ok(true);
    }
    let current_tid = thread::current_os_thread_id();
    let res = global_table().with(handle, |object| {
        if let Some(th) = object.as_any().downcast_ref::<thread::ThreadHandleObject>() {
            return Ok(th.is_completed());
        }
        if let Some(tr) = object.as_any().downcast_ref::<thread::ThreadReferenceHandleObject>() {
            return Ok(tr.is_completed());
        }
        if let Some(mutex) = object.as_any().downcast_ref::<MutexHandleObject>() {
            let (lock, _) = &*mutex.state;
            let guard = lock.lock().expect("mutex state poisoned");
            let sig = guard.owner_tid.is_none() || guard.owner_tid == Some(current_tid);
            return Ok(sig);
        }
        if let Some(event) = object.as_any().downcast_ref::<EventHandleObject>() {
            let (lock, _) = &*event.state;
            let guard = lock.lock().expect("event state poisoned");
            return Ok(guard.signaled);
        }
        if let Some(semaphore) = object.as_any().downcast_ref::<SemaphoreHandleObject>() {
            let (lock, _) = &*semaphore.state;
            let guard = lock.lock().expect("semaphore state poisoned");
            return Ok(guard.count > 0);
        }
        Err(())
    });
    res.unwrap_or(Err(()))
}

pub fn wait_for_single_object(handle: Handle, timeout_ms: u32) -> u32 {
    if handle == DXVK_FRAME_LATENCY_HANDLE {
        return WAIT_OBJECT_0;
    }

    enum WaitTarget {
        Thread(Handle),
        Mutex(Arc<(Mutex<MutexState>, Condvar)>),
        Event(Arc<(Mutex<EventState>, Condvar)>),
        Semaphore(Arc<(Mutex<SemaphoreState>, Condvar)>),
    }

    let target = global_table().with(handle, |object| {
        if object.as_any().is::<thread::ThreadHandleObject>()
            || object.as_any().is::<thread::ThreadReferenceHandleObject>()
        {
            return Some(WaitTarget::Thread(handle));
        }
        if let Some(mutex) = object.as_any().downcast_ref::<MutexHandleObject>() {
            return Some(WaitTarget::Mutex(mutex.state.clone()));
        }
        if let Some(event) = object.as_any().downcast_ref::<EventHandleObject>() {
            return Some(WaitTarget::Event(event.state.clone()));
        }
        if let Some(semaphore) = object.as_any().downcast_ref::<SemaphoreHandleObject>() {
            return Some(WaitTarget::Semaphore(semaphore.state.clone()));
        }
        None
    });

    match target.flatten() {
        Some(WaitTarget::Thread(thread_handle)) => {
            thread::wait_for_thread(thread_handle, timeout_ms)
        }
        Some(WaitTarget::Mutex(state)) => wait_on_mutex_state(state, timeout_ms),
        Some(WaitTarget::Event(state)) => wait_on_event_state(state, timeout_ms),
        Some(WaitTarget::Semaphore(state)) => wait_on_semaphore_state(state, timeout_ms),
        None => WAIT_FAILED,
    }
}

pub fn wait_for_multiple_objects(handles: &[Handle], wait_all: bool, timeout_ms: u32) -> u32 {
    if handles.is_empty() {
        return WAIT_FAILED;
    }

    for handle in handles {
        if is_signaled(*handle).is_err() {
            return WAIT_FAILED;
        }
    }

    let deadline = if timeout_ms == INFINITE {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
    };

    if wait_all {
        let mut loop_count = 0u32;
        loop {
            let mut all_signaled = true;
            for handle in handles {
                match is_signaled(*handle) {
                    Ok(true) => {}
                    Ok(false) => {
                        all_signaled = false;
                        break;
                    }
                    Err(()) => return WAIT_FAILED,
                }
            }

            if all_signaled {
                for handle in handles {
                    let result = wait_for_single_object(*handle, 0);
                    if result != WAIT_OBJECT_0 {
                        all_signaled = false;
                        break;
                    }
                }
                if all_signaled {
                    return WAIT_OBJECT_0;
                }
            }

            if let Some(end) = deadline {
                if Instant::now() >= end {
                    return WAIT_TIMEOUT;
                }
            }

            loop_count = loop_count.saturating_add(1);
            if loop_count < 16 {
                std::hint::spin_loop();
            } else if loop_count < 32 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(Duration::from_micros(50));
            }
        }
    }

    let mut loop_count = 0u32;
    loop {
        for (index, handle) in handles.iter().enumerate() {
            if wait_for_single_object(*handle, 0) == WAIT_OBJECT_0 {
                return WAIT_OBJECT_0 + index as u32;
            }
        }

        if let Some(end) = deadline {
            if Instant::now() >= end {
                return WAIT_TIMEOUT;
            }
        }

        loop_count = loop_count.saturating_add(1);
        if loop_count < 16 {
            std::hint::spin_loop();
        } else if loop_count < 32 {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_micros(50));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use crate::utils::handle::INVALID_HANDLE_VALUE;

    #[test]
    fn event_can_be_set_and_waited() {
        let _guard = serial_guard();
        let event = create_event(false, false);
        assert_ne!(event, INVALID_HANDLE_VALUE);

        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(set_event(event), 1);
        });

        assert_eq!(wait_for_single_object(event, INFINITE), WAIT_OBJECT_0);
        worker.join().expect("worker should finish");
    }

    #[test]
    fn semaphore_release_and_wait_round_trip() {
        let _guard = serial_guard();
        let semaphore = create_semaphore(0, 2);
        assert_ne!(semaphore, INVALID_HANDLE_VALUE);
        assert_eq!(wait_for_single_object(semaphore, 10), WAIT_TIMEOUT);
        assert_eq!(release_semaphore(semaphore, 1, std::ptr::null_mut()), 1);
        assert_eq!(wait_for_single_object(semaphore, INFINITE), WAIT_OBJECT_0);
    }

    #[test]
    fn mutex_is_recursive_for_same_thread() {
        let _guard = serial_guard();
        let mutex = create_mutex(false);
        assert_ne!(mutex, INVALID_HANDLE_VALUE);
        assert_eq!(wait_for_single_object(mutex, INFINITE), WAIT_OBJECT_0);
        assert_eq!(wait_for_single_object(mutex, INFINITE), WAIT_OBJECT_0);
        assert_eq!(release_mutex(mutex), 1);
        assert_eq!(release_mutex(mutex), 1);
    }

    #[test]
    fn wait_for_multiple_objects_wait_all_preserves_auto_reset_events_until_all_signaled() {
        let _guard = serial_guard();
        let ev1 = create_event(false, false); // auto-reset
        let ev2 = create_event(false, false); // auto-reset

        set_event(ev1);
        // ev1 is signaled, ev2 is not. wait_all should timeout without consuming ev1.
        assert_eq!(wait_for_multiple_objects(&[ev1, ev2], true, 10), WAIT_TIMEOUT);

        // Verify ev1 is still signaled!
        assert_eq!(is_signaled(ev1), Ok(true));

        // Now set ev2, and wait_all should succeed and atomically consume both ev1 and ev2.
        set_event(ev2);
        assert_eq!(wait_for_multiple_objects(&[ev1, ev2], true, 100), WAIT_OBJECT_0);

        // Verify both auto-reset events were consumed
        assert_eq!(is_signaled(ev1), Ok(false));
        assert_eq!(is_signaled(ev2), Ok(false));
    }

    #[test]
    fn wait_for_thread_reference_handle_and_is_signaled() {
        let _guard = serial_guard();
        let ev = create_event(true, false);
        let ev_copy = ev;

        let thread_handle = thread::create_thread(
            std::ptr::null(),
            0,
            thread_worker as *const std::ffi::c_void,
            ev_copy as usize as *mut std::ffi::c_void,
            0,
            std::ptr::null_mut(),
        );
        assert_ne!(thread_handle, INVALID_HANDLE_VALUE);

        let os_tid = global_table()
            .with(thread_handle, |obj| {
                obj.as_any()
                    .downcast_ref::<thread::ThreadHandleObject>()
                    .map(thread::ThreadHandleObject::os_thread_id)
            })
            .flatten()
            .expect("must have os_tid");

        let ref_handle = thread::open_thread_by_id(os_tid).expect("open_thread_by_id");
        assert_eq!(is_signaled(ref_handle), Ok(false));

        // Signal event to let worker exit
        set_event(ev);

        // Wait on the reference handle
        assert_eq!(wait_for_single_object(ref_handle, 2000), WAIT_OBJECT_0);
        assert_eq!(is_signaled(ref_handle), Ok(true));
    }

    extern "win64" fn thread_worker(param: *mut std::ffi::c_void) -> u32 {
        let ev = param as usize as Handle;
        wait_for_single_object(ev, INFINITE);
        0
    }
}
