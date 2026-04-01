//! Waitable synchronization primitives backed by host mutexes/condvars.

use std::{
    any::Any,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use crate::{
    nt_kernel::thread,
    utils::handle::{global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE},
};

pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_ABANDONED_0: u32 = 0x80;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
pub const INFINITE: u32 = 0xFFFF_FFFF;

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

    fn wait(&self, timeout_ms: u32) -> u32 {
        let (lock, condvar) = &*self.state;
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

    fn wait(&self, timeout_ms: u32) -> u32 {
        let (lock, condvar) = &*self.state;
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

    fn wait(&self, timeout_ms: u32) -> u32 {
        let (lock, condvar) = &*self.state;
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

pub fn create_event(manual_reset: bool, initial_state: bool) -> Handle {
    init_global_table();
    global_table().alloc(Box::new(EventHandleObject::new(manual_reset, initial_state)))
}

pub fn create_semaphore(initial_count: i32, maximum_count: i32) -> Handle {
    if initial_count < 0 || maximum_count <= 0 || initial_count > maximum_count {
        return INVALID_HANDLE_VALUE;
    }

    init_global_table();
    global_table().alloc(Box::new(SemaphoreHandleObject::new(initial_count, maximum_count)))
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

pub fn wait_for_single_object(handle: Handle, timeout_ms: u32) -> u32 {
    let result = global_table().with(handle, |object| {
        if let Some(thread) = object.as_any().downcast_ref::<thread::ThreadHandleObject>() {
            return Some(thread.wait(timeout_ms));
        }
        if let Some(mutex) = object.as_any().downcast_ref::<MutexHandleObject>() {
            return Some(mutex.wait(timeout_ms));
        }
        if let Some(event) = object.as_any().downcast_ref::<EventHandleObject>() {
            return Some(event.wait(timeout_ms));
        }
        if let Some(semaphore) = object.as_any().downcast_ref::<SemaphoreHandleObject>() {
            return Some(semaphore.wait(timeout_ms));
        }
        None
    });

    result.flatten().unwrap_or(WAIT_FAILED)
}

pub fn wait_for_multiple_objects(handles: &[Handle], wait_all: bool, timeout_ms: u32) -> u32 {
    if handles.is_empty() {
        return WAIT_FAILED;
    }

    if wait_all {
        let deadline = if timeout_ms == INFINITE {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
        };

        for handle in handles {
            let timeout = deadline
                .map(|end| end.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(u64::MAX / 2));
            let timeout_ms = if deadline.is_none() {
                INFINITE
            } else {
                timeout.as_millis().min(u32::MAX as u128) as u32
            };

            let result = wait_for_single_object(*handle, timeout_ms);
            if result != WAIT_OBJECT_0 {
                return result;
            }
        }
        return WAIT_OBJECT_0;
    }

    let deadline = if timeout_ms == INFINITE {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
    };

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

        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

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
}
