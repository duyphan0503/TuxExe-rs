#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Guest thread creation and lifecycle management.

use std::{
    any::Any,
    ffi::c_void,
    panic,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use tracing::{trace, warn};

use crate::{
    threading::{teb, tls},
    utils::handle::{global_table, init_global_table, Handle, HandleObject, INVALID_HANDLE_VALUE},
};

pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
pub const INFINITE: u32 = 0xFFFF_FFFF;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
pub const THREAD_EXIT_PANIC: u32 = 0xC000_0409;
pub const CURRENT_THREAD_PSEUDO_HANDLE: Handle = 0xFFFF_FFFE;

type ThreadStartRoutine = unsafe extern "win64" fn(*mut c_void) -> u32;

#[derive(Debug)]
struct ThreadControl {
    completed: bool,
    exit_code: u32,
    os_thread_id: u32,
    suspend_count: u32,
}

#[derive(Debug)]
pub struct ThreadHandleObject {
    control: Arc<(Mutex<ThreadControl>, Condvar)>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl ThreadHandleObject {
    fn new(control: Arc<(Mutex<ThreadControl>, Condvar)>, join_handle: JoinHandle<()>) -> Self {
        Self { control, join_handle: Mutex::new(Some(join_handle)) }
    }

    pub fn wait(&self, timeout_ms: u32) -> u32 {
        let (lock, condvar) = &*self.control;
        let mut guard = lock.lock().expect("thread control poisoned");

        let completed = if timeout_ms == INFINITE {
            while !guard.completed {
                guard = condvar.wait(guard).expect("thread control poisoned");
            }
            true
        } else {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
            while !guard.completed {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                let (next, timeout) =
                    condvar.wait_timeout(guard, remaining).expect("thread control poisoned");
                guard = next;
                if timeout.timed_out() {
                    break;
                }
            }
            guard.completed
        };

        drop(guard);

        if !completed {
            return WAIT_TIMEOUT;
        }

        if let Some(join) = self.join_handle.lock().expect("thread join handle poisoned").take() {
            let _ = join.join();
        }

        WAIT_OBJECT_0
    }

    pub fn os_thread_id(&self) -> u32 {
        self.control.0.lock().expect("thread control poisoned").os_thread_id
    }

    pub fn suspend(&self) -> u32 {
        let (lock, _) = &*self.control;
        let mut guard = lock.lock().expect("thread control poisoned");
        let previous = guard.suspend_count;
        guard.suspend_count = guard.suspend_count.saturating_add(1);
        previous
    }

    pub fn resume(&self) -> u32 {
        let (lock, condvar) = &*self.control;
        let mut guard = lock.lock().expect("thread control poisoned");
        let previous = guard.suspend_count;
        if guard.suspend_count > 0 {
            guard.suspend_count -= 1;
            if guard.suspend_count == 0 {
                condvar.notify_all();
            }
        }
        previous
    }
}

impl HandleObject for ThreadHandleObject {
    fn type_name(&self) -> &'static str {
        "ThreadHandle"
    }

    fn close(&mut self) {
        let _ = self.join_handle.lock().expect("thread join handle poisoned").take();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
struct ThreadExitSignal(u32);

fn current_thread_id() -> u32 {
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

fn wait_for_start(control: &Arc<(Mutex<ThreadControl>, Condvar)>) {
    let (lock, condvar) = &**control;
    let mut guard = lock.lock().expect("thread control poisoned");
    guard.os_thread_id = current_thread_id();
    condvar.notify_all();

    while guard.suspend_count > 0 {
        guard = condvar.wait(guard).expect("thread control poisoned");
    }
}

fn finish_thread(control: &Arc<(Mutex<ThreadControl>, Condvar)>, exit_code: u32) {
    let (lock, condvar) = &**control;
    let mut guard = lock.lock().expect("thread control poisoned");
    guard.completed = true;
    guard.exit_code = exit_code;
    condvar.notify_all();
}

pub fn create_thread(
    _attributes: *const c_void,
    stack_size: usize,
    start_address: *const c_void,
    parameter: *mut c_void,
    creation_flags: u32,
    thread_id_out: *mut u32,
) -> Handle {
    if start_address.is_null() {
        return INVALID_HANDLE_VALUE;
    }

    init_global_table();

    let control = Arc::new((
        Mutex::new(ThreadControl {
            completed: false,
            exit_code: 0,
            os_thread_id: 0,
            suspend_count: if creation_flags & CREATE_SUSPENDED != 0 { 1 } else { 0 },
        }),
        Condvar::new(),
    ));

    let start: ThreadStartRoutine = unsafe { std::mem::transmute(start_address) };
    let start_address = start as usize;
    let parameter = parameter as usize;
    let control_clone = Arc::clone(&control);
    let builder = if stack_size > 0 {
        thread::Builder::new().stack_size(stack_size)
    } else {
        thread::Builder::new()
    };

    let join_handle = match builder.spawn(move || {
        let start: ThreadStartRoutine = unsafe { std::mem::transmute(start_address) };
        let parameter = parameter as *mut c_void;
        if let Err(error) = teb::attach_spawned_thread() {
            warn!(%error, "Failed to attach TEB for guest thread");
        }

        wait_for_start(&control_clone);
        tls::invoke_thread_attach_callbacks();

        let result = panic::catch_unwind(|| unsafe { start(parameter) });
        let exit_code = match result {
            Ok(code) => code,
            Err(payload) => match payload.downcast::<ThreadExitSignal>() {
                Ok(signal) => signal.0,
                Err(_) => THREAD_EXIT_PANIC,
            },
        };

        finish_thread(&control_clone, exit_code);
        teb::destroy_current_teb();
    }) {
        Ok(handle) => handle,
        Err(_) => return INVALID_HANDLE_VALUE,
    };

    let handle = global_table().alloc(Box::new(ThreadHandleObject::new(control, join_handle)));

    let thread_id = wait_for_thread_id(handle);
    if !thread_id_out.is_null() {
        unsafe {
            *thread_id_out = thread_id;
        }
    }

    trace!(handle, thread_id, "Created guest thread");
    handle
}

fn wait_for_thread_id(handle: Handle) -> u32 {
    let thread = global_table()
        .with(handle, |object| {
            object
                .as_any()
                .downcast_ref::<ThreadHandleObject>()
                .map(|thread| thread.control.clone())
        })
        .flatten();

    let Some(control) = thread else {
        return 0;
    };

    let (lock, condvar) = &*control;
    let mut guard = lock.lock().expect("thread control poisoned");
    while guard.os_thread_id == 0 {
        guard = condvar.wait(guard).expect("thread control poisoned");
    }
    guard.os_thread_id
}

pub fn wait_for_thread(handle: Handle, timeout_ms: u32) -> u32 {
    global_table()
        .with(handle, |object| {
            object
                .as_any()
                .downcast_ref::<ThreadHandleObject>()
                .map(|thread| thread.wait(timeout_ms))
        })
        .flatten()
        .unwrap_or(WAIT_FAILED)
}

pub fn suspend_thread(handle: Handle) -> u32 {
    global_table()
        .with(handle, |object| {
            object.as_any().downcast_ref::<ThreadHandleObject>().map(ThreadHandleObject::suspend)
        })
        .flatten()
        .unwrap_or(u32::MAX)
}

pub fn resume_thread(handle: Handle) -> u32 {
    global_table()
        .with(handle, |object| {
            object.as_any().downcast_ref::<ThreadHandleObject>().map(ThreadHandleObject::resume)
        })
        .flatten()
        .unwrap_or(u32::MAX)
}

pub fn current_thread_pseudo_handle() -> Handle {
    CURRENT_THREAD_PSEUDO_HANDLE
}

pub fn exit_thread(exit_code: u32) -> ! {
    if teb::is_managed_guest_thread() {
        panic::panic_any(ThreadExitSignal(exit_code));
    }

    unsafe {
        libc::_exit(exit_code as i32);
    }
}

pub fn current_os_thread_id() -> u32 {
    current_thread_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use std::sync::atomic::{AtomicU32, Ordering};

    static THREAD_RESULT: AtomicU32 = AtomicU32::new(0);

    unsafe extern "win64" fn test_thread(arg: *mut c_void) -> u32 {
        THREAD_RESULT.store(arg as usize as u32, Ordering::SeqCst);
        42
    }

    #[test]
    fn guest_threads_can_be_created_and_waited() {
        let _guard = serial_guard();
        THREAD_RESULT.store(0, Ordering::SeqCst);
        let mut thread_id = 0;
        let handle = create_thread(
            std::ptr::null(),
            0,
            test_thread as *const c_void,
            7usize as *mut c_void,
            0,
            &mut thread_id,
        );

        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_ne!(thread_id, 0);
        assert_eq!(wait_for_thread(handle, INFINITE), WAIT_OBJECT_0);
        assert_eq!(THREAD_RESULT.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn suspended_threads_can_be_resumed() {
        let _guard = serial_guard();
        THREAD_RESULT.store(0, Ordering::SeqCst);
        let handle = create_thread(
            std::ptr::null(),
            0,
            test_thread as *const c_void,
            9usize as *mut c_void,
            CREATE_SUSPENDED,
            std::ptr::null_mut(),
        );

        assert_ne!(handle, INVALID_HANDLE_VALUE);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(THREAD_RESULT.load(Ordering::SeqCst), 0);

        assert_eq!(resume_thread(handle), 1);
        assert_eq!(wait_for_thread(handle, INFINITE), WAIT_OBJECT_0);
        assert_eq!(THREAD_RESULT.load(Ordering::SeqCst), 9);
    }
}
