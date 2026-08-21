#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Guest thread creation and lifecycle management.

use std::{
    any::Any,
    collections::HashMap,
    ffi::c_void,
    panic,
    sync::{Arc, Condvar, Mutex, OnceLock, Weak},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use tracing::{info, trace, warn};

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

thread_local! {
    // A Windows current-thread pseudo handle is valid for SuspendThread and
    // ResumeThread.  Suspending the host thread executing the call would make
    // the runtime unable to return, so keep the observable counter locally.
    // This is enough for Mono's GC bookkeeping, which only needs the pair to
    // succeed for the collector thread itself.
    static CURRENT_THREAD_SUSPEND_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[derive(Debug)]
struct ThreadControl {
    completed: bool,
    exited_via_api: bool,
    exit_code: u32,
    os_thread_id: u32,
    suspend_count: u32,
}

#[derive(Debug)]
pub struct ThreadHandleObject {
    control: Arc<(Mutex<ThreadControl>, Condvar)>,
    join_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

/// A non-owning handle returned by OpenThread.  Unlike the CreateThread handle
/// it must not consume the JoinHandle when callers close it.
#[derive(Debug)]
pub struct ThreadReferenceHandleObject {
    control: Arc<(Mutex<ThreadControl>, Condvar)>,
}

impl ThreadReferenceHandleObject {
    pub fn os_thread_id(&self) -> u32 {
        self.control.0.lock().expect("thread control poisoned").os_thread_id
    }

    pub fn is_completed(&self) -> bool {
        self.control.0.lock().expect("thread control poisoned").completed
    }
}

impl HandleObject for ThreadReferenceHandleObject {
    fn type_name(&self) -> &'static str {
        "ThreadReferenceHandle"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

type ThreadControlRef = Arc<(Mutex<ThreadControl>, Condvar)>;

fn thread_registry() -> &'static Mutex<HashMap<u32, Weak<(Mutex<ThreadControl>, Condvar)>>> {
    static THREADS: OnceLock<Mutex<HashMap<u32, Weak<(Mutex<ThreadControl>, Condvar)>>>> =
        OnceLock::new();
    THREADS.get_or_init(|| Mutex::new(HashMap::new()))
}

impl ThreadHandleObject {
    fn new(control: Arc<(Mutex<ThreadControl>, Condvar)>, join_handle: JoinHandle<()>) -> Self {
        Self { control, join_handle: Arc::new(Mutex::new(Some(join_handle))) }
    }

    pub fn wait(&self, timeout_ms: u32) -> u32 {
        Self::wait_with_handles(self.control.clone(), self.join_handle.clone(), timeout_ms)
    }

    fn wait_with_handles(
        control: Arc<(Mutex<ThreadControl>, Condvar)>,
        join_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
        timeout_ms: u32,
    ) -> u32 {
        let (lock, condvar) = &*control;
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

        if let Some(join) = join_handle.lock().expect("thread join handle poisoned").take() {
            if control.0.lock().expect("thread control poisoned").exited_via_api {
                drop(join);
            } else {
                let _ = join.join();
            }
        }

        WAIT_OBJECT_0
    }

    pub fn is_completed(&self) -> bool {
        self.control.0.lock().expect("thread control poisoned").completed
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

thread_local! {
    static CACHED_NT_TID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn current_thread_id() -> u32 {
    let tid = CACHED_NT_TID.get();
    if tid != 0 {
        return tid;
    }
    let new_tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    CACHED_NT_TID.set(new_tid);
    new_tid
}

fn wait_for_start(control: &Arc<(Mutex<ThreadControl>, Condvar)>) {
    let (lock, condvar) = &**control;
    let mut guard = lock.lock().expect("thread control poisoned");
    guard.os_thread_id = current_thread_id();
    thread_registry()
        .lock()
        .expect("thread registry poisoned")
        .insert(guard.os_thread_id, Arc::downgrade(control));
    condvar.notify_all();

    while guard.suspend_count > 0 {
        guard = condvar.wait(guard).expect("thread control poisoned");
    }
}

fn control_for_handle(handle: Handle) -> Option<ThreadControlRef> {
    global_table().with(handle, |object| {
        object
            .as_any()
            .downcast_ref::<ThreadHandleObject>()
            .map(|thread| thread.control.clone())
            .or_else(|| {
                object
                    .as_any()
                    .downcast_ref::<ThreadReferenceHandleObject>()
                    .map(|thread| thread.control.clone())
            })
    })?
}

/// Return a distinct Windows handle for a guest OS thread ID, mirroring
/// OpenThread rather than substituting the current-thread pseudo handle.
pub fn open_thread_by_id(thread_id: u32) -> Option<Handle> {
    init_global_table();
    let control = {
        let mut registry = thread_registry().lock().expect("thread registry poisoned");
        let control = registry.get(&thread_id).and_then(Weak::upgrade);
        if control.is_none() {
            registry.remove(&thread_id);
        }
        control
    }?;
    Some(global_table().alloc(Box::new(ThreadReferenceHandleObject { control })))
}

/// Snapshot the live guest thread IDs.  The caller can add its own host thread
/// when required, but must not fabricate handles for unknown threads.
pub fn live_thread_ids() -> Vec<u32> {
    let mut registry = thread_registry().lock().expect("thread registry poisoned");
    registry.retain(|_, control| control.upgrade().is_some());
    registry.keys().copied().collect()
}

fn finish_thread(control: &Arc<(Mutex<ThreadControl>, Condvar)>, exit_code: u32) {
    let (lock, condvar) = &**control;
    let mut guard = lock.lock().expect("thread control poisoned");
    guard.completed = true;
    guard.exit_code = exit_code;
    condvar.notify_all();
}

fn finish_thread_via_api(control: &Arc<(Mutex<ThreadControl>, Condvar)>, exit_code: u32) {
    let (lock, condvar) = &**control;
    let mut guard = lock.lock().expect("thread control poisoned");
    guard.completed = true;
    guard.exited_via_api = true;
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
    trace!(start = ?start_address, param = ?parameter, flags = creation_flags, "nt_kernel::create_thread called");
    if start_address.is_null() {
        return INVALID_HANDLE_VALUE;
    }

    init_global_table();

    let control = Arc::new((
        Mutex::new(ThreadControl {
            completed: false,
            exited_via_api: false,
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
    let actual_stack_size =
        if stack_size > 0 { stack_size.max(512 * 1024) } else { 2 * 1024 * 1024 };
    let builder = thread::Builder::new().stack_size(actual_stack_size);

    let join_handle = match builder.spawn(move || {
        let start: ThreadStartRoutine = unsafe { std::mem::transmute(start_address) };
        let parameter = parameter as *mut c_void;
        if let Err(error) = teb::attach_spawned_thread() {
            warn!(%error, "Failed to attach TEB for guest thread");
        }
        tls::initialize_static_tls_for_current_thread();

        wait_for_start(&control_clone);
        tls::invoke_thread_attach_callbacks();
        crate::dll_manager::loader::invoke_thread_attach_dll_mains();

        let result = panic::catch_unwind(|| {
            crate::runtime::guest_stack::invoke_thread(start as usize, parameter)
                .map_err(|error| format!("guest thread stack transition failed: {error}"))
        });
        let exit_code = match result {
            Ok(Ok(code)) => code,
            Ok(Err(error)) => {
                warn!(%error, "Guest thread could not enter PE64 routine");
                THREAD_EXIT_PANIC
            }
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
    let waiter = global_table()
        .with(handle, |object| {
            if let Some(th) = object.as_any().downcast_ref::<ThreadHandleObject>() {
                return Some((th.control.clone(), Some(th.join_handle.clone())));
            }
            if let Some(tr) = object.as_any().downcast_ref::<ThreadReferenceHandleObject>() {
                return Some((tr.control.clone(), None));
            }
            None
        })
        .flatten();

    let Some((control, join_handle)) = waiter else {
        return WAIT_FAILED;
    };

    if let Some(join) = join_handle {
        ThreadHandleObject::wait_with_handles(control, join, timeout_ms)
    } else {
        let (lock, condvar) = &*control;
        let mut guard = lock.lock().expect("thread control poisoned");
        if timeout_ms == INFINITE {
            while !guard.completed {
                guard = condvar.wait(guard).expect("thread control poisoned");
            }
            WAIT_OBJECT_0
        } else {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
            while !guard.completed {
                let now = Instant::now();
                if now >= deadline {
                    return WAIT_TIMEOUT;
                }
                let remaining = deadline.saturating_duration_since(now);
                let (next, timeout) =
                    condvar.wait_timeout(guard, remaining).expect("thread control poisoned");
                guard = next;
                if timeout.timed_out() {
                    return WAIT_TIMEOUT;
                }
            }
            if guard.completed {
                WAIT_OBJECT_0
            } else {
                WAIT_TIMEOUT
            }
        }
    }
}

pub fn suspend_thread(handle: Handle) -> u32 {
    if handle == CURRENT_THREAD_PSEUDO_HANDLE {
        return CURRENT_THREAD_SUSPEND_COUNT.with(|count| {
            let previous = count.get();
            count.set(previous.saturating_add(1));
            previous
        });
    }

    let result = control_for_handle(handle)
        .map(|control| {
            let (lock, _) = &*control;
            let mut guard = lock.lock().expect("thread control poisoned");
            let previous = guard.suspend_count;
            guard.suspend_count = guard.suspend_count.saturating_add(1);
            previous
        })
        .unwrap_or(u32::MAX);
    if result == u32::MAX {
        info!(handle, "SuspendThread rejected unknown thread handle");
    } else {
        info!(handle, previous_suspend_count = result, "SuspendThread accepted guest thread");
    }
    result
}

pub fn resume_thread(handle: Handle) -> u32 {
    if handle == CURRENT_THREAD_PSEUDO_HANDLE {
        return CURRENT_THREAD_SUSPEND_COUNT.with(|count| {
            let previous = count.get();
            count.set(previous.saturating_sub(1));
            previous
        });
    }

    let result = control_for_handle(handle)
        .map(|control| {
            let (lock, condvar) = &*control;
            let mut guard = lock.lock().expect("thread control poisoned");
            let previous = guard.suspend_count;
            if guard.suspend_count > 0 {
                guard.suspend_count -= 1;
                if guard.suspend_count == 0 {
                    condvar.notify_all();
                }
            }
            previous
        })
        .unwrap_or(u32::MAX);
    if result == u32::MAX {
        info!(handle, "ResumeThread rejected unknown thread handle");
    } else {
        info!(handle, previous_suspend_count = result, "ResumeThread accepted guest thread");
    }
    result
}

pub fn current_thread_pseudo_handle() -> Handle {
    CURRENT_THREAD_PSEUDO_HANDLE
}

pub fn exit_thread(exit_code: u32) -> ! {
    tracing::info!(exit_code, "exit_thread terminating thread");
    let thread_id = current_thread_id();
    let control = thread_registry()
        .lock()
        .expect("thread registry poisoned")
        .get(&thread_id)
        .and_then(Weak::upgrade);
    if let Some(control) = control {
        finish_thread_via_api(&control, exit_code);
    }
    teb::destroy_current_teb();
    unsafe {
        libc::pthread_exit(exit_code as usize as *mut c_void);
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

    unsafe extern "win64" fn exiting_thread(_arg: *mut c_void) -> u32 {
        exit_thread(123)
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
    fn exit_thread_signals_waiters() {
        let _guard = serial_guard();
        let handle = create_thread(
            std::ptr::null(),
            0,
            exiting_thread as *const c_void,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(wait_for_thread(handle, 500), WAIT_OBJECT_0);
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

    #[test]
    fn current_thread_pseudo_handle_has_a_balanced_suspend_count() {
        let _guard = serial_guard();
        while resume_thread(CURRENT_THREAD_PSEUDO_HANDLE) != 0 {}

        assert_eq!(suspend_thread(CURRENT_THREAD_PSEUDO_HANDLE), 0);
        assert_eq!(suspend_thread(CURRENT_THREAD_PSEUDO_HANDLE), 1);
        assert_eq!(resume_thread(CURRENT_THREAD_PSEUDO_HANDLE), 2);
        assert_eq!(resume_thread(CURRENT_THREAD_PSEUDO_HANDLE), 1);
        assert_eq!(resume_thread(CURRENT_THREAD_PSEUDO_HANDLE), 0);
    }
}
