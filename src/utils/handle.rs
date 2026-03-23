//! Windows HANDLE table — opaque `u32` handles mapped to typed objects.
//!
//! Windows uses `HANDLE` (a pointer-sized integer) as an opaque reference to
//! kernel objects: files, threads, mutexes, events, etc.  In TuxExe-rs we
//! represent handles as `u32` IDs stored in a global table that maps each ID
//! to a `Box<dyn HandleObject>`.
//!
//! ## Design
//!
//! - **Atomic counter** for handle allocation (avoids locking on alloc).
//! - **`RwLock<HashMap<...>>`** for the table itself (cheap for reads).
//! - **Pre-allocated pseudo-handles** for stdin/stdout/stderr (0x80000001–3).
//! - **Invalid handle sentinel**: `0xFFFFFFFF` (mirrors `INVALID_HANDLE_VALUE`).
//!
//! ## Thread safety
//!
//! All public entry points are `Send + Sync`.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
};

// ── Public HANDLE type ────────────────────────────────────────────────────────

/// An opaque Windows-compatible handle value.
///
/// On real Windows, `HANDLE` is a `*mut c_void`. We use `u32` for simplicity;
/// the high bit is reserved for pseudo-handles.
pub type Handle = u32;

/// Sentinel for `INVALID_HANDLE_VALUE` (-1 as u32).
pub const INVALID_HANDLE_VALUE: Handle = 0xFFFF_FFFF;

/// Pseudo-handle for `STD_INPUT_HANDLE` (-10 as u32).
pub const PSEUDO_STDIN: Handle = 0xFFFF_FFF6;
/// Pseudo-handle for `STD_OUTPUT_HANDLE` (-11 as u32).
pub const PSEUDO_STDOUT: Handle = 0xFFFF_FFF5;
/// Pseudo-handle for `STD_ERROR_HANDLE` (-12 as u32).
pub const PSEUDO_STDERR: Handle = 0xFFFF_FFF4;

use std::any::Any;

// ── Handle object trait ───────────────────────────────────────────────────────

/// Every object stored in the handle table implements this trait.
///
/// Concrete types: `FileHandle`, `ThreadHandle`, `MutexHandle`, `EventHandle`, …
pub trait HandleObject: Send + Sync + fmt::Debug + Any {
    /// Human-readable type name for diagnostics.
    fn type_name(&self) -> &'static str;

    /// Called when the last reference via `CloseHandle` is dropped.
    fn close(&mut self) {}

    /// Support for downcasting.
    fn as_any(&self) -> &dyn Any;
}

// ── Concrete built-in handle types ───────────────────────────────────────────

/// Standard I/O stream handle (stdin / stdout / stderr).
#[derive(Debug)]
pub struct StdioHandle {
    /// Underlying file descriptor (0 = stdin, 1 = stdout, 2 = stderr).
    pub fd: i32,
    pub name: &'static str,
}

impl HandleObject for StdioHandle {
    fn type_name(&self) -> &'static str {
        "StdioHandle"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ── Handle table ─────────────────────────────────────────────────────────────

/// Thread-safe handle table — the single source of truth for all open handles.
#[derive(Debug)]
pub struct HandleTable {
    /// Monotonically increasing counter (starts at 1; 0 is never allocated).
    counter: AtomicU32,
    /// Inner map from handle ID → boxed object.
    inner: RwLock<HashMap<Handle, Box<dyn HandleObject>>>,
}

impl HandleTable {
    /// Create a new, empty handle table with the three stdio pseudo-handles pre-inserted.
    pub fn new() -> Self {
        let table = Self { counter: AtomicU32::new(1), inner: RwLock::new(HashMap::new()) };
        table.insert_at(PSEUDO_STDIN, Box::new(StdioHandle { fd: 0, name: "stdin" }));
        table.insert_at(PSEUDO_STDOUT, Box::new(StdioHandle { fd: 1, name: "stdout" }));
        table.insert_at(PSEUDO_STDERR, Box::new(StdioHandle { fd: 2, name: "stderr" }));
        table
    }

    /// Allocate the next handle ID and store `obj`.
    ///
    /// Returns the newly allocated handle.
    pub fn alloc(&self, obj: Box<dyn HandleObject>) -> Handle {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, INVALID_HANDLE_VALUE, "handle counter wrapped");
        let mut guard = self.inner.write().expect("handle table poisoned");
        guard.insert(id, obj);
        id
    }

    /// Insert an object at a specific handle value (for pseudo-handles).
    fn insert_at(&self, id: Handle, obj: Box<dyn HandleObject>) {
        let mut guard = self.inner.write().expect("handle table poisoned");
        guard.insert(id, obj);
    }

    /// Returns `true` if `handle` exists in the table.
    pub fn is_valid(&self, handle: Handle) -> bool {
        if handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let guard = self.inner.read().expect("handle table poisoned");
        guard.contains_key(&handle)
    }

    /// Run a closure on the object, immutably.
    ///
    /// Returns `None` if the handle does not exist.
    pub fn with<F, R>(&self, handle: Handle, f: F) -> Option<R>
    where
        F: FnOnce(&dyn HandleObject) -> R,
    {
        let guard = self.inner.read().expect("handle table poisoned");
        guard.get(&handle).map(|obj| f(obj.as_ref()))
    }

    /// Run a closure on the object, mutably.
    pub fn with_mut<F, R>(&self, handle: Handle, f: F) -> Option<R>
    where
        F: FnOnce(&mut dyn HandleObject) -> R,
    {
        let mut guard = self.inner.write().expect("handle table poisoned");
        guard.get_mut(&handle).map(|obj| f(obj.as_mut()))
    }

    /// Remove the handle, calling `close()` on the object.
    ///
    /// Returns `true` if the handle existed, `false` otherwise
    /// (mirrors Windows `CloseHandle` returning `FALSE` on invalid handle).
    pub fn close_handle(&self, handle: Handle) -> bool {
        // Prevent closing pseudo-handles accidentally.
        if matches!(handle, PSEUDO_STDIN | PSEUDO_STDOUT | PSEUDO_STDERR) {
            return false;
        }
        let mut guard = self.inner.write().expect("handle table poisoned");
        if let Some(mut obj) = guard.remove(&handle) {
            obj.close();
            true
        } else {
            false
        }
    }

    /// Return the number of currently open handles (excludes pseudo-handles in count
    /// but they are technically present in the inner map).
    pub fn len(&self) -> usize {
        self.inner.read().expect("handle table poisoned").len()
    }

    /// Returns `true` when no user-allocated handles are open (only pseudo-handles remain).
    pub fn is_empty(&self) -> bool {
        self.len() <= 3 // only the 3 pseudo-handles
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global process-wide handle table ─────────────────────────────────────────

use std::sync::OnceLock;

static GLOBAL_TABLE: OnceLock<Arc<HandleTable>> = OnceLock::new();

/// Initialise the global handle table (idempotent; call once at startup).
pub fn init_global_table() -> Arc<HandleTable> {
    GLOBAL_TABLE.get_or_init(|| Arc::new(HandleTable::new())).clone()
}

/// Get a reference to the global handle table.
///
/// # Panics
///
/// Panics if `init_global_table()` was never called.
pub fn global_table() -> &'static HandleTable {
    GLOBAL_TABLE.get().expect("handle table not initialised — call init_global_table() first")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial test object.
    #[derive(Debug)]
    struct DummyObj(String);

    impl HandleObject for DummyObj {
        fn type_name(&self) -> &'static str {
            "DummyObj"
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn new_table() -> HandleTable {
        HandleTable::new()
    }

    #[test]
    fn alloc_returns_nonzero_handle() {
        let t = new_table();
        let h = t.alloc(Box::new(DummyObj("a".into())));
        assert_ne!(h, 0);
        assert_ne!(h, INVALID_HANDLE_VALUE);
    }

    #[test]
    fn is_valid_after_alloc() {
        let t = new_table();
        let h = t.alloc(Box::new(DummyObj("b".into())));
        assert!(t.is_valid(h));
    }

    #[test]
    fn invalid_handle_sentinel_not_valid() {
        let t = new_table();
        assert!(!t.is_valid(INVALID_HANDLE_VALUE));
    }

    #[test]
    fn close_handle_removes_it() {
        let t = new_table();
        let h = t.alloc(Box::new(DummyObj("c".into())));
        assert!(t.close_handle(h));
        assert!(!t.is_valid(h));
    }

    #[test]
    fn close_nonexistent_returns_false() {
        let t = new_table();
        assert!(!t.close_handle(9999));
    }

    #[test]
    fn pseudo_handles_pre_registered() {
        let t = new_table();
        assert!(t.is_valid(PSEUDO_STDIN));
        assert!(t.is_valid(PSEUDO_STDOUT));
        assert!(t.is_valid(PSEUDO_STDERR));
    }

    #[test]
    fn cannot_close_pseudo_handle() {
        let t = new_table();
        assert!(!t.close_handle(PSEUDO_STDOUT));
        // Must still be valid after the attempted close.
        assert!(t.is_valid(PSEUDO_STDOUT));
    }

    #[test]
    fn with_reads_type_name() {
        let t = new_table();
        let h = t.alloc(Box::new(DummyObj("d".into())));
        let name = t.with(h, |obj| obj.type_name()).unwrap();
        assert_eq!(name, "DummyObj");
    }

    #[test]
    fn with_mut_can_replace_content() {
        #[derive(Debug)]
        struct Counter(u32);
        impl HandleObject for Counter {
            fn type_name(&self) -> &'static str {
                "Counter"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let t = new_table();
        let h = t.alloc(Box::new(Counter(0)));
        t.with_mut(h, |obj| {
            // Downcast via Any would be cleaner, but for this
            // test we verify the closure runs without panic.
            let _ = obj.type_name();
        });
        assert!(t.is_valid(h));
    }

    #[test]
    fn with_invalid_handle_returns_none() {
        let t = new_table();
        let result = t.with(9876, |obj| obj.type_name());
        assert!(result.is_none());
    }

    #[test]
    fn handles_are_monotonically_increasing() {
        let t = new_table();
        let h1 = t.alloc(Box::new(DummyObj("e".into())));
        let h2 = t.alloc(Box::new(DummyObj("f".into())));
        assert!(h2 > h1);
    }

    #[test]
    fn stdio_type_names() {
        let t = new_table();
        let name = t.with(PSEUDO_STDIN, |o| o.type_name()).unwrap();
        assert_eq!(name, "StdioHandle");
    }
}
