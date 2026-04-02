//! SEH chain walking — __try/__except handler dispatch.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use tracing::{debug, trace};

use crate::exceptions::signals::ExceptionRecord;

/// Return value modeled after Windows exception filter semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SehDisposition {
    /// Equivalent to EXCEPTION_CONTINUE_EXECUTION.
    ContinueExecution,
    /// Equivalent to EXCEPTION_CONTINUE_SEARCH.
    ContinueSearch,
}

/// Minimal SEH handler signature used by the emulator.
pub type SehHandler = fn(&ExceptionRecord) -> SehDisposition;
pub type X86SehHandler = fn(&ExceptionRecord) -> SehDisposition;

const X86_SEH_END: u32 = 0xFFFF_FFFF;

thread_local! {
    /// Thread-local SEH chain (top-most handler is the last registered entry).
    static SEH_CHAIN: RefCell<Vec<SehHandler>> = const { RefCell::new(Vec::new()) };
    static X86_SEH_HEAD: Cell<u32> = const { Cell::new(X86_SEH_END) };
    static X86_SEH_FRAMES: RefCell<HashMap<u32, (u32, X86SehHandler)>> = RefCell::new(HashMap::new());
}

/// Push a new handler to the current thread's SEH chain.
pub fn push_handler(handler: SehHandler) {
    SEH_CHAIN.with(|chain| chain.borrow_mut().push(handler));
}

/// Pop the latest handler from the current thread's SEH chain.
pub fn pop_handler() {
    SEH_CHAIN.with(|chain| {
        let _ = chain.borrow_mut().pop();
    });
}

/// Walk handlers from the newest to the oldest one.
///
/// Returns `true` when a handler requests continue-execution.
pub fn walk_seh_chain(record: &ExceptionRecord) -> bool {
    SEH_CHAIN.with(|chain| {
        let handlers = chain.borrow();
        debug!(handlers = handlers.len(), ?record, "Walking SEH chain");

        for handler in handlers.iter().rev() {
            match handler(record) {
                SehDisposition::ContinueExecution => {
                    trace!("SEH handler requested continue-execution");
                    return true;
                }
                SehDisposition::ContinueSearch => {
                    trace!("SEH handler requested continue-search");
                }
            }
        }
        false
    })
}

/// Set the synthetic FS:[0] head for x86-style SEH walking.
pub fn set_x86_seh_head(head: u32) {
    X86_SEH_HEAD.with(|slot| slot.set(head));
}

pub fn x86_seh_head() -> u32 {
    X86_SEH_HEAD.with(Cell::get)
}

/// Register one x86 SEH frame.
pub fn push_x86_handler(frame_ptr: u32, handler: X86SehHandler) {
    X86_SEH_FRAMES.with(|frames| {
        X86_SEH_HEAD.with(|head| {
            let next = head.get();
            frames.borrow_mut().insert(frame_ptr, (next, handler));
            head.set(frame_ptr);
        });
    });
}

/// Remove one x86 SEH frame and restore chain links.
pub fn pop_x86_handler(frame_ptr: u32) {
    X86_SEH_FRAMES.with(|frames| {
        X86_SEH_HEAD.with(|head| {
            let mut frames = frames.borrow_mut();
            let removed = frames.remove(&frame_ptr);
            if removed.is_none() {
                return;
            }

            if head.get() == frame_ptr {
                if let Some((next, _)) = removed {
                    head.set(next);
                }
                return;
            }

            for (_, link) in frames.iter_mut() {
                if link.0 == frame_ptr {
                    if let Some((next, _)) = removed {
                        link.0 = next;
                    }
                    break;
                }
            }
        });
    });
}

/// Walk x86 frame-based chain starting at synthetic FS:[0].
pub fn walk_x86_seh_chain(record: &ExceptionRecord) -> bool {
    X86_SEH_HEAD.with(|head| {
        X86_SEH_FRAMES.with(|frames| {
            let frames = frames.borrow();
            let mut cursor = head.get();

            while cursor != X86_SEH_END {
                let Some((next, handler)) = frames.get(&cursor) else {
                    break;
                };

                match handler(record) {
                    SehDisposition::ContinueExecution => return true,
                    SehDisposition::ContinueSearch => {
                        cursor = *next;
                    }
                }
            }

            false
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static FIRST_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SECOND_CALLS: AtomicUsize = AtomicUsize::new(0);
    static X86_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn first_handler(_record: &ExceptionRecord) -> SehDisposition {
        FIRST_CALLS.fetch_add(1, Ordering::SeqCst);
        SehDisposition::ContinueSearch
    }

    fn second_handler(_record: &ExceptionRecord) -> SehDisposition {
        SECOND_CALLS.fetch_add(1, Ordering::SeqCst);
        SehDisposition::ContinueExecution
    }

    fn x86_handler(_record: &ExceptionRecord) -> SehDisposition {
        X86_CALLS.fetch_add(1, Ordering::SeqCst);
        SehDisposition::ContinueExecution
    }

    #[test]
    fn walks_handlers_in_lifo_order() {
        FIRST_CALLS.store(0, Ordering::SeqCst);
        SECOND_CALLS.store(0, Ordering::SeqCst);

        push_handler(first_handler);
        push_handler(second_handler);

        let record = ExceptionRecord {
            exception_code: 0xC000_0005,
            signal_number: libc::SIGSEGV,
            fault_address: 0x1234,
        };
        let handled = walk_seh_chain(&record);
        assert!(handled);
        assert_eq!(SECOND_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FIRST_CALLS.load(Ordering::SeqCst), 0);

        pop_handler();
        pop_handler();
    }

    #[test]
    fn walks_x86_frame_chain_from_fs0_head() {
        X86_CALLS.store(0, Ordering::SeqCst);
        set_x86_seh_head(X86_SEH_END);

        push_x86_handler(0x2000, x86_handler);
        let record = ExceptionRecord {
            exception_code: 0xC000_0005,
            signal_number: libc::SIGSEGV,
            fault_address: 0x8888,
        };

        assert!(walk_x86_seh_chain(&record));
        assert_eq!(X86_CALLS.load(Ordering::SeqCst), 1);

        pop_x86_handler(0x2000);
        assert_eq!(x86_seh_head(), X86_SEH_END);
    }
}
