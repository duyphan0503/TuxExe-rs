//! SEH chain walking — __try/__except handler dispatch.

use std::cell::RefCell;

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

thread_local! {
    /// Thread-local SEH chain (top-most handler is the last registered entry).
    static SEH_CHAIN: RefCell<Vec<SehHandler>> = const { RefCell::new(Vec::new()) };
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static FIRST_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SECOND_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn first_handler(_record: &ExceptionRecord) -> SehDisposition {
        FIRST_CALLS.fetch_add(1, Ordering::SeqCst);
        SehDisposition::ContinueSearch
    }

    fn second_handler(_record: &ExceptionRecord) -> SehDisposition {
        SECOND_CALLS.fetch_add(1, Ordering::SeqCst);
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
}
