//! TuxExe-rs — Windows PE compatibility layer for Linux.
//!
//! Runs Windows `.exe` files natively on Linux without a kernel module,
//! translating Win32/NT APIs to their Linux equivalents in user-space.
//!
//! # Architecture
//!
//! ```text
//! Windows .exe → PE Loader → DLL Manager → NT Kernel Emulation → Linux syscalls
//! ```

// The Win32 surface intentionally exposes C-compatible raw-pointer entry
// points. These lints are not actionable without changing the public ABI;
// pointer validation remains the responsibility of each API implementation.
#![allow(
    clippy::derivable_impls,
    clippy::field_reassign_with_default,
    clippy::if_same_then_else,
    clippy::manual_contains,
    clippy::manual_div_ceil,
    clippy::manual_range_contains,
    clippy::needless_return,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::type_complexity,
    clippy::unnecessary_cast,
    clippy::unusual_byte_groupings,
    clippy::zero_ptr
)]

pub mod dll_manager;
pub mod dxvk;
pub mod exceptions;
pub mod filesystem;
pub mod memory;
pub mod nt_kernel;
pub mod pe_loader;
pub mod platform;
pub mod registry;
pub mod runtime;
pub mod threading;
pub mod utils;
pub mod win32;
pub mod wow64;

#[cfg(test)]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub fn serial_guard() -> MutexGuard<'static, ()> {
        static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        match TEST_LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
