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

pub mod dll_manager;
pub mod dxvk;
pub mod exceptions;
pub mod filesystem;
pub mod memory;
pub mod nt_kernel;
pub mod pe_loader;
pub mod registry;
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
