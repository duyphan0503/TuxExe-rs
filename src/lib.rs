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
