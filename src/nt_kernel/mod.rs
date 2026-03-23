//! NT kernel emulation — translate NT syscalls to Linux equivalents.

pub mod file;
pub mod memory;
pub mod objects;
pub mod process;
pub mod registry;
pub mod sync;
pub mod thread;
