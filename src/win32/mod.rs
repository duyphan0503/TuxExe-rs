//! Win32 API subsystem — higher-level Windows APIs built on NT kernel emulation.

pub mod gdi32; // Phase 7
pub mod kernel32;
// pub mod advapi32;  // Phase 4
pub mod msvcrt; // Phase 2
pub mod user32; // Phase 7
pub mod ws2_32; // Phase 6
