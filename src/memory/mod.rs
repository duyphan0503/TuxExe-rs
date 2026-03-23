//! Memory manager — VirtualAlloc/VirtualFree/HeapCreate emulation via mmap.

pub mod heap;
pub mod section;
pub mod virtual_alloc;
