//! DLL manager — hybrid DLL loading (Rust-reimplemented + real DLL binary fallback).

pub mod loader;
pub mod search;

use crate::win32::{kernel32, msvcrt};
use tracing::trace;

/// Resolves an import in a static reimplemented DLL.
/// Returns the address of the function if found, or 0 if not implemented.
pub fn resolve_reimplemented_export(dll_name: &str, func_name: &str) -> usize {
    let dll_lower = dll_name.to_lowercase();
    
    // Ignore extensions
    let base_name = if let Some(idx) = dll_lower.find('.') {
        &dll_lower[..idx]
    } else {
        &dll_lower
    };

    match base_name {
        "kernel32" => {
            let exports = kernel32::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved kernel32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "msvcrt" => {
            let exports = msvcrt::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved msvcrt!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        _ => {}
    }

    trace!("Unresolved import {}!{}", dll_name, func_name);
    0
}
