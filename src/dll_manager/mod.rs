//! DLL manager — hybrid DLL loading (Rust-reimplemented + real DLL binary fallback).

pub mod loader;
pub mod search;

use crate::win32::{advapi32, kernel32, msvcrt, ws2_32};
use tracing::trace;

pub use loader::{
    free_library, get_loaded_module_handle, load_library, resolve_export, LoadedModule,
    ModuleSource, NativeModule,
};

/// Resolves an import in a static reimplemented DLL.
/// Returns the address of the function if found, or 0 if not implemented.
pub fn resolve_reimplemented_export(dll_name: &str, func_name: &str) -> usize {
    let dll_lower = dll_name.to_lowercase();

    // Ignore extensions
    let base_name =
        if let Some(idx) = dll_lower.find('.') { &dll_lower[..idx] } else { &dll_lower };

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
        "ws2_32" => {
            let exports = ws2_32::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved ws2_32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "user32" => {
            let exports = crate::win32::user32::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved user32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "gdi32" => {
            let exports = crate::win32::gdi32::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved gdi32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "dinput8" => {
            let exports = crate::win32::dinput8::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved dinput8!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "dsound" => {
            let exports = crate::win32::dsound::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved dsound!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "advapi32" => {
            let exports = advapi32::get_exports();
            if let Some(&addr) = exports.get(func_name) {
                trace!("Resolved advapi32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        _ => {}
    }

    trace!("Unresolved import {}!{}", dll_name, func_name);
    0
}
