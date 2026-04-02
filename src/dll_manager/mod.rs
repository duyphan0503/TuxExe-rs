//! DLL manager — hybrid DLL loading (Rust-reimplemented + real DLL binary fallback).

pub mod loader;
pub mod search;

use crate::win32::{kernel32, msvcrt, ws2_32};
use tracing::trace;

fn resolve_export_name(
    exports: &std::collections::HashMap<&'static str, usize>,
    func_name: &str,
) -> Option<usize> {
    let trimmed = func_name.trim();
    let trimmed = trimmed.split('\0').next().unwrap_or(trimmed).trim();
    let undecorated = trimmed
        .strip_prefix('_')
        .unwrap_or(trimmed)
        .split_once('@')
        .and_then(|(name, suffix)| suffix.chars().all(|ch| ch.is_ascii_digit()).then_some(name))
        .unwrap_or_else(|| trimmed.strip_prefix('_').unwrap_or(trimmed));

    [trimmed, undecorated].into_iter().find_map(|candidate| {
        exports.get(candidate).copied().or_else(|| {
            exports
                .iter()
                .find_map(|(name, addr)| name.eq_ignore_ascii_case(candidate).then_some(*addr))
        })
    })
}

pub use loader::{
    free_library, get_loaded_module_filename, get_loaded_module_handle, load_library,
    resolve_export, LoadedModule, ModuleSource, NativeModule,
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
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved kernel32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "msvcrt" => {
            let exports = msvcrt::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved msvcrt!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "ws2_32" => {
            let exports = ws2_32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved ws2_32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "user32" => {
            let exports = crate::win32::user32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved user32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "gdi32" => {
            let exports = crate::win32::gdi32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved gdi32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "dinput8" => {
            let exports = crate::win32::dinput8::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved dinput8!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "dsound" => {
            let exports = crate::win32::dsound::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved dsound!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        _ => {}
    }

    trace!("Unresolved import {}!{}", dll_name, func_name);
    0
}

#[cfg(test)]
mod tests {
    use super::resolve_export_name;
    use std::collections::HashMap;

    #[test]
    fn resolve_export_name_handles_stdcall_decoration() {
        let mut exports = HashMap::new();
        exports.insert("GetEnvironmentStringsW", 0x1234usize);
        assert_eq!(resolve_export_name(&exports, "_GetEnvironmentStringsW@0"), Some(0x1234));
    }

    #[test]
    fn resolve_export_name_handles_case_and_padding() {
        let mut exports = HashMap::new();
        exports.insert("GetModuleHandleW", 0x5678usize);
        assert_eq!(resolve_export_name(&exports, "  getmodulehandlew\0  "), Some(0x5678));
    }
}
