//! DLL manager — hybrid DLL loading (Rust-reimplemented + real DLL binary fallback).

pub mod loader;
pub mod search;

use crate::win32::{
    advapi32, bcrypt, crypt32, dbghelp, dwmapi, gdi32, hid, imm32, kernel32, msvcrt, ole32, oleaut32,
    opengl32, setupapi, shell32, shlwapi, unityplayer, user32, version, winhttp, winmm, ws2_32,
};
use tracing::trace;

fn resolve_export_name(
    exports: &std::collections::HashMap<&'static str, usize>,
    func_name: &str,
) -> Option<usize> {
    let cleaned = func_name.chars().filter(|ch| !ch.is_control()).collect::<String>();
    let trimmed = cleaned.trim();
    let trimmed = trimmed.split('\0').next().unwrap_or(trimmed).trim().to_string();
    let undecorated = trimmed
        .as_str()
        .strip_prefix('_')
        .unwrap_or(trimmed.as_str())
        .split_once('@')
        .and_then(|(name, suffix)| suffix.chars().all(|ch| ch.is_ascii_digit()).then_some(name))
        .unwrap_or_else(|| trimmed.as_str().strip_prefix('_').unwrap_or(trimmed.as_str()))
        .to_string();

    [trimmed, undecorated].into_iter().find_map(|candidate| {
        exports.get(candidate.as_str()).copied().or_else(|| {
            exports
                .iter()
                .find_map(|(name, addr)| name.eq_ignore_ascii_case(&candidate).then_some(*addr))
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
            let exports = user32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved user32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "gdi32" => {
            let exports = gdi32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved gdi32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "unityplayer" => {
            let exports = unityplayer::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved unityplayer!{} -> {:#x}", func_name, addr);
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
        "advapi32" => {
            let exports = advapi32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved advapi32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "bcrypt" => {
            let exports = bcrypt::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved bcrypt!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "crypt32" => {
            let exports = crypt32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved crypt32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "ole32" => {
            let exports = ole32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved ole32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "version" => {
            let exports = version::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved version!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "winmm" => {
            let exports = winmm::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved winmm!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "shlwapi" => {
            let exports = shlwapi::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved shlwapi!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "setupapi" => {
            let exports = setupapi::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved setupapi!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "shell32" => {
            let exports = shell32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved shell32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "opengl32" => {
            let exports = opengl32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved opengl32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "oleaut32" => {
            let exports = oleaut32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved oleaut32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "imm32" => {
            let exports = imm32::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved imm32!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "winhttp" => {
            let exports = winhttp::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved winhttp!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "dwmapi" => {
            let exports = dwmapi::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved dwmapi!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "hid" => {
            let exports = hid::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved hid!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        "dbghelp" => {
            let exports = dbghelp::get_exports();
            if let Some(addr) = resolve_export_name(&exports, func_name) {
                trace!("Resolved dbghelp!{} -> {:#x}", func_name, addr);
                return addr;
            }
        }
        _ => {}
    }

    trace!("Unresolved import {}!{}", dll_name, func_name);
    0
}

/// Resolves an import by ordinal number from a static reimplemented DLL.
/// Returns the address of the function if found, or 0 if not implemented.
pub fn resolve_export_by_ordinal(module_handle: usize, dll_name: &str, ordinal: u16) -> Option<usize> {
    // For reimplemented DLLs, try looking up by "#N" format in exports
    let key = loader::module_key_by_handle(module_handle)?;
    let guard = loader::registry().read().ok()?;
    let module = guard.get(&key)?;

    match &module.source {
        loader::ModuleSource::Reimplemented => {
            let ordinal_key = format!("#{}", ordinal);
            let addr = resolve_reimplemented_export(dll_name, &ordinal_key);
            (addr != 0).then_some(addr)
        }
        _ => None,
    }
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

    #[test]
    fn resolve_export_name_ignores_control_chars() {
        let mut exports = HashMap::new();
        exports.insert("CancelIo", 0x9abcusize);
        assert_eq!(resolve_export_name(&exports, "CancelIo\u{1}\u{2}"), Some(0x9abc));
    }

    #[test]
    fn resolve_reimplemented_kernel32_cancel_io() {
        let addr = super::resolve_reimplemented_export("KERNEL32.dll", "CancelIo");
        assert_ne!(addr, 0);
    }

    #[test]
    fn resolve_reimplemented_kernel32_format_message_a() {
        let addr = super::resolve_reimplemented_export("KERNEL32.dll", "FormatMessageA");
        assert_ne!(addr, 0);
    }
}
