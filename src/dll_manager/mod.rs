//! DLL manager — hybrid DLL loading (Rust-reimplemented + real DLL binary fallback).

pub mod loader;
pub mod search;

use crate::win32::{
    advapi32, bcrypt, crypt32, d3d11, dbghelp, dwmapi, dxgi, gdi32, hid, imm32, kernel32, msvcrt,
    ole32, oleaut32, opengl32, setupapi, shell32, shlwapi, unityplayer, user32, version, winhttp,
    winmm, ws2_32,
};
use tracing::trace;

/// Compatibility level of a native export exposed to a guest PE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStatus {
    Implemented,
    CompatibilityStub,
    Unsupported,
}

/// Known bring-up-only exports. These functions are deliberately exposed so
/// applications can progress through startup, but they do not provide the
/// complete Windows behavior of their API.
fn is_compatibility_stub(dll_name: &str, func_name: &str) -> bool {
    let dll = dll_name.trim().to_ascii_lowercase().trim_end_matches(".dll").to_string();
    let func = func_name.trim().to_ascii_lowercase();

    if matches!(dll.as_str(), "dwmapi" | "hid" | "imm32" | "setupapi" | "winmm") {
        return true;
    }

    matches!(
        (dll.as_str(), func.as_str()),
        ("dbghelp", "syminitialize")
            | ("dbghelp", "symcleanup")
            | ("dbghelp", "symgetoptions")
            | ("dbghelp", "symsetoptions")
            | ("dbghelp", "stackwalk64")
            | ("dbghelp", "minidumpwritedump")
            | ("shell32", "shellexecutew")
            | ("shell32", "shellexecuteexw")
            | ("shell32", "shgetfolderpathw")
            | ("shell32", "shgetknownfolderpath")
            | ("shell32", "shbrowseforfolderw")
            | ("shell32", "shfileoperationw")
            | ("shlwapi", "pathfindfilenamew")
            | ("shlwapi", "pathisdirectoryw")
            | ("shlwapi", "pathfileexistsw")
            | ("shlwapi", "pathcanonicalizew")
            | ("shlwapi", "shdeletekeyw")
            | ("unityplayer", "unitygetd3d9interface")
            | ("unityplayer", "unitygetd3d11interface")
            | ("unityplayer", "unitygetd3d12interface")
            | ("unityplayer", "unitygetvulkaninterface")
            | ("unityplayer", "unitygetglinterface")
    )
}

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

    let single_suffix = if trimmed.ends_with("WW") {
        Some(format!("{}W", &trimmed[..trimmed.len() - 1]))
    } else if trimmed.ends_with("AA") {
        Some(format!("{}A", &trimmed[..trimmed.len() - 1]))
    } else {
        None
    };

    let mut candidates = vec![trimmed, undecorated];
    if let Some(s) = single_suffix {
        candidates.push(s);
    }

    candidates.into_iter().find_map(|candidate| {
        exports.get(candidate.as_str()).copied().or_else(|| {
            exports
                .iter()
                .find_map(|(name, addr)| name.eq_ignore_ascii_case(&candidate).then_some(*addr))
        })
    })
}

pub use loader::{
    disable_thread_library_calls, free_library, get_loaded_module_filename,
    get_loaded_module_handle, load_library, resolve_export, LoadedModule, ModuleSource,
    NativeModule,
};

pub extern "win64" fn __wine_dbg_output(str_ptr: *const libc::c_char) -> i32 {
    if !str_ptr.is_null() {
        if let Ok(s) = unsafe { std::ffi::CStr::from_ptr(str_ptr) }.to_str() {
            println!("DXVK: {}", s.trim_end());
        }
    }
    0
}

pub extern "win64" fn __wine_dbg_header(
    _cls: u32,
    _ch: u32,
    _func: *const libc::c_char,
) -> *const libc::c_char {
    static EMPTY: &[u8] = b"\0";
    EMPTY.as_ptr() as *const libc::c_char
}

pub extern "win64" fn __wine_dbg_get_channel_flags(_ch: *const libc::c_char) -> u32 {
    0
}

fn normalize_dll_base_name(dll_name: &str) -> String {
    let dll_lower = dll_name.to_lowercase();
    let base_name =
        if let Some(idx) = dll_lower.find('.') { &dll_lower[..idx] } else { &dll_lower };

    if base_name == "kernelbase" {
        "kernel32".to_string()
    } else if base_name.starts_with("api-ms-win-crt-") {
        "msvcrt".to_string()
    } else if base_name.starts_with("api-ms-win-core-")
        || base_name.starts_with("api-ms-win-shcore-")
        || base_name.starts_with("api-ms-win-appmodel-")
        || base_name.starts_with("api-ms-win-devices-")
    {
        "kernel32".to_string()
    } else if base_name.starts_with("api-ms-win-security-")
        || base_name.starts_with("api-ms-win-eventing-")
        || base_name.starts_with("api-ms-win-service-")
    {
        "advapi32".to_string()
    } else if base_name.starts_with("ext-ms-win-ntuser-") {
        "user32".to_string()
    } else if base_name.starts_with("ext-ms-win-gdi-") {
        "gdi32".to_string()
    } else {
        base_name.to_string()
    }
}

/// Resolves an import in a static reimplemented DLL.
/// Returns the address of the function if found, or 0 if not implemented.
fn resolve_explicit_reimplemented_export(dll_name: &str, func_name: &str) -> Option<usize> {
    let base_name = normalize_dll_base_name(dll_name);

    if base_name == "ntdll" {
        match func_name {
            "__wine_dbg_output" => return Some(__wine_dbg_output as usize),
            "__wine_dbg_header" => return Some(__wine_dbg_header as usize),
            "__wine_dbg_get_channel_flags" => return Some(__wine_dbg_get_channel_flags as usize),
            _ => {
                if let Some(addr) =
                    resolve_export_name(&crate::win32::ntdll::get_exports(), func_name)
                {
                    return Some(addr);
                }
                if let Some(addr) = resolve_export_name(&msvcrt::get_exports(), func_name) {
                    return Some(addr);
                }
                if let Some(addr) = resolve_export_name(&kernel32::get_exports(), func_name) {
                    return Some(addr);
                }
            }
        }
    }

    match base_name.as_str() {
        "kernel32" => resolve_export_name(&kernel32::get_exports(), func_name),
        // UCRT and the legacy MSVCRT exports used by the current games share
        // this implementation.  Falling through to the generic stub makes
        // allocation functions such as ucrtbase!malloc return NULL and causes
        // a misleading crash much later in Unity startup.
        "msvcrt" | "ucrtbase" => resolve_export_name(&msvcrt::get_exports(), func_name),
        "ws2_32" | "iphlpapi" => resolve_export_name(&ws2_32::get_exports(), func_name),
        "user32" | "shcore" => resolve_export_name(&user32::get_exports(), func_name),
        "gdi32" => resolve_export_name(&gdi32::get_exports(), func_name),
        "unityplayer" => resolve_export_name(&unityplayer::get_exports(), func_name),
        "dinput8" => resolve_export_name(&crate::win32::dinput8::get_exports(), func_name),
        "dsound" => resolve_export_name(&crate::win32::dsound::get_exports(), func_name),
        "advapi32" => resolve_export_name(&advapi32::get_exports(), func_name),
        "bcrypt" => resolve_export_name(&bcrypt::get_exports(), func_name),
        "crypt32" => resolve_export_name(&crypt32::get_exports(), func_name),
        "ole32" => resolve_export_name(&ole32::get_exports(), func_name),
        "version" => resolve_export_name(&version::get_exports(), func_name),
        "winmm" => resolve_export_name(&winmm::get_exports(), func_name),
        "shlwapi" => resolve_export_name(&shlwapi::get_exports(), func_name),
        "setupapi" => resolve_export_name(&setupapi::get_exports(), func_name),
        "shell32" => resolve_export_name(&shell32::get_exports(), func_name),
        "opengl32" => {
            if let Some(addr) = resolve_export_name(&opengl32::get_exports(), func_name) {
                Some(addr)
            } else if func_name.starts_with("gl") {
                opengl32::resolve_gl_function(func_name)
            } else {
                None
            }
        }
        "oleaut32" => resolve_export_name(&oleaut32::get_exports(), func_name),
        "imm32" => resolve_export_name(&imm32::get_exports(), func_name),
        "winhttp" => resolve_export_name(&winhttp::get_exports(), func_name),
        "dwmapi" => resolve_export_name(&dwmapi::get_exports(), func_name),
        "hid" => resolve_export_name(&hid::get_exports(), func_name),
        "dbghelp" => resolve_export_name(&dbghelp::get_exports(), func_name),
        "d3d11" => resolve_export_name(&d3d11::get_exports(), func_name),
        "dxgi" => resolve_export_name(&dxgi::get_exports(), func_name),
        "vulkan-1" | "winevulkan" => {
            resolve_export_name(&crate::win32::vulkan::get_exports(), func_name)
        }
        "steam_api64" | "steam_api" => crate::win32::steam_api64::resolve_export(func_name),
        "comdlg32" => resolve_export_name(&crate::win32::comdlg32::get_exports(), func_name),
        "winspool" | "winspool.drv" => {
            resolve_export_name(&crate::win32::winspool::get_exports(), func_name)
        }
        _ => None,
    }
}

/// Resolve an export for a runtime feature probe without fabricating a
/// compatibility stub. Windows `GetProcAddress` returns NULL for a symbol that
/// the selected module does not export; missing optional symbols are expected
/// and must not be reported as startup warnings.
pub(crate) fn resolve_optional_reimplemented_export(
    dll_name: &str,
    func_name: &str,
) -> Option<usize> {
    resolve_explicit_reimplemented_export(dll_name, func_name)
}

/// Resolves an import in a static reimplemented DLL.
///
/// Some well-known startup DLLs intentionally use a generic compatibility
/// fallback so a game can continue far enough to emit diagnostics.  Callers
/// that need to distinguish that fallback from a real export should use
/// [`resolve_export_status`].
pub fn resolve_reimplemented_export(dll_name: &str, func_name: &str) -> usize {
    let base_name = normalize_dll_base_name(dll_name);

    if let Some(addr) = resolve_explicit_reimplemented_export(dll_name, func_name) {
        trace!("Resolved {}!{} -> {:#x}", base_name, func_name, addr);
        addr
    } else if matches!(
        base_name.as_str(),
        "kernel32"
            | "msvcrt"
            | "ws2_32"
            | "user32"
            | "gdi32"
            | "unityplayer"
            | "dinput8"
            | "dsound"
            | "advapi32"
            | "crypt32"
            | "ole32"
            | "version"
            | "winmm"
            | "shlwapi"
            | "setupapi"
            | "shell32"
            | "opengl32"
            | "oleaut32"
            | "imm32"
            | "winhttp"
            | "dwmapi"
            | "hid"
            | "dbghelp"
            | "d3d11"
            | "dxgi"
            | "ntdll"
            | "ucrtbase"
            | "nsi"
            | "dnsapi"
            | "iphlpapi"
            | "vulkan-1"
            | "winevulkan"
            | "comdlg32"
            | "winspool"
            | "winspool.drv"
            | "shcore"
    ) {
        tracing::warn!(
            "{}!{} requested but not explicitly defined — providing generic stub",
            base_name,
            func_name
        );
        msvcrt::generic_msvcrt_stub as usize
    } else {
        trace!("Unresolved import {}!{}", dll_name, func_name);
        0
    }
}

/// Resolve an export and retain whether the address represents a real
/// implementation, a bring-up stub, or an unsupported API.
pub fn resolve_export_status(dll_name: &str, func_name: &str) -> ExportStatus {
    let status = if resolve_explicit_reimplemented_export(dll_name, func_name).is_none() {
        ExportStatus::Unsupported
    } else if is_compatibility_stub(dll_name, func_name) {
        ExportStatus::CompatibilityStub
    } else {
        ExportStatus::Implemented
    };

    crate::runtime::telemetry::record(format!(
        "export_resolve:{}!{}={status:?}",
        dll_name, func_name
    ));
    status
}

/// Resolves an import by ordinal number from a static reimplemented DLL.
/// Returns the address of the function if found, or 0 if not implemented.
pub fn resolve_export_by_ordinal(
    module_handle: usize,
    dll_name: &str,
    ordinal: u16,
) -> Option<usize> {
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
    use super::{
        resolve_export_name, resolve_export_status, resolve_optional_reimplemented_export,
        ExportStatus,
    };
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

    #[test]
    fn ucrtbase_uses_real_crt_allocators() {
        assert_ne!(super::resolve_reimplemented_export("ucrtbase.dll", "malloc"), 0);
        assert_ne!(super::resolve_reimplemented_export("ucrtbase.dll", "free"), 0);
    }

    #[test]
    fn export_status_distinguishes_implemented_stub_and_unsupported() {
        assert_eq!(
            resolve_export_status("kernel32.dll", "GetLastError"),
            ExportStatus::Implemented
        );
        assert_eq!(
            resolve_export_status("setupapi.dll", "SetupDiGetClassDevsW"),
            ExportStatus::CompatibilityStub
        );
        assert_eq!(
            resolve_export_status("kernel32.dll", "DefinitelyMissing"),
            ExportStatus::Unsupported
        );
    }

    #[test]
    fn optional_export_probe_never_fabricates_a_generic_stub() {
        assert!(resolve_optional_reimplemented_export("kernel32.dll", "GetProcAddress").is_some());
        assert!(
            resolve_optional_reimplemented_export("shell32.dll", "mono_profiler_startup").is_none()
        );
        assert!(resolve_optional_reimplemented_export("kernel32.dll", "GetFileAttributesExWW")
            .is_none());
    }
}
