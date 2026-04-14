//! Runtime DLL loader and module lifecycle management.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock, RwLock,
};

use goblin::pe::PE;
use tracing::{info, trace, warn};

use crate::pe_loader::imports::{enumerate_delay_imports, enumerate_imports, resolve_imports};
use crate::pe_loader::mapper::{map_pe, MappedImage};
use crate::pe_loader::parser::ParsedPe;
use crate::pe_loader::relocations::apply_relocations;
use crate::threading::tls::initialize_static_tls;

use super::search::resolve_dll_path;

const DLL_PROCESS_DETACH: u32 = 0;
const DLL_PROCESS_ATTACH: u32 = 1;

#[derive(Debug)]
pub enum ModuleSource {
    Reimplemented,
    Native(Box<NativeModule>),
    LoadingNative(PathBuf),
}

#[derive(Debug)]
pub struct NativeModule {
    pub path: PathBuf,
    pub mapped: MappedImage,
    pub parsed: ParsedPe,
    pub exports: HashMap<String, usize>,
}

#[derive(Debug)]
pub struct LoadedModule {
    pub handle: usize,
    pub canonical_name: String,
    pub source: ModuleSource,
    pub ref_count: usize,
}

pub(crate) fn registry() -> &'static RwLock<HashMap<String, LoadedModule>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, LoadedModule>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

fn next_module_handle() -> usize {
    static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(0x7000_0000);
    NEXT_HANDLE.fetch_add(0x1000, Ordering::Relaxed)
}

fn canonicalize_module_name(name: &str) -> String {
    let lower = name.trim().replace('\\', "/").to_ascii_lowercase();
    let leaf = lower.rsplit('/').next().unwrap_or(&lower);
    let with_ext = if leaf.ends_with(".dll") {
        leaf.to_string()
    } else {
        format!("{leaf}.dll")
    };

    normalize_api_set_name(&with_ext)
}

fn normalize_api_set_name(canonical: &str) -> String {
    match canonical {
        // Common API-set forwarders used by Unity/CRT startup.
        // We route them to concrete host DLLs like Windows loader does.
        "api-ms-win-core-synch-l1-2-0.dll"
        | "api-ms-win-core-synch-l1-1-0.dll"
        | "api-ms-win-core-threadpool-l1-2-0.dll"
        | "api-ms-win-core-threadpool-l1-1-0.dll"
        | "api-ms-win-core-fibers-l1-1-1.dll"
        | "api-ms-win-core-fibers-l1-1-0.dll"
        | "api-ms-win-core-processthreads-l1-1-0.dll"
        | "api-ms-win-core-processthreads-l1-1-1.dll"
        | "api-ms-win-core-handle-l1-1-0.dll"
        | "api-ms-win-core-heap-l1-1-0.dll"
        | "api-ms-win-core-memory-l1-1-0.dll"
        | "api-ms-win-core-file-l1-1-0.dll"
        | "api-ms-win-core-file-l1-2-0.dll"
        | "api-ms-win-core-libraryloader-l1-1-0.dll"
        | "api-ms-win-core-localization-l1-2-0.dll"
        | "api-ms-win-core-localization-l1-2-1.dll"
        | "api-ms-win-core-datetime-l1-1-0.dll"
        | "api-ms-win-core-sysinfo-l1-1-0.dll"
        | "api-ms-win-core-string-l1-1-0.dll"
        | "api-ms-win-core-errorhandling-l1-1-0.dll"
        | "api-ms-win-core-debug-l1-1-0.dll"
        | "api-ms-win-core-profile-l1-1-0.dll"
        | "api-ms-win-core-util-l1-1-0.dll"
        | "ext-ms-win-ntuser-window-l1-1-0.dll"
        | "ext-ms-win-ntuser-message-l1-1-0.dll"
        | "ext-ms-win-ntuser-input-l1-1-0.dll" => "kernel32.dll".to_string(),

        "api-ms-win-crt-runtime-l1-1-0.dll"
        | "api-ms-win-crt-heap-l1-1-0.dll"
        | "api-ms-win-crt-stdio-l1-1-0.dll"
        | "api-ms-win-crt-string-l1-1-0.dll"
        | "api-ms-win-crt-convert-l1-1-0.dll"
        | "api-ms-win-crt-locale-l1-1-0.dll"
        | "api-ms-win-crt-math-l1-1-0.dll"
        | "api-ms-win-crt-time-l1-1-0.dll"
        | "api-ms-win-crt-environment-l1-1-0.dll" => "msvcrt.dll".to_string(),

        _ => canonical.to_string(),
    }
}

fn is_reimplemented(canonical: &str) -> bool {
    matches!(
        canonical,
        "kernel32.dll"
            | "msvcrt.dll"
            | "ws2_32.dll"
            | "user32.dll"
            | "gdi32.dll"
            | "dinput8.dll"
            | "dsound.dll"
            | "bcrypt.dll"
            | "crypt32.dll"
            | "ole32.dll"
            | "version.dll"
            | "advapi32.dll"
            | "winmm.dll"
            | "shlwapi.dll"
            | "setupapi.dll"
            | "shell32.dll"
            | "opengl32.dll"
            | "oleaut32.dll"
            | "imm32.dll"
            | "winhttp.dll"
            | "dwmapi.dll"
            | "hid.dll"
            | "dbghelp.dll"
    )
}

pub(crate) fn module_key_by_handle(handle: usize) -> Option<String> {
    registry()
        .read()
        .expect("dll registry poisoned")
        .iter()
        .find_map(|(key, module)| (module.handle == handle).then(|| key.clone()))
}

fn should_call_dll_main() -> bool {
    match std::env::var("TUXEXE_CALL_DLLMAIN") {
        Ok(value) => matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

fn should_call_dll_main_for(canonical: &str) -> bool {
    if should_call_dll_main() {
        return true;
    }

    if canonical.eq_ignore_ascii_case("unityplayer.dll") {
        return matches!(
            std::env::var("TUXEXE_CALL_UNITY_DLLMAIN"),
            Ok(value)
                if matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes"
                )
        );
    }

    false
}

fn call_dll_main(native: &NativeModule, reason: u32) -> Result<(), String> {
    if native.parsed.entry_point_rva == 0 {
        return Ok(());
    }

    let entry = native.mapped.base_addr() + native.parsed.entry_point_rva as usize;
    trace!(
        path = %native.path.display(),
        reason,
        entry = format_args!("0x{entry:x}"),
        "Invoking DllMain"
    );

    // SAFETY: We mapped and relocated the image and call its declared DLL entrypoint ABI.
    let result = unsafe {
        let dll_main: extern "win64" fn(*mut c_void, u32, *mut c_void) -> i32 =
            std::mem::transmute(entry);
        dll_main(native.mapped.base_addr() as *mut c_void, reason, std::ptr::null_mut())
    };

    if reason == DLL_PROCESS_ATTACH && result == 0 {
        return Err(format!(
            "DllMain returned FALSE during PROCESS_ATTACH for {}",
            native.path.display()
        ));
    }

    Ok(())
}

fn build_export_map(parsed: &ParsedPe, mapped: &MappedImage) -> HashMap<String, usize> {
    let mut exports = HashMap::new();
    let Ok(pe) = PE::parse(&parsed.raw) else {
        return exports;
    };

    let base = mapped.base_addr();
    for export in pe.exports {
        if let Some(name) = export.name {
            if export.reexport.is_some() {
                continue;
            }
            exports.insert(name.to_string(), base + export.rva);
        }
    }
    exports
}

fn prime_unity_dispatch_cache(module_path: &std::path::Path, mapped: &mut MappedImage) {
    // UnityPlayer contains an encoded dispatch-cache table used to dynamically
    // resolve Fls*/Tls* and locale helpers during very early startup.
    //
    // On our loader path, these slots are observed as zero-initialized, which
    // decodes to a garbage non-null pointer under Unity's cookie transform and
    // causes an immediate `jmp rax` crash.
    //
    // Seeding slots with Unity's encoded `-1` sentinel forces the intended
    // slow-path resolution on first use.
    let name = module_path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    if !name.eq_ignore_ascii_case("unityplayer.dll") {
        return;
    }

    const COOKIE_RVA: usize = 0x1ac2168;
    const HEAP_HANDLE_RVA: usize = 0x1bb1c58;
    const DISPATCH_VECTOR_PTR_RVA: usize = 0x1bb1448;
    const DISPATCH_VECTOR_COUNT_RVA: usize = 0x1bb1440;
    const DISPATCH_TABLE_RVA: usize = 0x1bb1d00;
    const SLOTS_TO_PRIME: usize = 64;

    let Some(cookie) = mapped.read_u64(COOKIE_RVA) else {
        warn!("Unity dispatch cache prime skipped: cookie RVA unreadable");
        return;
    };
    let encoded_minus_one = !0u64 ^ cookie;

    // NOTE:
    // The wider dispatch vector/table around 0x1bb1d00 appears to carry mixed
    // pointer semantics across Unity versions (some paths expect decoded
    // pointers, others encoded sentinels). Writing encoded sentinel values into
    // that table causes deterministic invalid dereferences like
    //   fault = encoded_minus_one + 0x14
    // at startup.
    //
    // Keep this compatibility patch narrow: only seed the single early startup
    // slot we have validated, and avoid touching the broader dispatch vector.

    // Unity also uses a single encoded dispatch slot at 0x1bb1400 for an
    // early startup fallback path. In current traces, force-seeding this slot
    // makes Unity jump into a path that immediately dereferences NULL.
    // Keep it untouched and let Unity initialize it lazily.

    let vector_ptr = mapped.read_u64(DISPATCH_VECTOR_PTR_RVA);
    let vector_count = mapped.read_u32(DISPATCH_VECTOR_COUNT_RVA);
    info!(
        ptr_rva = format_args!("0x{DISPATCH_VECTOR_PTR_RVA:x}"),
        cnt_rva = format_args!("0x{DISPATCH_VECTOR_COUNT_RVA:x}"),
        ptr = format_args!("0x{:x}", vector_ptr.unwrap_or(0)),
        count = vector_count.unwrap_or(0),
        "Unity dispatch vector probe"
    );

    if matches!(vector_ptr, Some(0)) {
        let dispatch_table_va = mapped.base_addr().saturating_add(DISPATCH_TABLE_RVA) as u64;
        let _ = mapped.write_u64(DISPATCH_VECTOR_PTR_RVA, dispatch_table_va);
        info!(
            ptr_rva = format_args!("0x{DISPATCH_VECTOR_PTR_RVA:x}"),
            table_va = format_args!("0x{dispatch_table_va:x}"),
            "Seeded Unity dispatch vector base pointer to primed dispatch table"
        );
    }

    if matches!(vector_count, Some(0)) {
        let _ = mapped.write_u32(DISPATCH_VECTOR_COUNT_RVA, SLOTS_TO_PRIME as u32);
        info!(
            cnt_rva = format_args!("0x{DISPATCH_VECTOR_COUNT_RVA:x}"),
            count = SLOTS_TO_PRIME,
            "Seeded Unity dispatch vector count"
        );
    }

    if matches!(mapped.read_u64(HEAP_HANDLE_RVA), Some(0)) {
        let process_heap = crate::memory::heap::get_process_heap();
        let _ = mapped.write_u64(HEAP_HANDLE_RVA, process_heap as u64);
        info!(
            heap_handle = process_heap,
            rva = format_args!("0x{HEAP_HANDLE_RVA:x}"),
            "Seeded Unity CRT heap handle with process heap"
        );
    }

    info!(
        cookie = format_args!("0x{cookie:x}"),
        encoded_minus_one = format_args!("0x{encoded_minus_one:x}"),
        slots = SLOTS_TO_PRIME,
        "Primed Unity dispatch cache slots"
    );
}

fn load_native_module(path: PathBuf) -> Result<NativeModule, String> {
    let parsed = ParsedPe::from_file(&path).map_err(|e| format!("parse failed: {e}"))?;
    let mut mapped = map_pe(&parsed).map_err(|e| format!("map failed: {e}"))?;
    apply_relocations(&parsed, &mut mapped).map_err(|e| format!("relocations failed: {e}"))?;

    let imports =
        enumerate_imports(&parsed, &mapped).map_err(|e| format!("imports failed: {e}"))?;
    resolve_imports(&mut mapped, &parsed, &imports).map_err(|e| format!("IAT failed: {e}"))?;

    let delay_imports = enumerate_delay_imports(&parsed, &mapped)
        .map_err(|e| format!("delay imports failed: {e}"))?;
    resolve_imports(&mut mapped, &parsed, &delay_imports)
        .map_err(|e| format!("delay IAT failed: {e}"))?;

    initialize_static_tls(&parsed, &mut mapped)
        .map_err(|e| format!("static TLS init failed: {e}"))?;

    prime_unity_dispatch_cache(&path, &mut mapped);

    // Runtime patch for UnityPlayer.dll crash at RVA 0x843c78
    // This is a known issue where Unity tries to write to a NULL pointer during init.
    //
    // Code sequence in UnityPlayer.dll:
    //   0x843c68: call 0x841e90         <- init function returns success
    //   0x843c6d: test eax, eax         <- 85 c0
    //   0x843c6f: je 0x843c7f           <- 74 0e (skip if failed)
    //   0x843c71: mov rcx, [rbp+0x630]  <- 48 8b 8d 30 06 00 00 (rcx = NULL!)
    //   0x843c78: mov [rcx+0x1c], 1     <- c7 41 1c 01 00 00 00 (CRASH!)
    //   0x843c7f: mov r13, [rsp+0x6f8]  <- continuation
    //
    // Fix: replace test+je with unconditional JMP to skip the crash block.
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    if name.eq_ignore_ascii_case("unityplayer.dll") {
        // Patch 1: Jump over crash block (test eax,eax + je +0x0e -> jmp +0x10 + NOP + NOP)
        let patch1_rva = 0x843c6dusize;
        let patch1_bytes: [u8; 4] = [0xEB, 0x10, 0x90, 0x90];
        let patch1_ok = if patch1_rva < mapped.size() {
            mapped.write_slice(patch1_rva, &patch1_bytes)
        } else {
            false
        };

        // Patch 2: NOP out crash instruction as backup safety
        let patch2_rva = 0x843c78usize;
        let patch2_bytes: [u8; 7] = [0x90; 7];
        let patch2_ok = if patch2_rva < mapped.size() {
            mapped.write_slice(patch2_rva, &patch2_bytes)
        } else {
            false
        };

        // Patch 3: Replace the Unity thunk `jmp rax` stub (RVA 0x16a4850)
        // with an indirect jump through the known dispatch IAT slot at
        // RVA 0x16b00e8 (`jmp qword ptr [rip+0xb892]`).
        //
        // This avoids immediate crashes when RAX carries an encoded/invalid
        // dispatch cache value during very early startup.
        let patch3_rva = 0x16a4850usize;
        let patch3_bytes: [u8; 6] = [0xFF, 0x25, 0x92, 0xB8, 0x00, 0x00];
        let patch3_ok = if patch3_rva < mapped.size() {
            mapped.write_slice(patch3_rva, &patch3_bytes)
        } else {
            false
        };

        if patch1_ok || patch2_ok || patch3_ok {
            tracing::info!(
                rva1 = format_args!("0x{patch1_rva:x}"),
                rva2 = format_args!("0x{patch2_rva:x}"),
                rva3 = format_args!("0x{patch3_rva:x}"),
                "Applied UnityPlayer.dll runtime crash patches"
            );
        } else {
            tracing::warn!("Failed to apply UnityPlayer.dll runtime crash patches");
        }
    }

    mapped.apply_protections(&parsed).map_err(|e| format!("protections failed: {e}"))?;

    let exports = build_export_map(&parsed, &mapped);
    Ok(NativeModule { path, mapped, parsed, exports })
}

/// Load (or reference) a DLL module and return its pseudo HMODULE handle.
pub fn load_library(module_name: &str) -> Result<usize, String> {
    let canonical = canonicalize_module_name(module_name);
    if canonical.is_empty() || canonical == ".dll" {
        return Err("empty module name".to_string());
    }

    {
        let mut guard = registry().write().expect("dll registry poisoned");
        if let Some(existing) = guard.get_mut(&canonical) {
            existing.ref_count += 1;
            trace!(module = %canonical, ref_count = existing.ref_count, "Reused loaded module");
            return Ok(existing.handle);
        }
    }

    if is_reimplemented(&canonical) {
        let handle = next_module_handle();
        let module = LoadedModule {
            handle,
            canonical_name: canonical.clone(),
            source: ModuleSource::Reimplemented,
            ref_count: 1,
        };
        registry().write().expect("dll registry poisoned").insert(canonical.clone(), module);
        info!(module = %canonical, handle = format_args!("0x{handle:x}"), "Loaded module");
        return Ok(handle);
    }

    let Some(path) = resolve_dll_path(module_name) else {
        return Err(format!("DLL not found: {module_name}"));
    };

    let handle = next_module_handle();
    {
        let module = LoadedModule {
            handle,
            canonical_name: canonical.clone(),
            source: ModuleSource::LoadingNative(path.clone()),
            ref_count: 1,
        };
        registry().write().expect("dll registry poisoned").insert(canonical.clone(), module);
    }

    match load_native_module(path.clone()) {
        Ok(native) => {
            if should_call_dll_main_for(&canonical) {
                if let Err(err) = call_dll_main(&native, DLL_PROCESS_ATTACH) {
                    registry().write().expect("dll registry poisoned").remove(&canonical);
                    return Err(err);
                }
            } else {
                info!(
                    module = %canonical,
                    path = %path.display(),
                    "Skipping DllMain(PROCESS_ATTACH); set TUXEXE_CALL_DLLMAIN=1 (global) or TUXEXE_CALL_UNITY_DLLMAIN=1 (Unity only)"
                );
            }

            let mut guard = registry().write().expect("dll registry poisoned");
            if let Some(module) = guard.get_mut(&canonical) {
                module.source = ModuleSource::Native(Box::new(native));
            } else {
                return Err("module disappeared while finalizing native load".to_string());
            }
            info!(
                module = %canonical,
                path = %path.display(),
                handle = format_args!("0x{handle:x}"),
                "Loaded native module"
            );
            Ok(handle)
        }
        Err(err) => {
            warn!(
                module = %canonical,
                path = %path.display(),
                %err,
                "Failed to load native module"
            );
            registry().write().expect("dll registry poisoned").remove(&canonical);
            Err(err)
        }
    }
}

/// Best-effort lookup of a native module base containing the given virtual address.
pub fn module_base_for_address(address: usize) -> Option<usize> {
    let guard = registry().read().expect("dll registry poisoned");
    guard.values().find_map(|module| {
        let ModuleSource::Native(native) = &module.source else {
            return None;
        };

        let base = native.mapped.base_addr();
        let end = base.saturating_add(native.mapped.size());
        (address >= base && address < end).then_some(base)
    })
}

/// Decrement the module refcount and unload when it reaches zero.
pub fn free_library(module_handle: usize) -> Result<(), String> {
    let Some(key) = module_key_by_handle(module_handle) else {
        return Err(format!("invalid module handle: 0x{module_handle:x}"));
    };

    let mut detached_native: Option<NativeModule> = None;
    {
        let mut guard = registry().write().expect("dll registry poisoned");
        let Some(module) = guard.get_mut(&key) else {
            return Err("module disappeared from registry".to_string());
        };

        if module.ref_count > 1 {
            module.ref_count -= 1;
            trace!(
                module = %module.canonical_name,
                handle = format_args!("0x{:x}", module_handle),
                ref_count = module.ref_count,
                "Decremented module reference count"
            );
            return Ok(());
        }

        let removed = guard.remove(&key).expect("module key should exist");
        if let ModuleSource::Native(native) = removed.source {
            detached_native = Some(*native);
        }
    }

    if should_call_dll_main() {
        if let Some(native) = detached_native.as_ref() {
            if let Err(error) = call_dll_main(native, DLL_PROCESS_DETACH) {
                warn!(
                    module = %key,
                    handle = format_args!("0x{:x}", module_handle),
                    %error,
                    "DllMain detach callback reported an error"
                );
            }
        }
    }

    info!(
        module = %key,
        handle = format_args!("0x{:x}", module_handle),
        "Unloaded module"
    );
    Ok(())
}

/// Return HMODULE for a loaded module name if present.
pub fn get_loaded_module_handle(module_name: &str) -> Option<usize> {
    let canonical = canonicalize_module_name(module_name);
    registry().read().expect("dll registry poisoned").get(&canonical).map(|m| m.handle)
}

/// Return a displayable module filename/path for a loaded module handle.
pub fn get_loaded_module_filename(module_handle: usize) -> Option<String> {
    let key = module_key_by_handle(module_handle)?;
    let guard = registry().read().expect("dll registry poisoned");
    let module = guard.get(&key)?;

    match &module.source {
        ModuleSource::Native(native) => Some(native.path.display().to_string()),
        ModuleSource::Reimplemented | ModuleSource::LoadingNative(_) => {
            Some(module.canonical_name.clone())
        }
    }
}

/// Resolve an exported symbol from a loaded module handle.
pub fn resolve_export(module_handle: usize, proc_name: &str) -> Option<usize> {
    let key = module_key_by_handle(module_handle)?;
    let guard = registry().read().expect("dll registry poisoned");
    let module = guard.get(&key)?;

    match &module.source {
        ModuleSource::Reimplemented => {
            let addr = super::resolve_reimplemented_export(&module.canonical_name, proc_name);
            (addr != 0).then_some(addr)
        }
        ModuleSource::Native(native) => {
            let trimmed = proc_name.trim().trim_end_matches('\0').trim();
            let undecorated = trimmed
                .strip_prefix('_')
                .unwrap_or(trimmed)
                .split_once('@')
                .and_then(|(name, suffix)| {
                    suffix.chars().all(|ch| ch.is_ascii_digit()).then_some(name)
                })
                .unwrap_or_else(|| trimmed.strip_prefix('_').unwrap_or(trimmed));

            [trimmed, undecorated].into_iter().find_map(|candidate| {
                native.exports.get(candidate).copied().or_else(|| {
                    native.exports.iter().find_map(|(name, addr)| {
                        name.eq_ignore_ascii_case(candidate).then_some(*addr)
                    })
                })
            })
        }
        ModuleSource::LoadingNative(path) => {
            warn!(
                module = %module.canonical_name,
                path = %path.display(),
                proc_name = %proc_name,
                "Requested export from module still loading"
            );
            None
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_registry_for_tests() {
    registry().write().expect("dll registry poisoned").clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_adds_dll_extension() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        assert_eq!(canonicalize_module_name("KERNEL32"), "kernel32.dll");
        assert_eq!(canonicalize_module_name("C:\\Windows\\System32\\msvcrt.dll"), "msvcrt.dll");
        assert_eq!(
            canonicalize_module_name("api-ms-win-core-synch-l1-2-0"),
            "kernel32.dll"
        );
        assert_eq!(
            canonicalize_module_name("api-ms-win-crt-runtime-l1-1-0.dll"),
            "msvcrt.dll"
        );
    }

    #[test]
    fn load_library_reuses_handle_for_same_module() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let h1 = load_library("kernel32").expect("load 1");
        let h2 = load_library("kernel32.dll").expect("load 2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn get_loaded_module_handle_reports_loaded_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let handle = load_library("msvcrt").expect("load");
        assert_eq!(get_loaded_module_handle("MSVCRT.DLL"), Some(handle));
    }

    #[test]
    fn resolve_export_works_for_reimplemented_modules() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let handle = load_library("kernel32").expect("load");
        let addr = resolve_export(handle, "LoadLibraryA");
        assert!(addr.is_some());
    }

    #[test]
    fn resolve_export_finds_cancel_io() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let handle = load_library("kernel32").expect("load");
        let addr = resolve_export(handle, "CancelIo");
        assert!(addr.is_some());
    }

    #[test]
    fn free_library_decrements_refcount_and_unloads() {
        let _guard = crate::test_support::serial_guard();
        reset_registry_for_tests();
        let handle = load_library("kernel32").expect("load");
        let handle_again = load_library("kernel32").expect("load again");
        assert_eq!(handle, handle_again);

        free_library(handle).expect("free first ref");
        assert_eq!(get_loaded_module_handle("kernel32"), Some(handle));

        free_library(handle).expect("free second ref");
        assert_eq!(get_loaded_module_handle("kernel32"), None);
    }
}
