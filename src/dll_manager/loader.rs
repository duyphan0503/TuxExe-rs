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

fn registry() -> &'static RwLock<HashMap<String, LoadedModule>> {
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
    if leaf.ends_with(".dll") {
        leaf.to_string()
    } else {
        format!("{leaf}.dll")
    }
}

fn is_reimplemented(canonical: &str) -> bool {
    matches!(canonical, "kernel32.dll" | "msvcrt.dll" | "ws2_32.dll" | "user32.dll" | "gdi32.dll")
}

fn module_key_by_handle(handle: usize) -> Option<String> {
    registry()
        .read()
        .expect("dll registry poisoned")
        .iter()
        .find_map(|(key, module)| (module.handle == handle).then(|| key.clone()))
}

fn call_dll_main(native: &NativeModule, reason: u32) {
    if native.parsed.entry_point_rva == 0 {
        return;
    }

    let entry = native.mapped.base_addr() + native.parsed.entry_point_rva as usize;
    trace!(
        path = %native.path.display(),
        reason,
        entry = format_args!("0x{entry:x}"),
        "Invoking DllMain"
    );

    // SAFETY: We mapped and relocated the image and call its declared DLL entrypoint ABI.
    unsafe {
        let dll_main: extern "win64" fn(*mut c_void, u32, *mut c_void) -> i32 =
            std::mem::transmute(entry);
        let _ = dll_main(native.mapped.base_addr() as *mut c_void, reason, std::ptr::null_mut());
    }
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
            call_dll_main(&native, DLL_PROCESS_ATTACH);
            let mut guard = registry().write().expect("dll registry poisoned");
            if let Some(module) = guard.get_mut(&canonical) {
                module.source = ModuleSource::Native(Box::new(native));
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
            registry().write().expect("dll registry poisoned").remove(&canonical);
            Err(err)
        }
    }
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

    if let Some(native) = detached_native.as_ref() {
        call_dll_main(native, DLL_PROCESS_DETACH);
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
        ModuleSource::Native(native) => native.exports.get(proc_name).copied(),
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
