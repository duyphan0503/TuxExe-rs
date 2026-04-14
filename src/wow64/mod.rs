//! WoW64 — 32-bit PE32 on 64-bit Linux (thunking and address space management).

pub mod address_space;
pub mod entry;
pub mod loader;
pub mod teb32;
pub mod thunk;

use std::path::Path;
use std::process::Command;

use crate::exceptions::seh;
use crate::pe_loader::parser::{Machine, ParsedPe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X86RunBackend {
    Native,
    Wine,
}

fn parse_x86_backend(raw: &str) -> X86RunBackend {
    match raw.trim().to_ascii_lowercase().as_str() {
        "native" => X86RunBackend::Native,
        _ => X86RunBackend::Wine,
    }
}

fn selected_x86_backend() -> X86RunBackend {
    match std::env::var("TUXEXE_X86_BACKEND") {
        Ok(value) => parse_x86_backend(&value),
        Err(_) => X86RunBackend::Wine,
    }
}

fn run_x86_via_wine(exe: &Path, args: &[String]) -> Result<(), String> {
    let wine_cmd = std::env::var("TUXEXE_WINE_CMD").unwrap_or_else(|_| "wine".to_string());
    let status = Command::new(&wine_cmd)
        .arg(exe)
        .args(args)
        .status()
        .map_err(|err| format!("failed to spawn '{wine_cmd}': {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("'{wine_cmd}' exited with status {status}"))
    }
}

/// For x86 binaries, optionally delegate execution to an external backend.
///
/// Returns `Ok(true)` if execution was delegated and completed.
/// Returns `Ok(false)` when the caller should proceed with native execution path.
pub fn try_delegate_x86_run(exe: &Path, args: &[String]) -> Result<bool, String> {
    let parsed = ParsedPe::from_file(exe).map_err(|err| format!("parse failed: {err}"))?;
    if parsed.machine != Machine::X86 {
        return Ok(false);
    }

    match selected_x86_backend() {
        X86RunBackend::Native => Ok(false),
        X86RunBackend::Wine => {
            run_x86_via_wine(exe, args)?;
            Ok(true)
        }
    }
}

/// Normalize x86 backend mode for native-only runtime.
///
/// Returns `Some(warning)` when a legacy backend value is present and ignored.
pub fn normalize_x86_backend_mode(raw_mode: Option<&str>) -> Option<String> {
    let mode = raw_mode.map(str::trim).filter(|value| !value.is_empty())?;
    if mode.eq_ignore_ascii_case("native") {
        None
    } else {
        Some(format!(
            "ignoring deprecated TUXEXE_X86_BACKEND='{mode}': runtime is native-only and never delegates to Wine"
        ))
    }
}

/// Resolve x86 execution backend policy for native-only mode.
pub fn enforce_native_x86_backend() -> Option<String> {
    normalize_x86_backend_mode(std::env::var("TUXEXE_X86_BACKEND").ok().as_deref())
}

/// Configure WoW64 runtime scaffolding for an x86 image mapped in low memory.
pub fn setup_wow64_context(image_base: usize, mapping_size: usize) -> Result<(), String> {
    let image_base32 = u32::try_from(image_base)
        .map_err(|_| format!("image base 0x{image_base:x} exceeds 32-bit range"))?;

    let _reservation = address_space::reserve_low_4gb_on_startup();
    address_space::validate_low_4gb_mapping(image_base, mapping_size)?;

    let teb = teb32::create_teb32(image_base32);
    let _ = teb32::setup_fs_segment_for_teb32(teb.tib.self_ptr);
    seh::set_x86_seh_head(teb.tib.exception_list);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_native_or_empty_backend_modes() {
        assert!(normalize_x86_backend_mode(None).is_none());
        assert!(normalize_x86_backend_mode(Some("")).is_none());
        assert!(normalize_x86_backend_mode(Some("native")).is_none());
        assert!(normalize_x86_backend_mode(Some("NATIVE")).is_none());
    }

    #[test]
    fn warns_on_non_native_backend_modes() {
        let warning = normalize_x86_backend_mode(Some("wine"))
            .expect("wine mode should produce deprecation warning");
        assert!(warning.contains("deprecated"));
        assert!(warning.contains("native-only"));

        let warning = normalize_x86_backend_mode(Some("custom"))
            .expect("custom mode should produce deprecation warning");
        assert!(warning.contains("native-only"));
    }
}
