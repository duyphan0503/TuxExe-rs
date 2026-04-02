//! WoW64 — 32-bit PE32 on 64-bit Linux (thunking and address space management).

pub mod address_space;
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

/// Configure WoW64 runtime scaffolding for an x86 image mapped in low memory.
pub fn setup_wow64_context(image_base: usize) -> Result<(), String> {
    let image_base32 = u32::try_from(image_base)
        .map_err(|_| format!("image base 0x{image_base:x} exceeds 32-bit range"))?;

    let _reservation = address_space::reserve_low_4gb_on_startup();
    address_space::validate_low_4gb_mapping(image_base, 1)?;

    let teb = teb32::create_teb32(image_base32);
    let _ = teb32::setup_fs_segment_for_teb32(teb.tib.self_ptr);
    seh::set_x86_seh_head(teb.tib.exception_list);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parser_accepts_native() {
        assert_eq!(parse_x86_backend("native"), X86RunBackend::Native);
        assert_eq!(parse_x86_backend("NATIVE"), X86RunBackend::Native);
    }

    #[test]
    fn backend_parser_defaults_to_wine() {
        assert_eq!(parse_x86_backend("wine"), X86RunBackend::Wine);
        assert_eq!(parse_x86_backend(""), X86RunBackend::Wine);
        assert_eq!(parse_x86_backend("unknown"), X86RunBackend::Wine);
    }
}
