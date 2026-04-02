//! DLL search order (mirrors Windows DLL search semantics).

use std::cell::Cell;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DllSearchMode {
    Native,
    Wow64,
}

thread_local! {
    static DLL_SEARCH_MODE: Cell<DllSearchMode> = const { Cell::new(DllSearchMode::Native) };
}

#[must_use]
pub struct DllSearchModeGuard {
    previous: DllSearchMode,
}

impl Drop for DllSearchModeGuard {
    fn drop(&mut self) {
        DLL_SEARCH_MODE.with(|slot| slot.set(self.previous));
    }
}

pub fn enter_wow64_search_mode() -> DllSearchModeGuard {
    let previous = DLL_SEARCH_MODE.with(|slot| {
        let prev = slot.get();
        slot.set(DllSearchMode::Wow64);
        prev
    });

    DllSearchModeGuard { previous }
}

fn active_search_mode() -> DllSearchMode {
    DLL_SEARCH_MODE.with(Cell::get)
}

fn default_search_roots(mode: DllSearchMode) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }

    if let Ok(home) = std::env::var("HOME") {
        let base = PathBuf::from(home).join(".tuxexe").join("drive_c").join("Windows");
        match mode {
            DllSearchMode::Native => {
                roots.push(base.join("System32"));
                roots.push(base.join("SysWOW64"));
            }
            DllSearchMode::Wow64 => {
                roots.push(base.join("SysWOW64"));
                roots.push(base.join("System32"));
            }
        }
        roots.push(base);
    }

    roots
}

/// Resolve a DLL path by applying a minimal Windows-like search order.
pub fn resolve_dll_path(module_name: &str) -> Option<PathBuf> {
    let trimmed = module_name.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate = Path::new(trimmed);
    if candidate.is_absolute() || trimmed.contains('/') || trimmed.contains('\\') {
        let normalized = PathBuf::from(trimmed.replace('\\', "/"));
        return normalized.exists().then_some(normalized);
    }

    let with_ext = if trimmed.to_ascii_lowercase().ends_with(".dll") {
        trimmed.to_string()
    } else {
        format!("{trimmed}.dll")
    };

    let mode = active_search_mode();
    for root in default_search_roots(mode) {
        let full = root.join(&with_ext);
        if full.exists() {
            return Some(full);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_empty_name() {
        assert!(resolve_dll_path("").is_none());
    }

    #[test]
    fn wow64_guard_switches_mode_temporarily() {
        assert_eq!(active_search_mode(), DllSearchMode::Native);
        {
            let _guard = enter_wow64_search_mode();
            assert_eq!(active_search_mode(), DllSearchMode::Wow64);
        }
        assert_eq!(active_search_mode(), DllSearchMode::Native);
    }
}
