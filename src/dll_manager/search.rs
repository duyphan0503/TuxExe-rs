//! DLL search order (mirrors Windows DLL search semantics).

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

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

fn executable_directory_cell() -> &'static RwLock<Option<PathBuf>> {
    static EXE_DIR: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
    EXE_DIR.get_or_init(|| RwLock::new(None))
}

/// Configure the primary executable directory for DLL search.
///
/// When set, this directory is searched before the current working directory.
pub fn set_executable_directory(dir: Option<PathBuf>) {
    *executable_directory_cell().write().expect("executable directory lock poisoned") = dir;
}

fn configured_executable_directory() -> Option<PathBuf> {
    executable_directory_cell().read().expect("executable directory lock poisoned").clone()
}

fn push_unique_root(roots: &mut Vec<PathBuf>, root: PathBuf) {
    if !roots.iter().any(|existing| existing == &root) {
        roots.push(root);
    }
}

fn default_search_roots(mode: DllSearchMode) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(exe_dir) = configured_executable_directory() {
        push_unique_root(&mut roots, exe_dir);
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_unique_root(&mut roots, cwd);
    }

    if let Ok(home) = std::env::var("HOME") {
        let base = PathBuf::from(home).join(".tuxexe").join("drive_c").join("Windows");
        match mode {
            DllSearchMode::Native => {
                push_unique_root(&mut roots, base.join("System32"));
                push_unique_root(&mut roots, base.join("SysWOW64"));
            }
            DllSearchMode::Wow64 => {
                push_unique_root(&mut roots, base.join("SysWOW64"));
                push_unique_root(&mut roots, base.join("System32"));
            }
        }
        push_unique_root(&mut roots, base);
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn executable_directory_is_searched_before_cwd() {
        let _guard = crate::test_support::serial_guard();

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_nanos();
        let base = std::env::temp_dir().join(format!("tuxexe-search-{nonce}"));
        let exe_dir = base.join("exe");
        let cwd_dir = base.join("cwd");
        std::fs::create_dir_all(&exe_dir).expect("create exe dir");
        std::fs::create_dir_all(&cwd_dir).expect("create cwd dir");

        let dll_name = "priority_test.dll";
        let exe_dll = exe_dir.join(dll_name);
        let cwd_dll = cwd_dir.join(dll_name);
        std::fs::write(&exe_dll, b"exe").expect("write exe dll");
        std::fs::write(&cwd_dll, b"cwd").expect("write cwd dll");

        let original_cwd = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(&cwd_dir).expect("switch cwd");
        set_executable_directory(Some(exe_dir.clone()));

        let resolved = resolve_dll_path(dll_name);

        set_executable_directory(None);
        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        std::fs::remove_dir_all(&base).expect("cleanup temp dirs");

        assert_eq!(resolved, Some(exe_dll));
    }
}
