//! DLL search order (mirrors Windows DLL search semantics).

use std::path::{Path, PathBuf};

fn default_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }

    if let Ok(home) = std::env::var("HOME") {
        let base = PathBuf::from(home).join(".tuxexe").join("drive_c").join("Windows");
        roots.push(base.join("System32"));
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

    for root in default_search_roots() {
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
}
