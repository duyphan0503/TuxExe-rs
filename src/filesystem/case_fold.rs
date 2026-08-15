//! High-performance concurrent case-insensitive file lookup with directory caching.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

struct CaseFoldCache {
    entries: RwLock<HashMap<String, Option<PathBuf>>>,
}

impl CaseFoldCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(4096)),
        }
    }

    fn get(&self, key: &str) -> Option<Option<PathBuf>> {
        self.entries.read().ok()?.get(key).cloned()
    }

    fn insert_batch(&self, batch: Vec<(String, PathBuf)>) {
        if let Ok(mut guard) = self.entries.write() {
            for (key, path) in batch {
                guard.insert(key, Some(path));
            }
        }
    }

    fn insert_miss(&self, key: String) {
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(key, None);
        }
    }
}

fn cache_key(path: &Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

fn global_cache() -> &'static CaseFoldCache {
    static CACHE: OnceLock<CaseFoldCache> = OnceLock::new();
    CACHE.get_or_init(CaseFoldCache::new)
}

/// Resolve a path using case-insensitive file name matching.
///
/// If the exact path exists, returns it directly.
/// Otherwise scans the parent directory for a case-insensitive filename match,
/// caching all entries in that directory for fast subsequent lookups.
pub fn resolve_case_insensitive(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }

    let key = cache_key(path);
    if let Some(cached) = global_cache().get(&key) {
        return cached;
    }

    let parent = path.parent()?;
    let file_name = path.file_name()?.to_string_lossy().to_string();

    let Ok(dir_entries) = std::fs::read_dir(parent) else {
        global_cache().insert_miss(key);
        return None;
    };

    let mut batch = Vec::new();
    let mut matched = None;

    for entry in dir_entries.flatten() {
        let entry_path = entry.path();
        let entry_name = entry.file_name();
        let entry_name_str = entry_name.to_string_lossy();
        
        let entry_key = cache_key(&entry_path);
        if entry_name_str.eq_ignore_ascii_case(&file_name) {
            matched = Some(entry_path.clone());
        }
        batch.push((entry_key, entry_path));
    }

    if !batch.is_empty() {
        global_cache().insert_batch(batch);
    }

    if matched.is_none() {
        global_cache().insert_miss(key);
    }

    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn finds_case_insensitive_match() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let real_file = temp.path().join("ReadMe.TXT");
        std::fs::write(&real_file, b"ok").expect("write");

        let lookup = temp.path().join("readme.txt");
        let resolved = resolve_case_insensitive(&lookup).expect("resolved");
        assert_eq!(resolved, real_file);
    }

    #[test]
    fn returns_exact_path_when_present() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let real_file = temp.path().join("config.ini");
        std::fs::write(&real_file, b"ok").expect("write");

        let resolved = resolve_case_insensitive(&real_file).expect("resolved");
        assert_eq!(resolved, real_file);
    }
}
