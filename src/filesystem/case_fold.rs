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

/// Resolve a path using case-insensitive file and directory matching.
///
/// If the exact path exists, returns it directly.
/// Otherwise traverses from the root component by component, matching directory and
/// Resolve a path using case-insensitive file and directory matching.
///
/// If the exact path exists, returns it directly.
/// Otherwise traverses from the root component by component, matching directory and
/// file names case-insensitively while caching directory entries for sub-microsecond lookups.
pub fn resolve_case_insensitive(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        return None;
    }

    let key = cache_key(path);
    if let Some(cached) = global_cache().get(&key) {
        return cached;
    }

    if path.exists() {
        let path_buf = path.to_path_buf();
        global_cache().insert_batch(vec![(key, path_buf.clone())]);
        return Some(path_buf);
    }

    // Resolve parent directory (fast via cache or single lookup)
    if let Some(parent) = path.parent() {
        let resolved_parent = if parent.as_os_str().is_empty() {
            Some(PathBuf::from("."))
        } else if parent.exists() {
            Some(parent.to_path_buf())
        } else {
            resolve_case_insensitive(parent)
        };

        if let Some(actual_parent) = resolved_parent {
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                if let Ok(dir_entries) = std::fs::read_dir(&actual_parent) {
                    let mut matched = None;
                    let mut batch = Vec::new();
                    for entry in dir_entries.flatten() {
                        let entry_path = entry.path();
                        let entry_name = entry.file_name();
                        let entry_name_str = entry_name.to_string_lossy();
                        let entry_key = cache_key(&entry_path);
                        if entry_name_str.eq_ignore_ascii_case(&file_name_str) {
                            matched = Some(entry_path.clone());
                        }
                        batch.push((entry_key, entry_path));
                    }
                    if !batch.is_empty() {
                        global_cache().insert_batch(batch);
                    }
                    if let Some(found) = matched {
                        global_cache().insert_batch(vec![(key, found.clone())]);
                        return Some(found);
                    }
                }
            }
            global_cache().insert_miss(key);
            return None;
        }
    }

    global_cache().insert_miss(key);
    None
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
    fn finds_multi_level_case_insensitive_match() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let sub_dir = temp.path().join("StreamingAssets").join("DLC");
        std::fs::create_dir_all(&sub_dir).expect("create_dir_all");
        let real_file = sub_dir.join("dlc_00");
        std::fs::write(&real_file, b"dlc content").expect("write");

        let lookup = temp.path().join("streamingassets").join("dlc").join("DLC_00");
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
