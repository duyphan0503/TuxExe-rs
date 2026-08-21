//! High-performance concurrent case-insensitive file lookup with directory caching.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static DIRECTORY_SCAN_COUNT: AtomicUsize = AtomicUsize::new(0);

struct CaseFoldCache {
    entries: RwLock<HashMap<String, Option<PathBuf>>>,
}

impl CaseFoldCache {
    fn new() -> Self {
        Self { entries: RwLock::new(HashMap::with_capacity(4096)) }
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

pub fn record_file_created(path: &Path) {
    let key = cache_key(path);
    if let Ok(mut guard) = global_cache().entries.write() {
        guard.insert(key, Some(path.to_path_buf()));
    }
}

pub fn record_file_deleted(path: &Path) {
    let key = cache_key(path);
    if let Ok(mut guard) = global_cache().entries.write() {
        guard.remove(&key);
        guard.insert(key, None);
    }
}

fn normalize_numeric_key(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut chars = lower.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            let mut digits = String::new();
            digits.push(c);
            while let Some(&next) = chars.peek() {
                if next.is_ascii_digit() {
                    digits.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            let trimmed = digits.trim_start_matches('0');
            if trimmed.is_empty() {
                out.push('0');
            } else {
                out.push_str(trimmed);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Resolve a path using case-insensitive file and directory matching.
///
/// If in cache, returns immediately without filesystem syscalls.
/// Otherwise traverses from the root component by component, matching directory and
/// file names case-insensitively while caching directory entries for sub-microsecond lookups.
pub fn resolve_case_insensitive(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        return None;
    }

    let key = cache_key(path);

    // Fast-path: Check memory cache first (instant hit, 0 syscalls)
    match global_cache().get(&key) {
        Some(Some(cached)) => return Some(cached),
        Some(None) => {
            // Guest-created files call `record_file_created`, so a negative entry normally
            // remains authoritative without rescanning the whole directory.  The exact-path
            // probe also notices files created externally on the Linux side.
            if path.exists() {
                let path_buf = path.to_path_buf();
                global_cache().insert_batch(vec![(key, path_buf.clone())]);
                return Some(path_buf);
            }
            return None;
        }
        None => {}
    }

    // Check if the exact path exists on disk
    if path.exists() {
        let path_buf = path.to_path_buf();
        global_cache().insert_batch(vec![(key, path_buf.clone())]);
        return Some(path_buf);
    }

    // Resolve parent directory (fast via cache or single lookup)
    if let Some(parent) = path.parent() {
        let resolved_parent = if parent.as_os_str().is_empty() {
            Some(PathBuf::from("."))
        } else {
            resolve_case_insensitive(parent)
        };

        if let Some(actual_parent) = resolved_parent {
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                let target_numeric_key = normalize_numeric_key(&file_name_str);
                #[cfg(test)]
                DIRECTORY_SCAN_COUNT.fetch_add(1, Ordering::Relaxed);
                if let Ok(dir_entries) = std::fs::read_dir(&actual_parent) {
                    let mut matched = None;
                    let mut numeric_matched = None;
                    let mut batch = Vec::new();
                    for entry in dir_entries.flatten() {
                        let entry_path = entry.path();
                        let entry_name = entry.file_name();
                        let entry_name_str = entry_name.to_string_lossy();
                        let entry_key = cache_key(&entry_path);
                        if entry_name_str.eq_ignore_ascii_case(&file_name_str) {
                            matched = Some(entry_path.clone());
                        } else if matched.is_none()
                            && normalize_numeric_key(&entry_name_str) == target_numeric_key
                        {
                            numeric_matched = Some(entry_path.clone());
                        }
                        batch.push((entry_key, entry_path));
                    }
                    if !batch.is_empty() {
                        global_cache().insert_batch(batch);
                    }
                    if let Some(found) = matched.or(numeric_matched) {
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

    #[test]
    fn finds_numeric_normalized_match() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let real_file = temp.path().join("SaveMap3.png");
        std::fs::write(&real_file, b"png_data").expect("write");

        // Query with zero padding 'SaveMap03.png' should resolve to 'SaveMap3.png'
        let lookup = temp.path().join("SaveMap03.png");
        let resolved = resolve_case_insensitive(&lookup).expect("resolved");
        assert_eq!(resolved, real_file);

        // Query with lowercase 'savemap03.png' should also resolve
        let lookup_lower = temp.path().join("savemap03.png");
        let resolved_lower = resolve_case_insensitive(&lookup_lower).expect("resolved_lower");
        assert_eq!(resolved_lower, real_file);
    }

    #[test]
    fn refreshes_a_cached_miss_after_a_save_file_appears() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let lookup = temp.path().join("SaveImage03.png");

        assert!(resolve_case_insensitive(&lookup).is_none());
        std::fs::write(&lookup, b"real save thumbnail").expect("create save image");

        assert_eq!(resolve_case_insensitive(&lookup), Some(lookup));
    }

    #[test]
    fn cached_miss_does_not_rescan_an_unchanged_save_directory() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let lookup = temp.path().join("SaveImage99.png");

        let before = DIRECTORY_SCAN_COUNT.load(Ordering::Relaxed);
        assert!(resolve_case_insensitive(&lookup).is_none());
        let after_first = DIRECTORY_SCAN_COUNT.load(Ordering::Relaxed);
        assert!(after_first > before, "first miss must inspect its directory");

        assert!(resolve_case_insensitive(&lookup).is_none());
        assert_eq!(
            DIRECTORY_SCAN_COUNT.load(Ordering::Relaxed),
            after_first,
            "a cached miss must not rescan the directory"
        );
    }
}
