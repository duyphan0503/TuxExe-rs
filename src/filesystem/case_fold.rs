//! Case-insensitive file lookup — scan directory for case-folded match, cache results.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const DEFAULT_CACHE_CAPACITY: usize = 512;

#[derive(Debug)]
struct LruCache {
    capacity: usize,
    order: VecDeque<String>,
    entries: HashMap<String, PathBuf>,
}

impl LruCache {
    fn new(capacity: usize) -> Self {
        Self { capacity, order: VecDeque::new(), entries: HashMap::new() }
    }

    fn get(&mut self, key: &str) -> Option<PathBuf> {
        let value = self.entries.get(key).cloned()?;
        self.touch(key);
        Some(value)
    }

    fn insert(&mut self, key: String, value: PathBuf) {
        if self.entries.contains_key(&key) {
            self.entries.insert(key.clone(), value);
            self.touch(&key);
            return;
        }

        self.entries.insert(key.clone(), value);
        self.order.push_back(key.clone());

        while self.entries.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn touch(&mut self, key: &str) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.to_string());
    }
}

fn cache_key(path: &Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

fn global_cache() -> &'static Mutex<LruCache> {
    static CACHE: OnceLock<Mutex<LruCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(LruCache::new(DEFAULT_CACHE_CAPACITY)))
}

/// Resolve a path using case-insensitive file name matching.
///
/// If the exact path exists, returns it directly.
/// Otherwise scans the parent directory for a case-insensitive filename match.
pub fn resolve_case_insensitive(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }

    let key = cache_key(path);
    if let Ok(mut cache) = global_cache().lock() {
        if let Some(cached) = cache.get(&key) {
            if cached.exists() {
                return Some(cached);
            }
        }
    }

    let parent = path.parent()?;
    let file_name = path.file_name()?.to_string_lossy().to_string();

    let candidate = std::fs::read_dir(parent).ok()?.filter_map(Result::ok).find_map(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.eq_ignore_ascii_case(&file_name) {
            Some(entry.path())
        } else {
            None
        }
    })?;

    if let Ok(mut cache) = global_cache().lock() {
        cache.insert(key, candidate.clone());
    }

    Some(candidate)
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
