//! Drive letter mapping — C: → ~/.tuxexe/drive_c/, configurable mount points.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Default Linux-side root used for the virtual Windows drive layout.
///
/// Example: `/home/alice/.tuxexe` containing `drive_c`, `drive_d`, ...
pub fn default_prefix() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".tuxexe")
    } else {
        PathBuf::from(".tuxexe")
    }
}

/// Convert a drive letter to canonical uppercase form.
pub fn normalize_drive_letter(letter: char) -> Option<char> {
    if letter.is_ascii_alphabetic() {
        Some(letter.to_ascii_uppercase())
    } else {
        None
    }
}

/// Drive mapping storage used by path translation.
#[derive(Debug, Clone)]
pub struct DriveMap {
    map: BTreeMap<char, PathBuf>,
}

impl Default for DriveMap {
    fn default() -> Self {
        Self::new_with_prefix(default_prefix())
    }
}

impl DriveMap {
    pub fn new_with_prefix(prefix: PathBuf) -> Self {
        let mut map = BTreeMap::new();
        for ch in 'A'..='Z' {
            let dir = format!("drive_{}", ch.to_ascii_lowercase());
            map.insert(ch, prefix.join(dir));
        }
        Self { map }
    }

    pub fn set_drive<P: Into<PathBuf>>(&mut self, letter: char, path: P) -> Result<(), String> {
        let letter = normalize_drive_letter(letter)
            .ok_or_else(|| format!("Invalid drive letter: {letter:?}"))?;
        self.map.insert(letter, path.into());
        Ok(())
    }

    pub fn resolve(&self, letter: char) -> Option<&Path> {
        let letter = normalize_drive_letter(letter)?;
        self.map.get(&letter).map(PathBuf::as_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_default_drive_layout() {
        let map = DriveMap::new_with_prefix(PathBuf::from("/tmp/tuxexe"));
        assert_eq!(map.resolve('c'), Some(Path::new("/tmp/tuxexe/drive_c")));
        assert_eq!(map.resolve('D'), Some(Path::new("/tmp/tuxexe/drive_d")));
    }

    #[test]
    fn set_drive_overrides_mapping() {
        let mut map = DriveMap::new_with_prefix(PathBuf::from("/tmp/tuxexe"));
        map.set_drive('z', "/mnt/windows").expect("set drive");
        assert_eq!(map.resolve('Z'), Some(Path::new("/mnt/windows")));
    }

    #[test]
    fn normalize_drive_letter_rejects_non_alpha() {
        assert_eq!(normalize_drive_letter('C'), Some('C'));
        assert_eq!(normalize_drive_letter('c'), Some('C'));
        assert_eq!(normalize_drive_letter('1'), None);
    }
}
