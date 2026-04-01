//! Windows path ↔ Linux path conversion (C:\foo\bar → ~/.tuxexe/drive_c/foo/bar).

use std::path::{Path, PathBuf};

use crate::filesystem::drives::{normalize_drive_letter, DriveMap};

#[derive(Debug, Clone)]
pub struct SpecialFolders {
    pub temp: PathBuf,
    pub user_profile: PathBuf,
    pub app_data: PathBuf,
}

impl SpecialFolders {
    pub fn from_host_env() -> Self {
        let user_profile =
            std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"));
        let temp =
            std::env::var("TMPDIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"));
        let app_data = user_profile.join(".local/share");

        Self { temp, user_profile, app_data }
    }
}

fn expand_special_folders(input: &str, special: &SpecialFolders) -> Option<PathBuf> {
    let normalized = input.replace('\\', "/").to_ascii_uppercase();
    match normalized.as_str() {
        "%TEMP%" | "%TMP%" => Some(special.temp.clone()),
        "%USERPROFILE%" => Some(special.user_profile.clone()),
        "%APPDATA%" => Some(special.app_data.clone()),
        _ => None,
    }
}

/// Translate a Windows path into a Linux host path.
pub fn windows_to_host(
    input: &str,
    drives: &DriveMap,
    special: &SpecialFolders,
) -> Result<PathBuf, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Path is empty".to_string());
    }

    if let Some(mapped) = expand_special_folders(trimmed, special) {
        return Ok(mapped);
    }

    let normalized = trimmed.replace('\\', "/");
    let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);

    // Host-absolute fallback for internal/runtime callers that already resolved a Linux path.
    if normalized.starts_with('/') {
        return Ok(PathBuf::from(normalized));
    }

    // Drive-absolute paths like "C:/Windows/System32"
    if normalized.len() >= 2 && normalized.as_bytes()[1] == b':' {
        let drive = normalized
            .chars()
            .next()
            .and_then(normalize_drive_letter)
            .ok_or_else(|| format!("Invalid drive in path: {input}"))?;
        let root = drives.resolve(drive).ok_or_else(|| format!("Drive {drive}: not configured"))?;

        let tail = normalized[2..].trim_start_matches('/');
        return Ok(root.join(tail));
    }

    // Fallback for relative paths: resolve against current working directory.
    Ok(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(normalized))
}

/// Translate a Linux host path back into Windows drive syntax.
pub fn host_to_windows(host_path: &Path, drives: &DriveMap) -> Option<String> {
    for drive in 'A'..='Z' {
        let root = drives.resolve(drive)?;
        if let Ok(suffix) = host_path.strip_prefix(root) {
            let mut out = format!("{drive}:");
            if !suffix.as_os_str().is_empty() {
                out.push('\\');
                out.push_str(&suffix.to_string_lossy().replace('/', "\\"));
            }
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn translates_drive_absolute_path() {
        let drives = DriveMap::new_with_prefix(PathBuf::from("/sandbox/.tuxexe"));
        let special = SpecialFolders {
            temp: PathBuf::from("/tmp"),
            user_profile: PathBuf::from("/home/tester"),
            app_data: PathBuf::from("/home/tester/.local/share"),
        };

        let host = windows_to_host(r"C:\Windows\System32\kernel32.dll", &drives, &special)
            .expect("translate");
        assert_eq!(host, PathBuf::from("/sandbox/.tuxexe/drive_c/Windows/System32/kernel32.dll"));
    }

    #[test]
    fn expands_special_folder_tokens() {
        let drives = DriveMap::new_with_prefix(PathBuf::from("/sandbox/.tuxexe"));
        let special = SpecialFolders {
            temp: PathBuf::from("/tmp/virtual"),
            user_profile: PathBuf::from("/home/tester"),
            app_data: PathBuf::from("/home/tester/.local/share"),
        };

        assert_eq!(
            windows_to_host("%TEMP%", &drives, &special).expect("temp"),
            PathBuf::from("/tmp/virtual")
        );
        assert_eq!(
            windows_to_host("%APPDATA%", &drives, &special).expect("appdata"),
            PathBuf::from("/home/tester/.local/share")
        );
    }

    #[test]
    fn converts_host_path_back_to_windows() {
        let drives = DriveMap::new_with_prefix(PathBuf::from("/sandbox/.tuxexe"));
        let win =
            host_to_windows(Path::new("/sandbox/.tuxexe/drive_c/Users/tester/file.txt"), &drives)
                .expect("to windows path");
        assert_eq!(win, r"C:\Users\tester\file.txt");
    }
}
