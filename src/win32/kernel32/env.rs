//! Environment variable APIs

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ptr;
use std::sync::{OnceLock, RwLock};

type GuestEnvironmentEntry = Option<(String, String)>;

fn guest_environment_overrides() -> &'static RwLock<BTreeMap<String, GuestEnvironmentEntry>> {
    static OVERRIDES: OnceLock<RwLock<BTreeMap<String, GuestEnvironmentEntry>>> = OnceLock::new();
    OVERRIDES.get_or_init(|| RwLock::new(BTreeMap::new()))
}

fn set_guest_environment_variable(name: &str, value: Option<&str>) {
    let folded = name.to_ascii_uppercase();
    if let Ok(mut overrides) = guest_environment_overrides().write() {
        overrides.insert(folded, value.map(|value| (name.to_string(), value.to_string())));
    }
}

pub(crate) fn guest_environment_snapshot() -> Vec<(String, String)> {
    let mut merged: BTreeMap<String, (String, String)> =
        std::env::vars().map(|(name, value)| (name.to_ascii_uppercase(), (name, value))).collect();
    if let Ok(overrides) = guest_environment_overrides().read() {
        for (folded, entry) in overrides.iter() {
            match entry {
                Some((name, value)) => {
                    merged.insert(folded.clone(), (name.clone(), value.clone()));
                }
                None => {
                    merged.remove(folded);
                }
            }
        }
    }
    merged.into_values().collect()
}

fn lookup_env_var_case_insensitive(name: &str) -> Option<String> {
    let folded = name.to_ascii_uppercase();
    if let Ok(overrides) = guest_environment_overrides().read() {
        if let Some(entry) = overrides.get(&folded) {
            return entry.as_ref().map(|(_, value)| value.clone());
        }
    }

    if let Ok(value) = std::env::var(name) {
        return Some(value);
    }

    std::env::vars().find_map(|(key, value)| (key.to_ascii_uppercase() == folded).then_some(value))
}

/// GetEnvironmentVariableA - Get environment variable (ANSI)
#[no_mangle]
pub extern "win64" fn GetEnvironmentVariableA(
    lpName: *const u8,
    lpBuffer: *mut u8,
    nSize: u32,
) -> u32 {
    tracing::debug!("GetEnvironmentVariableA called");

    if lpName.is_null() {
        return 0;
    }

    unsafe {
        let name_cstr = CStr::from_ptr(lpName as *const i8);
        let name = match name_cstr.to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        };

        tracing::trace!("GetEnvironmentVariableA: name={}", name);

        // Get the environment variable
        let value = match lookup_env_var_case_insensitive(name) {
            Some(v) => v,
            None => {
                // Variable not found
                crate::win32::kernel32::error::set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
                tracing::trace!("GetEnvironmentVariableA: {} -> <not found>", name);
                return 0;
            }
        };

        let value_bytes = value.as_bytes();
        let required_size = value_bytes.len() + 1; // +1 for null terminator

        if lpBuffer.is_null() || nSize == 0 {
            // Return required buffer size
            return required_size as u32;
        }

        if (nSize as usize) < required_size {
            // Buffer too small
            crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
            return required_size as u32;
        }

        // Copy value to buffer
        ptr::copy_nonoverlapping(value_bytes.as_ptr(), lpBuffer, value_bytes.len());
        *lpBuffer.add(value_bytes.len()) = 0; // Null terminate

        value_bytes.len() as u32
    }
}

/// GetEnvironmentVariableW - Get environment variable (Unicode)
#[no_mangle]
pub extern "win64" fn GetEnvironmentVariableW(
    lpName: *const u16,
    lpBuffer: *mut u16,
    nSize: u32,
) -> u32 {
    tracing::debug!("GetEnvironmentVariableW called");

    if lpName.is_null() {
        return 0;
    }

    let name = crate::utils::wide_string::wide_to_string(lpName);
    tracing::trace!("GetEnvironmentVariableW: name={}", name);

    // Get the environment variable
    let value = match lookup_env_var_case_insensitive(&name) {
        Some(v) => v,
        None => {
            // Variable not found
            crate::win32::kernel32::error::set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
            tracing::trace!("GetEnvironmentVariableW: {} -> <not found>", name);
            return 0;
        }
    };

    let value_wide = crate::utils::wide_string::str_to_wide(&value);
    let required_size = value_wide.len() + 1; // +1 for null terminator

    if lpBuffer.is_null() || nSize == 0 {
        // Return required buffer size
        return required_size as u32;
    }

    if (nSize as usize) < required_size {
        // Buffer too small
        crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return required_size as u32;
    }

    unsafe {
        // Copy value to buffer
        ptr::copy_nonoverlapping(value_wide.as_ptr(), lpBuffer, value_wide.len());
        *lpBuffer.add(value_wide.len()) = 0; // Null terminate
    }

    value_wide.len() as u32
}

/// SetEnvironmentVariableA - Set environment variable (ANSI)
#[no_mangle]
pub extern "win64" fn SetEnvironmentVariableA(lpName: *const u8, lpValue: *const u8) -> i32 {
    tracing::debug!("SetEnvironmentVariableA called");

    if lpName.is_null() {
        return 0;
    }

    unsafe {
        let name_cstr = CStr::from_ptr(lpName as *const i8);
        let name = match name_cstr.to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        };

        if lpValue.is_null() {
            // Remove the variable
            set_guest_environment_variable(name, None);
        } else {
            let value_cstr = CStr::from_ptr(lpValue as *const i8);
            let value = match value_cstr.to_str() {
                Ok(s) => s,
                Err(_) => return 0,
            };

            tracing::trace!("SetEnvironmentVariableA: {}={}", name, value);
            set_guest_environment_variable(name, Some(value));
        }
    }

    1 // TRUE
}

/// SetEnvironmentVariableW - Set environment variable (Unicode)
#[no_mangle]
pub extern "win64" fn SetEnvironmentVariableW(lpName: *const u16, lpValue: *const u16) -> i32 {
    tracing::debug!("SetEnvironmentVariableW called");

    if lpName.is_null() {
        return 0;
    }

    let name = crate::utils::wide_string::wide_to_string(lpName);

    if lpValue.is_null() {
        // Remove the variable
        set_guest_environment_variable(&name, None);
    } else {
        let value = crate::utils::wide_string::wide_to_string(lpValue);
        tracing::trace!("SetEnvironmentVariableW: {}={}", name, value);
        set_guest_environment_variable(&name, Some(&value));
    }

    1 // TRUE
}

/// ExpandEnvironmentStringsA - Expand environment variables in a string (ANSI)
#[no_mangle]
pub extern "win64" fn ExpandEnvironmentStringsA(
    lpSrc: *const u8,
    lpDst: *mut u8,
    nSize: u32,
) -> u32 {
    tracing::debug!("ExpandEnvironmentStringsA called");

    if lpSrc.is_null() {
        return 0;
    }

    unsafe {
        let src_cstr = CStr::from_ptr(lpSrc as *const i8);
        let src = match src_cstr.to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let expanded = expand_env_vars(src);
        let expanded_bytes = expanded.as_bytes();
        let required_size = expanded_bytes.len() + 1;

        if lpDst.is_null() || nSize == 0 {
            return required_size as u32;
        }

        if (nSize as usize) < required_size {
            return required_size as u32;
        }

        ptr::copy_nonoverlapping(expanded_bytes.as_ptr(), lpDst, expanded_bytes.len());
        *lpDst.add(expanded_bytes.len()) = 0;

        required_size as u32
    }
}

/// ExpandEnvironmentStringsW - Expand environment variables in a string (Unicode)
#[no_mangle]
pub extern "win64" fn ExpandEnvironmentStringsW(
    lpSrc: *const u16,
    lpDst: *mut u16,
    nSize: u32,
) -> u32 {
    tracing::debug!("ExpandEnvironmentStringsW called");

    if lpSrc.is_null() {
        return 0;
    }

    let src = crate::utils::wide_string::wide_to_string(lpSrc);
    let expanded = expand_env_vars(&src);
    let expanded_wide = crate::utils::wide_string::str_to_wide(&expanded);
    let required_size = expanded_wide.len() + 1;

    if lpDst.is_null() || nSize == 0 {
        return required_size as u32;
    }

    if (nSize as usize) < required_size {
        return required_size as u32;
    }

    unsafe {
        ptr::copy_nonoverlapping(expanded_wide.as_ptr(), lpDst, expanded_wide.len());
        *lpDst.add(expanded_wide.len()) = 0;
    }

    required_size as u32
}

// Helper function to expand %VAR% in strings
fn expand_env_vars(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Found start of variable
            let mut var_name = String::new();
            let mut found_end = false;

            while let Some(&next_ch) = chars.peek() {
                if next_ch == '%' {
                    chars.next(); // Consume the closing %
                    found_end = true;
                    break;
                }
                var_name.push(chars.next().unwrap());
            }

            if found_end && !var_name.is_empty() {
                // Try to get the variable value
                if let Some(value) = lookup_env_var_case_insensitive(&var_name) {
                    result.push_str(&value);
                } else {
                    // Variable not found, keep original
                    result.push('%');
                    result.push_str(&var_name);
                    result.push('%');
                }
            } else {
                // No closing %, just add the %
                result.push('%');
                result.push_str(&var_name);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Initialize common Windows environment variables
pub fn init_windows_env_vars() {
    let home =
        std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| "/tmp".into());
    let profile = home.join(".tuxexe/drive_c/users/User");
    for directory in [
        profile.join("AppData/Roaming"),
        profile.join("AppData/Local"),
        profile.join("AppData/LocalLow"),
        profile.join("AppData/Local/Temp"),
        profile.join("Documents"),
    ] {
        if let Err(error) = std::fs::create_dir_all(&directory) {
            tracing::warn!(?directory, %error, "Failed to create virtual Windows profile directory");
        }
    }

    for (name, value) in [
        ("SYSTEMROOT", r"C:\Windows"),
        ("WINDIR", r"C:\Windows"),
        ("PROGRAMFILES", r"C:\Program Files"),
        ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        ("ProgramFiles", r"C:\Program Files"),
        ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ("ProgramData", r"C:\ProgramData"),
        ("USERPROFILE", r"C:\Users\User"),
        ("APPDATA", r"C:\Users\User\AppData\Roaming"),
        ("LOCALAPPDATA", r"C:\Users\User\AppData\Local"),
        ("TEMP", r"C:\Users\User\AppData\Local\Temp"),
        ("TMP", r"C:\Users\User\AppData\Local\Temp"),
        ("USERNAME", "User"),
        ("HOMEDRIVE", "C:"),
        ("HOMEPATH", r"\Users\User"),
        ("COMPUTERNAME", "TUXEXE-PC"),
    ] {
        set_guest_environment_variable(name, Some(value));
    }

    tracing::debug!("Windows environment variables initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn initializes_guest_visible_paths_with_one_windows_profile() {
        let _guard = serial_guard();
        const NAMES: [&str; 7] =
            ["SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"];
        let original_temp = std::env::var_os("TEMP");
        std::env::set_var("TEMP", "/host/tmp-must-remain-linux");

        init_windows_env_vars();
        let actual: Vec<_> = NAMES
            .iter()
            .map(|name| {
                ((*name).to_string(), lookup_env_var_case_insensitive(name).expect("initialized"))
            })
            .collect();
        let host_temp = std::env::var("TEMP").expect("host TEMP");

        match original_temp {
            Some(value) => std::env::set_var("TEMP", value),
            None => std::env::remove_var("TEMP"),
        }

        assert_eq!(
            actual,
            vec![
                ("SYSTEMROOT".into(), r"C:\Windows".into()),
                ("WINDIR".into(), r"C:\Windows".into()),
                ("USERPROFILE".into(), r"C:\Users\User".into()),
                ("APPDATA".into(), r"C:\Users\User\AppData\Roaming".into()),
                ("LOCALAPPDATA".into(), r"C:\Users\User\AppData\Local".into()),
                ("TEMP".into(), r"C:\Users\User\AppData\Local\Temp".into()),
                ("TMP".into(), r"C:\Users\User\AppData\Local\Temp".into()),
            ]
        );
        assert_eq!(host_temp, "/host/tmp-must-remain-linux");
    }
}
