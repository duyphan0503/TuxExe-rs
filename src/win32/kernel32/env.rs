//! Environment variable APIs

use std::ffi::CStr;
use std::ptr;

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
        let value = match std::env::var(name) {
            Ok(v) => v,
            Err(_) => {
                // Variable not found
                crate::win32::kernel32::error::set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
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
    let value = match std::env::var(&name) {
        Ok(v) => v,
        Err(_) => {
            // Variable not found
            crate::win32::kernel32::error::set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
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
            std::env::remove_var(name);
        } else {
            let value_cstr = CStr::from_ptr(lpValue as *const i8);
            let value = match value_cstr.to_str() {
                Ok(s) => s,
                Err(_) => return 0,
            };

            tracing::trace!("SetEnvironmentVariableA: {}={}", name, value);
            std::env::set_var(name, value);
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
        std::env::remove_var(&name);
    } else {
        let value = crate::utils::wide_string::wide_to_string(lpValue);
        tracing::trace!("SetEnvironmentVariableW: {}={}", name, value);
        std::env::set_var(&name, &value);
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
                if let Ok(value) = std::env::var(&var_name) {
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
    use std::env;

    // Set up common Windows environment variables if not already set
    let home_dir = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let tuxexe_root = format!("{}/.tuxexe", home_dir);
    let drive_c = format!("{}/drive_c", tuxexe_root);

    if env::var("SYSTEMROOT").is_err() {
        env::set_var("SYSTEMROOT", format!("{}/Windows", drive_c));
    }

    if env::var("WINDIR").is_err() {
        env::set_var("WINDIR", format!("{}/Windows", drive_c));
    }

    if env::var("PROGRAMFILES").is_err() {
        env::set_var("PROGRAMFILES", format!("{}/Program Files", drive_c));
    }

    if env::var("PROGRAMFILES(X86)").is_err() {
        env::set_var("PROGRAMFILES(X86)", format!("{}/Program Files (x86)", drive_c));
    }

    if env::var("USERPROFILE").is_err() {
        env::set_var("USERPROFILE", format!("{}/users/tuxexe", drive_c));
    }

    if env::var("APPDATA").is_err() {
        env::set_var("APPDATA", format!("{}/users/tuxexe/AppData/Roaming", drive_c));
    }

    if env::var("LOCALAPPDATA").is_err() {
        env::set_var("LOCALAPPDATA", format!("{}/users/tuxexe/AppData/Local", drive_c));
    }

    if env::var("TEMP").is_err() {
        env::set_var("TEMP", "/tmp");
    }

    if env::var("TMP").is_err() {
        env::set_var("TMP", "/tmp");
    }

    if env::var("COMPUTERNAME").is_err() {
        env::set_var("COMPUTERNAME", "TUXEXE-PC");
    }

    tracing::debug!("Windows environment variables initialized");
}
