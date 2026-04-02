//! Registry Win32 APIs wrapping NT kernel registry

use std::ffi::CStr;
use std::ptr;
use std::sync::OnceLock;

use crate::registry::store::{RegistryStore, REG_SZ};
use crate::utils::handle::{global_table, HandleObject};

// Error codes
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_MORE_DATA: i32 = 234;
const ERROR_NO_MORE_ITEMS: i32 = 259;

// Registry handle type
const HKEY_CLASSES_ROOT: usize = 0x80000000;
const HKEY_CURRENT_USER: usize = 0x80000001;
const HKEY_LOCAL_MACHINE: usize = 0x80000002;
const HKEY_USERS: usize = 0x80000003;
const HKEY_CURRENT_CONFIG: usize = 0x80000005;

#[derive(Debug)]
struct RegistryKeyHandle {
    path: String,
}

impl HandleObject for RegistryKeyHandle {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "RegistryKey"
    }
}

fn get_registry_store() -> &'static RegistryStore {
    static REGISTRY: OnceLock<RegistryStore> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let db_path = format!("{}/.tuxexe/registry.db", home);
        std::fs::create_dir_all(format!("{}/.tuxexe", home)).ok();

        RegistryStore::new(db_path.into()).expect("Failed to initialize registry")
    })
}

fn hkey_to_path(hKey: usize) -> Option<String> {
    match hKey {
        HKEY_CLASSES_ROOT => Some("HKEY_CLASSES_ROOT".to_string()),
        HKEY_CURRENT_USER => Some("HKEY_CURRENT_USER".to_string()),
        HKEY_LOCAL_MACHINE => Some("HKEY_LOCAL_MACHINE".to_string()),
        HKEY_USERS => Some("HKEY_USERS".to_string()),
        HKEY_CURRENT_CONFIG => Some("HKEY_CURRENT_CONFIG".to_string()),
        _ => {
            // Try to get from handle table
            let table = global_table();
            table.with(hKey as u32, |obj| {
                obj.as_any()
                    .downcast_ref::<RegistryKeyHandle>()
                    .map(|key| key.path.clone())
            }).flatten()
        }
    }
}

/// RegOpenKeyExA - Open registry key (ANSI)
#[no_mangle]
pub extern "win64" fn RegOpenKeyExA(
    hKey: usize,
    lpSubKey: *const u8,
    _ulOptions: u32,
    _samDesired: u32,
    phkResult: *mut usize,
) -> i32 {
    tracing::debug!("RegOpenKeyExA called");

    if phkResult.is_null() {
        return ERROR_FILE_NOT_FOUND;
    }

    let base_path = match hkey_to_path(hKey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let subkey = if lpSubKey.is_null() {
        String::new()
    } else {
        unsafe {
            CStr::from_ptr(lpSubKey as *const i8)
                .to_string_lossy()
                .to_string()
        }
    };

    let full_path = if subkey.is_empty() {
        base_path
    } else {
        format!("{}\\{}", base_path, subkey)
    };

    tracing::trace!("RegOpenKeyExA: opening {}", full_path);

    // Check if key exists
    let store = get_registry_store();
    match store.open_key_exists(&full_path) {
        Ok(true) => {
            // Create handle
            let key_handle = RegistryKeyHandle { path: full_path };
            let handle = global_table().alloc(Box::new(key_handle));
            unsafe {
                *phkResult = handle as usize;
            }
            ERROR_SUCCESS
        }
        _ => ERROR_FILE_NOT_FOUND,
    }
}

/// RegOpenKeyExW - Open registry key (Unicode)
#[no_mangle]
pub extern "win64" fn RegOpenKeyExW(
    hKey: usize,
    lpSubKey: *const u16,
    _ulOptions: u32,
    samDesired: u32,
    phkResult: *mut usize,
) -> i32 {
    tracing::debug!("RegOpenKeyExW called");

    let subkey = if lpSubKey.is_null() {
        String::new()
    } else {
        crate::utils::wide_string::wide_to_string(lpSubKey)
    };

    // Convert to ANSI and call ANSI version
    let subkey_bytes = subkey.as_bytes();
    let mut subkey_cstr = Vec::with_capacity(subkey_bytes.len() + 1);
    subkey_cstr.extend_from_slice(subkey_bytes);
    subkey_cstr.push(0);

    RegOpenKeyExA(
        hKey,
        subkey_cstr.as_ptr(),
        _ulOptions,
        samDesired,
        phkResult,
    )
}

/// RegCloseKey - Close registry key
#[no_mangle]
pub extern "win64" fn RegCloseKey(hKey: usize) -> i32 {
    tracing::debug!("RegCloseKey called: 0x{:x}", hKey);

    // Check if it's a predefined key
    match hKey {
        HKEY_CLASSES_ROOT | HKEY_CURRENT_USER | HKEY_LOCAL_MACHINE | HKEY_USERS
        | HKEY_CURRENT_CONFIG => {
            // Predefined keys don't need to be closed
            return ERROR_SUCCESS;
        }
        _ => {}
    }

    // Remove from handle table
    let table = global_table();
    table.close_handle(hKey as u32);

    ERROR_SUCCESS
}

/// RegQueryValueExA - Query registry value (ANSI)
#[no_mangle]
pub extern "win64" fn RegQueryValueExA(
    hKey: usize,
    lpValueName: *const u8,
    _lpReserved: *const u32,
    lpType: *mut u32,
    lpData: *mut u8,
    lpcbData: *mut u32,
) -> i32 {
    tracing::debug!("RegQueryValueExA called");

    let path = match hkey_to_path(hKey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let value_name = if lpValueName.is_null() {
        None
    } else {
        unsafe {
            Some(
                CStr::from_ptr(lpValueName as *const i8)
                    .to_string_lossy()
                    .to_string(),
            )
        }
    };

    tracing::trace!("RegQueryValueExA: {}\\{:?}", path, value_name);

    let store = get_registry_store();
    match store.query_value(&path, value_name.as_deref()) {
        Ok(Some(value)) => {
            // Set type if requested
            if !lpType.is_null() {
                unsafe {
                    *lpType = value.reg_type;
                }
            }

            // Get required size
            let data_size = value.data.len() as u32;

            if lpcbData.is_null() {
                return ERROR_SUCCESS;
            }

            unsafe {
                let buffer_size = *lpcbData;

                if lpData.is_null() || buffer_size < data_size {
                    // Return required size
                    *lpcbData = data_size;
                    if lpData.is_null() {
                        return ERROR_SUCCESS;
                    }
                    return ERROR_MORE_DATA;
                }

                // Copy data
                ptr::copy_nonoverlapping(value.data.as_ptr(), lpData, value.data.len());
                *lpcbData = data_size;
            }

            ERROR_SUCCESS
        }
        _ => ERROR_FILE_NOT_FOUND,
    }
}

/// RegQueryValueExW - Query registry value (Unicode)
#[no_mangle]
pub extern "win64" fn RegQueryValueExW(
    hKey: usize,
    lpValueName: *const u16,
    _lpReserved: *const u32,
    lpType: *mut u32,
    lpData: *mut u8,
    lpcbData: *mut u32,
) -> i32 {
    tracing::debug!("RegQueryValueExW called");

    let value_name = if lpValueName.is_null() {
        String::new()
    } else {
        crate::utils::wide_string::wide_to_string(lpValueName)
    };

    let value_name_bytes = value_name.as_bytes();
    let mut value_name_cstr = Vec::with_capacity(value_name_bytes.len() + 1);
    value_name_cstr.extend_from_slice(value_name_bytes);
    value_name_cstr.push(0);

    RegQueryValueExA(
        hKey,
        value_name_cstr.as_ptr(),
        _lpReserved,
        lpType,
        lpData,
        lpcbData,
    )
}

/// RegSetValueExA - Set registry value (ANSI)
#[no_mangle]
pub extern "win64" fn RegSetValueExA(
    hKey: usize,
    lpValueName: *const u8,
    _Reserved: u32,
    dwType: u32,
    lpData: *const u8,
    cbData: u32,
) -> i32 {
    tracing::debug!("RegSetValueExA called");

    let path = match hkey_to_path(hKey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let value_name = if lpValueName.is_null() {
        None
    } else {
        unsafe {
            Some(
                CStr::from_ptr(lpValueName as *const i8)
                    .to_string_lossy()
                    .to_string(),
            )
        }
    };

    let data = if lpData.is_null() || cbData == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(lpData, cbData as usize).to_vec() }
    };

    tracing::trace!("RegSetValueExA: {}\\{:?} = {:?} bytes", path, value_name, data.len());

    let store = get_registry_store();
    match store.set_value(&path, value_name.as_deref(), dwType, &data) {
        Ok(_) => ERROR_SUCCESS,
        Err(_) => ERROR_FILE_NOT_FOUND,
    }
}

/// RegSetValueExW - Set registry value (Unicode)
#[no_mangle]
pub extern "win64" fn RegSetValueExW(
    hKey: usize,
    lpValueName: *const u16,
    Reserved: u32,
    dwType: u32,
    lpData: *const u8,
    cbData: u32,
) -> i32 {
    tracing::debug!("RegSetValueExW called");

    let value_name = if lpValueName.is_null() {
        String::new()
    } else {
        crate::utils::wide_string::wide_to_string(lpValueName)
    };

    let value_name_bytes = value_name.as_bytes();
    let mut value_name_cstr = Vec::with_capacity(value_name_bytes.len() + 1);
    value_name_cstr.extend_from_slice(value_name_bytes);
    value_name_cstr.push(0);

    RegSetValueExA(hKey, value_name_cstr.as_ptr(), Reserved, dwType, lpData, cbData)
}

/// RegCreateKeyExA - Create registry key (ANSI)
#[no_mangle]
pub extern "win64" fn RegCreateKeyExA(
    hKey: usize,
    lpSubKey: *const u8,
    _Reserved: u32,
    __lpClass: *const u8,
    _dwOptions: u32,
    _samDesired: u32,
    _lpSecurityAttributes: *const u8,
    phkResult: *mut usize,
    _lpdwDisposition: *mut u32,
) -> i32 {
    tracing::debug!("RegCreateKeyExA called");

    // For now, just open or create the key
    // Setting a dummy value to ensure key exists
    let result = RegOpenKeyExA(hKey, lpSubKey, 0, 0, phkResult);

    if result == ERROR_FILE_NOT_FOUND {
        // Key doesn't exist, create it by setting a dummy value
        let base_path = match hkey_to_path(hKey) {
            Some(p) => p,
            None => return ERROR_FILE_NOT_FOUND,
        };

        let subkey = if lpSubKey.is_null() {
            String::new()
        } else {
            unsafe {
                CStr::from_ptr(lpSubKey as *const i8)
                    .to_string_lossy()
                    .to_string()
            }
        };

        let full_path = if subkey.is_empty() {
            base_path
        } else {
            format!("{}\\{}", base_path, subkey)
        };

        // Create a dummy value to ensure the key exists
        let store = get_registry_store();
        let _ = store.set_value(&full_path, Some("__created__"), REG_SZ, b"");

        // Try to open again
        return RegOpenKeyExA(hKey, lpSubKey, 0, 0, phkResult);
    }

    result
}

/// RegCreateKeyExW - Create registry key (Unicode)
#[no_mangle]
pub extern "win64" fn RegCreateKeyExW(
    hKey: usize,
    lpSubKey: *const u16,
    Reserved: u32,
    _lpClass: *const u16,
    dwOptions: u32,
    samDesired: u32,
    lpSecurityAttributes: *const u8,
    phkResult: *mut usize,
    lpdwDisposition: *mut u32,
) -> i32 {
    tracing::debug!("RegCreateKeyExW called");

    let subkey = if lpSubKey.is_null() {
        String::new()
    } else {
        crate::utils::wide_string::wide_to_string(lpSubKey)
    };

    let subkey_bytes = subkey.as_bytes();
    let mut subkey_cstr = Vec::with_capacity(subkey_bytes.len() + 1);
    subkey_cstr.extend_from_slice(subkey_bytes);
    subkey_cstr.push(0);

    RegCreateKeyExA(
        hKey,
        subkey_cstr.as_ptr(),
        Reserved,
        ptr::null(),
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition,
    )
}

/// RegDeleteKeyA - Delete registry key (ANSI)
#[no_mangle]
pub extern "win64" fn RegDeleteKeyA(hKey: usize, lpSubKey: *const u8) -> i32 {
    tracing::debug!("RegDeleteKeyA called");

    let base_path = match hkey_to_path(hKey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let subkey = if lpSubKey.is_null() {
        String::new()
    } else {
        unsafe {
            CStr::from_ptr(lpSubKey as *const i8)
                .to_string_lossy()
                .to_string()
        }
    };

    let full_path = if subkey.is_empty() {
        base_path
    } else {
        format!("{}\\{}", base_path, subkey)
    };

    let store = get_registry_store();
    match store.delete_key(&full_path) {
        Ok(_) => ERROR_SUCCESS,
        Err(_) => ERROR_FILE_NOT_FOUND,
    }
}

/// RegDeleteKeyW - Delete registry key (Unicode)
#[no_mangle]
pub extern "win64" fn RegDeleteKeyW(hKey: usize, lpSubKey: *const u16) -> i32 {
    tracing::debug!("RegDeleteKeyW called");

    let subkey = if lpSubKey.is_null() {
        String::new()
    } else {
        crate::utils::wide_string::wide_to_string(lpSubKey)
    };

    let subkey_bytes = subkey.as_bytes();
    let mut subkey_cstr = Vec::with_capacity(subkey_bytes.len() + 1);
    subkey_cstr.extend_from_slice(subkey_bytes);
    subkey_cstr.push(0);

    RegDeleteKeyA(hKey, subkey_cstr.as_ptr())
}

/// RegEnumKeyExA - Enumerate registry subkeys (ANSI)
#[no_mangle]
pub extern "win64" fn RegEnumKeyExA(
    hKey: usize,
    dwIndex: u32,
    lpName: *mut u8,
    lpcchName: *mut u32,
    _lpReserved: *const u32,
    __lpClass: *mut u8,
    __lpcchClass: *mut u32,
    __lpftLastWriteTime: *mut u64,
) -> i32 {
    tracing::debug!("RegEnumKeyExA called: index={}", dwIndex);

    if lpName.is_null() || lpcchName.is_null() {
        return ERROR_FILE_NOT_FOUND;
    }

    let path = match hkey_to_path(hKey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let store = get_registry_store();
    match store.enum_subkeys(&path) {
        Ok(subkeys) => {
            if (dwIndex as usize) >= subkeys.len() {
                return ERROR_NO_MORE_ITEMS;
            }

            let subkey = &subkeys[dwIndex as usize];
            let subkey_bytes = subkey.as_bytes();

            unsafe {
                let max_len = *lpcchName as usize;

                if max_len <= subkey_bytes.len() {
                    *lpcchName = (subkey_bytes.len() + 1) as u32;
                    return ERROR_MORE_DATA;
                }

                ptr::copy_nonoverlapping(subkey_bytes.as_ptr(), lpName, subkey_bytes.len());
                *lpName.add(subkey_bytes.len()) = 0;
                *lpcchName = subkey_bytes.len() as u32;
            }

            ERROR_SUCCESS
        }
        _ => ERROR_FILE_NOT_FOUND,
    }
}

/// RegEnumKeyExW - Enumerate registry subkeys (Unicode)
#[no_mangle]
pub extern "win64" fn RegEnumKeyExW(
    hKey: usize,
    dwIndex: u32,
    lpName: *mut u16,
    lpcchName: *mut u32,
    _lpReserved: *const u32,
    _lpClass: *mut u16,
    _lpcchClass: *mut u32,
    _lpftLastWriteTime: *mut u64,
) -> i32 {
    tracing::debug!("RegEnumKeyExW called: index={}", dwIndex);

    if lpName.is_null() || lpcchName.is_null() {
        return ERROR_FILE_NOT_FOUND;
    }

    let path = match hkey_to_path(hKey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let store = get_registry_store();
    match store.enum_subkeys(&path) {
        Ok(subkeys) => {
            if (dwIndex as usize) >= subkeys.len() {
                return ERROR_NO_MORE_ITEMS;
            }

            let subkey = &subkeys[dwIndex as usize];
            let subkey_wide = crate::utils::wide_string::str_to_wide(subkey);

            unsafe {
                let max_len = *lpcchName as usize;

                if max_len <= subkey_wide.len() {
                    *lpcchName = (subkey_wide.len() + 1) as u32;
                    return ERROR_MORE_DATA;
                }

                ptr::copy_nonoverlapping(subkey_wide.as_ptr(), lpName, subkey_wide.len());
                *lpName.add(subkey_wide.len()) = 0;
                *lpcchName = subkey_wide.len() as u32;
            }

            ERROR_SUCCESS
        }
        _ => ERROR_FILE_NOT_FOUND,
    }
}
