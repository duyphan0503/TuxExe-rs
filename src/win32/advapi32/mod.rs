//! advapi32.dll reimplementation — registry, security, crypto.

pub mod registry;

use std::collections::HashMap;
use tracing::trace;

// Crypto API types
pub type HCRYPTPROV = usize;
pub type HCRYPTHASH = usize;
pub type HCRYPTKEY = usize;

// Error codes
const ERROR_SUCCESS: u32 = 0;
const NTE_BAD_UID: u32 = 0x80090003;
const NTE_BAD_FLAGS: u32 = 0x80090009;

// ---------------------------------------------------------------------------
// Registry stubs not in registry.rs
// ---------------------------------------------------------------------------

extern "win64" fn RegCreateKeyW(
    hKey: usize,
    lpSubKey: *const u16,
    phkResult: *mut usize,
) -> i32 {
    trace!("RegCreateKeyW — stub");
    if phkResult.is_null() {
        return 2; // ERROR_FILE_NOT_FOUND
    }
    unsafe { *phkResult = 0x80000001; } // HKEY_CURRENT_USER stub
    0
}

extern "win64" fn RegDeleteValueA(hKey: usize, lpValueName: *const u8) -> i32 {
    trace!("RegDeleteValueA — stub");
    0 // ERROR_SUCCESS
}

// ---------------------------------------------------------------------------
// Cryptography API stubs
// ---------------------------------------------------------------------------

extern "win64" fn CryptAcquireContextW(
    phProv: *mut HCRYPTPROV,
    pszContainer: *const u16,
    pszProvider: *const u16,
    dwProvType: u32,
    dwFlags: u32,
) -> i32 {
    trace!("CryptAcquireContextW(prov_type={}, flags={:#x}) — stub", dwProvType, dwFlags);
    if phProv.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); } // ERROR_INVALID_PARAMETER
        return 0;
    }
    unsafe { *phProv = 0xDEAD_BEEF; }
    1 // TRUE
}

extern "win64" fn CryptReleaseContext(hProv: HCRYPTPROV, _dwFlags: u32) -> i32 {
    trace!("CryptReleaseContext({:#x}) — stub", hProv);
    1 // TRUE
}

extern "win64" fn CryptCreateHash(
    hProv: HCRYPTPROV,
    Algid: u32,
    hKey: HCRYPTKEY,
    _dwFlags: u32,
    phHash: *mut HCRYPTHASH,
) -> i32 {
    trace!("CryptCreateHash(algid={:#x}) — stub", Algid);
    if phHash.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    unsafe { *phHash = 0xCAFE_0001; }
    1
}

extern "win64" fn CryptHashData(
    hHash: HCRYPTHASH,
    pbData: *const u8,
    dwDataLen: u32,
    _dwFlags: u32,
) -> i32 {
    trace!("CryptHashData(hash={:#x}, len={}) — stub", hHash, dwDataLen);
    if pbData.is_null() && dwDataLen != 0 {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    1
}

extern "win64" fn CryptGetHashParam(
    hHash: HCRYPTHASH,
    dwParam: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    _dwFlags: u32,
) -> i32 {
    trace!("CryptGetHashParam(hash={:#x}, param={:#x}) — stub", hHash, dwParam);
    if pdwDataLen.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    // HP_HASHSIZE = 4, HP_HASHVAL = 2
    if dwParam == 4 {
        unsafe { *pdwDataLen = 32; } // SHA-256 size
        if !pbData.is_null() {
            unsafe { std::ptr::write_bytes(pbData, 0, 32); }
        }
    }
    1
}

extern "win64" fn CryptDestroyHash(hHash: HCRYPTHASH) -> i32 {
    trace!("CryptDestroyHash({:#x}) — stub", hHash);
    1
}

extern "win64" fn CryptEnumProvidersW(
    dwIndex: u32,
    pdwReserved: *mut u32,
    _dwFlags: u32,
    pdwProvType: *mut u32,
    pszProvName: *mut u16,
    pcbProvName: *mut u32,
) -> i32 {
    trace!("CryptEnumProvidersW(index={}) — stub", dwIndex);
    // Return no more providers after index 0
    if dwIndex > 0 {
        unsafe { crate::win32::kernel32::error::set_last_error(259); } // ERROR_NO_MORE_ITEMS
        return 0;
    }
    if pdwProvType.is_null() || pcbProvName.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    let name = "Microsoft Enhanced RSA and AES Cryptographic Provider\0";
    let wide: Vec<u16> = name.encode_utf16().collect();
    unsafe {
        *pdwProvType = 24; // PROV_RSA_AES
        *pcbProvName = wide.len() as u32;
        if !pszProvName.is_null() && *pcbProvName >= wide.len() as u32 {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), pszProvName, wide.len());
        }
    }
    1
}

extern "win64" fn CryptSignHashW(
    hHash: HCRYPTHASH,
    dwKeySpec: u32,
    sDescription: *const u16,
    _dwFlags: u32,
    pbSignature: *mut u8,
    pdwSigLen: *mut u32,
) -> i32 {
    trace!("CryptSignHashW — stub");
    if pdwSigLen.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    unsafe { *pdwSigLen = 256; } // RSA-2048 signature size
    1
}

extern "win64" fn CryptDestroyKey(hKey: HCRYPTKEY) -> i32 {
    trace!("CryptDestroyKey({:#x}) — stub", hKey);
    1
}

extern "win64" fn CryptSetHashParam(
    hHash: HCRYPTHASH,
    dwParam: u32,
    pbData: *const u8,
    _dwFlags: u32,
) -> i32 {
    trace!("CryptSetHashParam — stub");
    1
}

extern "win64" fn CryptGetProvParam(
    hProv: HCRYPTPROV,
    dwParam: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    _dwFlags: u32,
) -> i32 {
    trace!("CryptGetProvParam — stub");
    if pdwDataLen.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    unsafe { *pdwDataLen = 0; }
    1
}

extern "win64" fn CryptGetUserKey(
    hProv: HCRYPTPROV,
    dwKeySpec: u32,
    phUserKey: *mut HCRYPTKEY,
) -> i32 {
    trace!("CryptGetUserKey — stub");
    if phUserKey.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    unsafe { *phUserKey = 0xBEEF_0001; }
    1
}

extern "win64" fn CryptExportKey(
    hKey: HCRYPTKEY,
    hExpKey: HCRYPTKEY,
    dwBlobType: u32,
    _dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> i32 {
    trace!("CryptExportKey — stub");
    if pdwDataLen.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    unsafe { *pdwDataLen = 0; }
    1
}

extern "win64" fn CryptDecrypt(
    hKey: HCRYPTKEY,
    hHash: HCRYPTHASH,
    _Final: i32,
    _dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> i32 {
    trace!("CryptDecrypt — stub");
    1
}

// ---------------------------------------------------------------------------
// Security / Token API stubs
// ---------------------------------------------------------------------------

extern "win64" fn OpenProcessToken(
    ProcessHandle: usize,
    DesiredAccess: u32,
    TokenHandle: *mut usize,
) -> i32 {
    trace!("OpenProcessToken — stub");
    if TokenHandle.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    unsafe { *TokenHandle = 0xF00D_0001; }
    1
}

extern "win64" fn GetSidSubAuthority(pSid: *mut u8, nSubAuthority: u32) -> *mut u32 {
    trace!("GetSidSubAuthority — stub");
    if pSid.is_null() {
        return std::ptr::null_mut();
    }
    // SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities
    // SubAuthorities start at offset 8
    unsafe { pSid.offset(8 + 4).cast::<u32>().offset(nSubAuthority as isize) }
}

extern "win64" fn GetTokenInformation(
    TokenHandle: usize,
    TokenInformationClass: u32,
    TokenInformation: *mut u8,
    TokenInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32 {
    trace!("GetTokenInformation(class={}) — stub", TokenInformationClass);
    if ReturnLength.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    // TokenUser = 1
    if TokenInformationClass == 1 {
        // Return a minimal TOKEN_USER with a fake SID
        const TOKEN_USER_SIZE: u32 = 24;
        unsafe { *ReturnLength = TOKEN_USER_SIZE; }
        if TokenInformation.is_null() || TokenInformationLength < TOKEN_USER_SIZE {
            unsafe { crate::win32::kernel32::error::set_last_error(122); } // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }
        unsafe { std::ptr::write_bytes(TokenInformation, 0, TOKEN_USER_SIZE as usize); }
    }
    1
}

extern "win64" fn GetUserNameA(lpBuffer: *mut u8, pcbBuffer: *mut u32) -> i32 {
    trace!("GetUserNameA — stub");
    if lpBuffer.is_null() || pcbBuffer.is_null() {
        unsafe { crate::win32::kernel32::error::set_last_error(87); }
        return 0;
    }
    let name = b"user\0";
    unsafe {
        let available = *pcbBuffer as usize;
        if available < name.len() {
            *pcbBuffer = name.len() as u32;
            crate::win32::kernel32::error::set_last_error(234); // ERROR_MORE_DATA
            return 0;
        }
        std::ptr::copy_nonoverlapping(name.as_ptr(), lpBuffer, name.len());
        *pcbBuffer = (name.len() - 1) as u32;
    }
    1
}

// ---------------------------------------------------------------------------
// Event Log stubs
// ---------------------------------------------------------------------------

extern "win64" fn RegisterEventSourceW(
    lpUNCServerName: *const u16,
    lpSourceName: *const u16,
) -> usize {
    trace!("RegisterEventSourceW — stub");
    0x1000_0001 // fake handle
}

extern "win64" fn DeregisterEventSource(hEventLog: usize) -> i32 {
    trace!("DeregisterEventSource — stub");
    1
}

extern "win64" fn ReportEventW(
    hEventLog: usize,
    wType: u16,
    wCategory: u16,
    dwEventID: u32,
    lpUserSid: *mut u8,
    wNumStrings: u16,
    dwDataSize: u32,
    lpStrings: *const *const u16,
    lpRawData: *const u8,
) -> i32 {
    trace!("ReportEventW(type={}, id={}) — stub", wType, dwEventID);
    1
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    // Registry APIs
    exports.insert("RegOpenKeyExA", registry::RegOpenKeyExA as usize);
    exports.insert("RegOpenKeyExW", registry::RegOpenKeyExW as usize);
    exports.insert("RegCloseKey", registry::RegCloseKey as usize);
    exports.insert("RegQueryValueExA", registry::RegQueryValueExA as usize);
    exports.insert("RegQueryValueExW", registry::RegQueryValueExW as usize);
    exports.insert("RegSetValueExA", registry::RegSetValueExA as usize);
    exports.insert("RegSetValueExW", registry::RegSetValueExW as usize);
    exports.insert("RegCreateKeyExA", registry::RegCreateKeyExA as usize);
    exports.insert("RegCreateKeyExW", registry::RegCreateKeyExW as usize);
    exports.insert("RegDeleteKeyA", registry::RegDeleteKeyA as usize);
    exports.insert("RegDeleteKeyW", registry::RegDeleteKeyW as usize);
    exports.insert("RegEnumKeyExA", registry::RegEnumKeyExA as usize);
    exports.insert("RegEnumKeyExW", registry::RegEnumKeyExW as usize);

    // Additional registry
    exports.insert("RegCreateKeyW", RegCreateKeyW as usize);
    exports.insert("RegDeleteValueA", RegDeleteValueA as usize);

    // Cryptography
    exports.insert("CryptAcquireContextW", CryptAcquireContextW as usize);
    exports.insert("CryptReleaseContext", CryptReleaseContext as usize);
    exports.insert("CryptCreateHash", CryptCreateHash as usize);
    exports.insert("CryptHashData", CryptHashData as usize);
    exports.insert("CryptGetHashParam", CryptGetHashParam as usize);
    exports.insert("CryptDestroyHash", CryptDestroyHash as usize);
    exports.insert("CryptEnumProvidersW", CryptEnumProvidersW as usize);
    exports.insert("CryptSignHashW", CryptSignHashW as usize);
    exports.insert("CryptDestroyKey", CryptDestroyKey as usize);
    exports.insert("CryptSetHashParam", CryptSetHashParam as usize);
    exports.insert("CryptGetProvParam", CryptGetProvParam as usize);
    exports.insert("CryptGetUserKey", CryptGetUserKey as usize);
    exports.insert("CryptExportKey", CryptExportKey as usize);
    exports.insert("CryptDecrypt", CryptDecrypt as usize);

    // Security / Token
    exports.insert("OpenProcessToken", OpenProcessToken as usize);
    exports.insert("GetSidSubAuthority", GetSidSubAuthority as usize);
    exports.insert("GetTokenInformation", GetTokenInformation as usize);
    exports.insert("GetUserNameA", GetUserNameA as usize);

    // Event Log
    exports.insert("RegisterEventSourceW", RegisterEventSourceW as usize);
    exports.insert("DeregisterEventSource", DeregisterEventSource as usize);
    exports.insert("ReportEventW", ReportEventW as usize);

    exports
}
