//! advapi32.dll reimplementation — registry, security, crypto.

pub mod registry;

use std::{collections::HashMap, ffi::c_void, ptr};
use tracing::trace;

// Crypto API types
pub type HCRYPTPROV = usize;
pub type HCRYPTHASH = usize;
pub type HCRYPTKEY = usize;

// Error codes
const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_INVALID_SID: u32 = 1337;
const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_NO_TOKEN: u32 = 1008;
const NTE_BAD_UID: u32 = 0x80090003;
const NTE_BAD_FLAGS: u32 = 0x80090009;

// ---------------------------------------------------------------------------
// Registry stubs not in registry.rs
// ---------------------------------------------------------------------------

extern "win64" fn RegCreateKeyW(hKey: usize, lpSubKey: *const u16, phkResult: *mut usize) -> i32 {
    trace!("RegCreateKeyW — stub");
    if phkResult.is_null() {
        return 2; // ERROR_FILE_NOT_FOUND
    }
    unsafe {
        *phkResult = 0x80000001;
    } // HKEY_CURRENT_USER stub
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        } // ERROR_INVALID_PARAMETER
        return 0;
    }
    unsafe {
        *phProv = 0xDEAD_BEEF;
    }
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    unsafe {
        *phHash = 0xCAFE_0001;
    }
    1
}

extern "win64" fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8 {
    if random_buffer.is_null() || random_buffer_length == 0 {
        return 1;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(random_buffer, random_buffer_length as usize) };
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(slice);
    } else {
        let mut seed = 0x12345678u64;
        for byte in slice.iter_mut() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (seed >> 32) as u8;
        }
    }
    1
}

extern "win64" fn RtlGenRandom(random_buffer: *mut u8, random_buffer_length: u32) -> u8 {
    SystemFunction036(random_buffer, random_buffer_length)
}

extern "win64" fn CryptHashData(
    hHash: HCRYPTHASH,
    pbData: *const u8,
    dwDataLen: u32,
    _dwFlags: u32,
) -> i32 {
    trace!("CryptHashData(hash={:#x}, len={}) — stub", hHash, dwDataLen);
    if pbData.is_null() && dwDataLen != 0 {
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    // HP_HASHSIZE = 4, HP_HASHVAL = 2
    if dwParam == 4 {
        unsafe {
            *pdwDataLen = 32;
        } // SHA-256 size
        if !pbData.is_null() {
            unsafe {
                std::ptr::write_bytes(pbData, 0, 32);
            }
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(259);
        } // ERROR_NO_MORE_ITEMS
        return 0;
    }
    if pdwProvType.is_null() || pcbProvName.is_null() {
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    unsafe {
        *pdwSigLen = 256;
    } // RSA-2048 signature size
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    unsafe {
        *pdwDataLen = 0;
    }
    1
}

extern "win64" fn CryptGetUserKey(
    hProv: HCRYPTPROV,
    dwKeySpec: u32,
    phUserKey: *mut HCRYPTKEY,
) -> i32 {
    trace!("CryptGetUserKey — stub");
    if phUserKey.is_null() {
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    unsafe {
        *phUserKey = 0xBEEF_0001;
    }
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
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    unsafe {
        *pdwDataLen = 0;
    }
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

fn sid_length(sid: *const u8) -> Option<usize> {
    if sid.is_null() {
        return None;
    }
    let count = unsafe { *sid.add(1) as usize };
    8usize.checked_add(count.checked_mul(4)?)
}

extern "win64" fn AllocateAndInitializeSid(
    identifier_authority: *const u8,
    sub_authority_count: u8,
    sub_authority0: u32,
    sub_authority1: u32,
    sub_authority2: u32,
    sub_authority3: u32,
    sub_authority4: u32,
    sub_authority5: u32,
    sub_authority6: u32,
    sub_authority7: u32,
    sid_out: *mut *mut u8,
) -> i32 {
    if identifier_authority.is_null() || sid_out.is_null() || sub_authority_count > 8 {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(length) = 8usize.checked_add(sub_authority_count as usize * 4) else {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let sid = unsafe { libc::calloc(1, length).cast::<u8>() };
    if sid.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let authorities = [
        sub_authority0,
        sub_authority1,
        sub_authority2,
        sub_authority3,
        sub_authority4,
        sub_authority5,
        sub_authority6,
        sub_authority7,
    ];
    unsafe {
        sid.write(1);
        sid.add(1).write(sub_authority_count);
        ptr::copy_nonoverlapping(identifier_authority, sid.add(2), 6);
        for (index, authority) in authorities.iter().take(sub_authority_count as usize).enumerate()
        {
            sid.add(8).cast::<u32>().add(index).write(*authority);
        }
        *sid_out = sid;
    }
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

extern "win64" fn AllocateLocallyUniqueId(luid: *mut u64) -> i32 {
    trace!("AllocateLocallyUniqueId — generating LUID");
    if luid.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    static NEXT_LUID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);
    let val = NEXT_LUID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    unsafe {
        *luid = val;
    }
    1
}

extern "win64" fn FreeSid(sid: *mut u8) -> *mut u8 {
    if !sid.is_null() {
        unsafe { libc::free(sid.cast()) };
    }
    ptr::null_mut()
}

extern "win64" fn GetLengthSid(sid: *const u8) -> u32 {
    match sid_length(sid) {
        Some(length) => length as u32,
        None => {
            crate::win32::kernel32::error::set_last_error(ERROR_INVALID_SID);
            0
        }
    }
}

extern "win64" fn CopySid(destination_length: u32, destination: *mut u8, source: *const u8) -> i32 {
    let Some(length) = sid_length(source) else {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    if destination.is_null() || (destination_length as usize) < length {
        crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { ptr::copy_nonoverlapping(source, destination, length) };
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

extern "win64" fn BuildTrusteeWithSidW(trustee: *mut u8, sid: *mut u8) {
    if trustee.is_null() {
        return;
    }
    // TRUSTEE_W: MULTIPLE_TRUSTEE*, operation, form, type, SID pointer.
    unsafe {
        ptr::write_bytes(trustee, 0, 32);
        trustee.add(8).cast::<u32>().write(0); // NO_MULTIPLE_TRUSTEE
        trustee.add(12).cast::<u32>().write(0); // TRUSTEE_IS_SID
        trustee.add(16).cast::<u32>().write(0); // TRUSTEE_IS_UNKNOWN
        trustee.add(24).cast::<*mut u8>().write(sid);
    }
}

extern "win64" fn GetEffectiveRightsFromAclW(
    _acl: *const c_void,
    _trustee: *const c_void,
    access_rights: *mut u32,
) -> u32 {
    if !access_rights.is_null() {
        unsafe { *access_rights = 0 };
    }
    ERROR_CALL_NOT_IMPLEMENTED
}

extern "win64" fn SetEntriesInAclW(
    _entry_count: u32,
    _entries: *const c_void,
    _old_acl: *const c_void,
    new_acl: *mut *mut c_void,
) -> u32 {
    if !new_acl.is_null() {
        unsafe { *new_acl = ptr::null_mut() };
    }
    ERROR_CALL_NOT_IMPLEMENTED
}

extern "win64" fn SetNamedSecurityInfoW(
    _object_name: *mut u16,
    _object_type: u32,
    _security_info: u32,
    _owner: *mut c_void,
    _group: *mut c_void,
    _dacl: *mut c_void,
    _sacl: *mut c_void,
) -> u32 {
    ERROR_CALL_NOT_IMPLEMENTED
}

extern "win64" fn GetNamedSecurityInfoW(
    _object_name: *mut u16,
    _object_type: u32,
    _security_info: u32,
    owner: *mut *mut c_void,
    group: *mut *mut c_void,
    dacl: *mut *mut c_void,
    sacl: *mut *mut c_void,
    descriptor: *mut *mut c_void,
) -> u32 {
    for output in [owner, group, dacl, sacl, descriptor] {
        if !output.is_null() {
            unsafe { *output = ptr::null_mut() };
        }
    }
    ERROR_CALL_NOT_IMPLEMENTED
}

extern "win64" fn OpenThreadToken(
    _thread: usize,
    _access: u32,
    _open_as_self: i32,
    token_out: *mut usize,
) -> i32 {
    if !token_out.is_null() {
        unsafe { *token_out = 0 };
    }
    crate::win32::kernel32::error::set_last_error(ERROR_NO_TOKEN);
    0
}

extern "win64" fn DuplicateToken(existing_token: usize, _level: u32, token_out: *mut usize) -> i32 {
    if token_out.is_null() || existing_token == 0 {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    unsafe { *token_out = existing_token };
    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

extern "win64" fn LookupAccountSidW(
    _system_name: *const u16,
    _sid: *const u8,
    _name: *mut u16,
    name_length: *mut u32,
    _domain: *mut u16,
    domain_length: *mut u32,
    _use_type: *mut u32,
) -> i32 {
    if !name_length.is_null() {
        unsafe { *name_length = 0 };
    }
    if !domain_length.is_null() {
        unsafe { *domain_length = 0 };
    }
    crate::win32::kernel32::error::set_last_error(ERROR_NONE_MAPPED);
    0
}

extern "win64" fn EventRegister(
    _provider_id: *const u8,
    _callback: usize,
    _context: *const c_void,
    registration_handle: *mut u64,
) -> u32 {
    if registration_handle.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { *registration_handle = 1 };
    ERROR_SUCCESS
}

extern "win64" fn EventUnregister(_registration_handle: u64) -> u32 {
    ERROR_SUCCESS
}

extern "win64" fn EventWriteTransfer(
    _registration_handle: u64,
    _event_descriptor: *const c_void,
    _activity_id: *const u8,
    _related_activity_id: *const u8,
    _user_data_count: u32,
    _user_data: *const c_void,
) -> u32 {
    ERROR_SUCCESS
}

extern "win64" fn RevertToSelf() -> i32 {
    1
}

extern "win64" fn ImpersonateLoggedOnUser(token: usize) -> i32 {
    if token == 0 {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    1
}

/// A deliberately non-spawning compatibility result. Mono imports this API
/// for its Windows process backend, but the native-only runtime must never
/// delegate it to Wine or start a host process under supplied credentials.
extern "win64" fn CreateProcessWithLogonW(
    _username: *const u16,
    _domain: *const u16,
    _password: *const u16,
    _logon_flags: u32,
    _application_name: *const u16,
    _command_line: *mut u16,
    _creation_flags: u32,
    _environment: *const u8,
    _current_directory: *const u16,
    _startup_info: *const u8,
    process_information: *mut u8,
) -> i32 {
    trace!("CreateProcessWithLogonW — unsupported native-only operation");
    if !process_information.is_null() {
        // PROCESS_INFORMATION is two handles and two DWORDs on PE64.
        unsafe { std::ptr::write_bytes(process_information, 0, 24) };
    }
    crate::win32::kernel32::error::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    0
}

extern "win64" fn OpenProcessToken(
    ProcessHandle: usize,
    DesiredAccess: u32,
    TokenHandle: *mut usize,
) -> i32 {
    trace!("OpenProcessToken — stub");
    if TokenHandle.is_null() {
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
        return 0;
    }
    unsafe {
        *TokenHandle = 0xF00D_0001;
    }
    1
}

extern "win64" fn GetSidSubAuthority(pSid: *mut u8, nSubAuthority: u32) -> *mut u32 {
    trace!("GetSidSubAuthority(index={})", nSubAuthority);
    if pSid.is_null() || unsafe { nSubAuthority >= *pSid.add(1) as u32 } {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }
    // SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities
    // SubAuthorities start at offset 8
    unsafe { pSid.add(8).cast::<u32>().add(nSubAuthority as usize) }
}

extern "win64" fn GetTokenInformation(
    TokenHandle: usize,
    TokenInformationClass: u32,
    TokenInformation: *mut u8,
    TokenInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32 {
    trace!("GetTokenInformation(class={})", TokenInformationClass);
    if ReturnLength.is_null() {
        unsafe {
            crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        }
        return 0;
    }
    // TokenUser = 1
    if TokenInformationClass == 1 {
        // Return a minimal TOKEN_USER with a fake SID
        const TOKEN_USER_SIZE: u32 = 24;
        unsafe {
            *ReturnLength = TOKEN_USER_SIZE;
        }
        if TokenInformation.is_null() || TokenInformationLength < TOKEN_USER_SIZE {
            unsafe {
                crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
            } // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }
        unsafe {
            std::ptr::write_bytes(TokenInformation, 0, TOKEN_USER_SIZE as usize);
        }
        crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
        return 1;
    }

    // TokenIntegrityLevel (25): Unity queries the mandatory-label SID and
    // immediately calls GetSidSubAuthority on it. A success response with an
    // empty buffer made that API return NULL, which then crashed Unity during
    // startup. Model a normal medium-integrity process.
    if TokenInformationClass == 25 {
        const TOKEN_MANDATORY_LABEL_SIZE: u32 = 16;
        const SID_SIZE: u32 = 12;
        const REQUIRED_SIZE: u32 = TOKEN_MANDATORY_LABEL_SIZE + SID_SIZE;
        const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
        const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000;

        unsafe {
            *ReturnLength = REQUIRED_SIZE;
        }
        if TokenInformation.is_null() || TokenInformationLength < REQUIRED_SIZE {
            crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        unsafe {
            std::ptr::write_bytes(TokenInformation, 0, REQUIRED_SIZE as usize);
            let sid = TokenInformation.add(TOKEN_MANDATORY_LABEL_SIZE as usize);
            // TOKEN_MANDATORY_LABEL.Label.Sid and .Attributes.
            TokenInformation.cast::<*mut u8>().write(sid);
            TokenInformation.add(8).cast::<u32>().write(SE_GROUP_INTEGRITY);
            // SID { Revision=1, SubAuthorityCount=1,
            //       IdentifierAuthority=SECURITY_MANDATORY_LABEL_AUTHORITY,
            //       SubAuthority[0]=SECURITY_MANDATORY_MEDIUM_RID }.
            sid.write(1);
            sid.add(1).write(1);
            sid.add(7).write(16);
            sid.add(8).cast::<u32>().write(SECURITY_MANDATORY_MEDIUM_RID);
        }
        crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
        return 1;
    }

    crate::win32::kernel32::error::set_last_error(ERROR_SUCCESS);
    1
}

extern "win64" fn GetUserNameA(lpBuffer: *mut u8, pcbBuffer: *mut u32) -> i32 {
    trace!("GetUserNameA — stub");
    if lpBuffer.is_null() || pcbBuffer.is_null() {
        unsafe {
            crate::win32::kernel32::error::set_last_error(87);
        }
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
    exports.insert("RegOpenKeyA", registry::RegOpenKeyA as usize);
    exports.insert("RegOpenKeyW", registry::RegOpenKeyW as usize);
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
    exports.insert("RegNotifyChangeKeyValue", registry::RegNotifyChangeKeyValue as usize);
    exports.insert("RegDeleteTreeA", registry::RegDeleteTreeA as usize);
    exports.insert("RegDeleteTreeW", registry::RegDeleteTreeW as usize);
    exports.insert("RegDeleteValueA", RegDeleteValueA as usize);
    exports.insert("RegDeleteValueW", registry::RegDeleteValueW as usize);
    exports.insert("RegEnumValueA", registry::RegEnumValueA as usize);
    exports.insert("RegEnumValueW", registry::RegEnumValueW as usize);
    exports.insert("RegQueryInfoKeyA", registry::RegQueryInfoKeyA as usize);
    exports.insert("RegQueryInfoKeyW", registry::RegQueryInfoKeyW as usize);

    // Additional registry
    exports.insert("RegCreateKeyW", RegCreateKeyW as usize);

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
    exports.insert("SystemFunction036", SystemFunction036 as usize);
    exports.insert("RtlGenRandom", RtlGenRandom as usize);

    // Security / Token
    exports.insert("AllocateAndInitializeSid", AllocateAndInitializeSid as usize);
    exports.insert("AllocateLocallyUniqueId", AllocateLocallyUniqueId as usize);
    exports.insert("BuildTrusteeWithSidW", BuildTrusteeWithSidW as usize);
    exports.insert("CopySid", CopySid as usize);
    exports.insert("CreateProcessWithLogonW", CreateProcessWithLogonW as usize);
    exports.insert("DuplicateToken", DuplicateToken as usize);
    exports.insert("EventRegister", EventRegister as usize);
    exports.insert("EventUnregister", EventUnregister as usize);
    exports.insert("EventWriteTransfer", EventWriteTransfer as usize);
    exports.insert("FreeSid", FreeSid as usize);
    exports.insert("GetEffectiveRightsFromAclW", GetEffectiveRightsFromAclW as usize);
    exports.insert("GetLengthSid", GetLengthSid as usize);
    exports.insert("GetNamedSecurityInfoW", GetNamedSecurityInfoW as usize);
    exports.insert("OpenProcessToken", OpenProcessToken as usize);
    exports.insert("OpenThreadToken", OpenThreadToken as usize);
    exports.insert("LookupAccountSidW", LookupAccountSidW as usize);
    exports.insert("SetEntriesInAclW", SetEntriesInAclW as usize);
    exports.insert("SetNamedSecurityInfoW", SetNamedSecurityInfoW as usize);
    exports.insert("GetSidSubAuthority", GetSidSubAuthority as usize);
    exports.insert("GetTokenInformation", GetTokenInformation as usize);
    exports.insert("GetUserNameA", GetUserNameA as usize);
    exports.insert("RevertToSelf", RevertToSelf as usize);
    exports.insert("ImpersonateLoggedOnUser", ImpersonateLoggedOnUser as usize);

    // Event Log
    exports.insert("RegisterEventSourceW", RegisterEventSourceW as usize);
    exports.insert("DeregisterEventSource", DeregisterEventSource as usize);
    exports.insert("ReportEventW", ReportEventW as usize);

    exports
}
