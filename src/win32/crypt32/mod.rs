#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MORE_DATA: u32 = 234;
const CRYPT_E_NOT_FOUND: u32 = 0x8009_2004;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CertChainPolicyPara {
    pub cbSize: u32,
    pub dwFlags: u32,
    pub pvExtraPolicyPara: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CertChainPolicyStatus {
    pub cbSize: u32,
    pub dwError: u32,
    pub lChainIndex: i32,
    pub lElementIndex: i32,
    pub pvExtraPolicyStatus: *mut c_void,
}

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

fn next_store_handle() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0xC320_0000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn next_chain_context() -> *const c_void {
    static NEXT: AtomicUsize = AtomicUsize::new(0xC340_0000);
    let value = NEXT.fetch_add(0x10, Ordering::Relaxed);
    value as *const c_void
}

pub extern "win64" fn CertOpenStore(
    _lpszStoreProvider: *const i8,
    _dwMsgAndCertEncodingType: u32,
    _hCryptProv: usize,
    _dwFlags: u32,
    _pvPara: *const c_void,
) -> usize {
    let handle = next_store_handle();
    set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn CertCloseStore(hCertStore: usize, _dwFlags: u32) -> i32 {
    if hCertStore == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CertOpenSystemStoreA(
    _hProv: usize,
    _szSubsystemProtocol: *const i8,
) -> usize {
    CertOpenStore(std::ptr::null(), 0, 0, 0, std::ptr::null())
}

pub extern "win64" fn CertOpenSystemStoreW(
    _hProv: usize,
    _szSubsystemProtocol: *const u16,
) -> usize {
    CertOpenStore(std::ptr::null(), 0, 0, 0, std::ptr::null())
}

pub extern "win64" fn CertEnumCertificatesInStore(
    hCertStore: usize,
    _pPrevCertContext: *const c_void,
) -> *const c_void {
    if hCertStore == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null();
    }

    set_last_error(CRYPT_E_NOT_FOUND);
    std::ptr::null()
}

pub extern "win64" fn CertFindCertificateInStore(
    hCertStore: usize,
    _dwCertEncodingType: u32,
    _dwFindFlags: u32,
    _dwFindType: u32,
    _pvFindPara: *const c_void,
    _pPrevCertContext: *const c_void,
) -> *const c_void {
    if hCertStore == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null();
    }

    set_last_error(CRYPT_E_NOT_FOUND);
    std::ptr::null()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertGetCertificateChain(
    _hChainEngine: usize,
    _pCertContext: *const c_void,
    _pTime: *const c_void,
    _hAdditionalStore: usize,
    _pChainPara: *const c_void,
    _dwFlags: u32,
    _pvReserved: *mut c_void,
    ppChainContext: *mut *const c_void,
) -> i32 {
    if ppChainContext.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        *ppChainContext = next_chain_context();
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CertFreeCertificateChain(_pChainContext: *const c_void) {
    set_last_error(ERROR_SUCCESS);
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertAddEncodedCertificateToStore(
    hCertStore: usize,
    _dwCertEncodingType: u32,
    pbCertEncoded: *const u8,
    cbCertEncoded: u32,
    _dwAddDisposition: u32,
    ppCertContext: *mut *const c_void,
) -> i32 {
    if hCertStore == 0 || (cbCertEncoded > 0 && pbCertEncoded.is_null()) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if !ppCertContext.is_null() {
        unsafe {
            *ppCertContext = std::ptr::null();
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertGetCertificateContextProperty(
    pCertContext: *const c_void,
    _dwPropId: u32,
    pvData: *mut c_void,
    pcbData: *mut u32,
) -> i32 {
    if pCertContext.is_null() || pcbData.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        if pvData.is_null() {
            *pcbData = 0;
        } else if *pcbData > 0 {
            std::ptr::write_bytes(pvData.cast::<u8>(), 0, *pcbData as usize);
            *pcbData = 0;
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CertFreeCertificateContext(_pCertContext: *const c_void) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CertDuplicateCertificateContext(
    pCertContext: *const c_void,
) -> *const c_void {
    set_last_error(ERROR_SUCCESS);
    pCertContext
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertGetNameStringW(
    _pCertContext: *const c_void,
    _dwType: u32,
    _dwFlags: u32,
    _pvTypePara: *const c_void,
    pszNameString: *mut u16,
    cchNameString: u32,
) -> u32 {
    if cchNameString == 0 {
        set_last_error(ERROR_SUCCESS);
        return 1;
    }

    if pszNameString.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        *pszNameString = 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertGetIntendedKeyUsage(
    _dwCertEncodingType: u32,
    _pCertInfo: *const c_void,
    pbKeyUsage: *mut u8,
    cbKeyUsage: u32,
) -> i32 {
    if cbKeyUsage > 0 && pbKeyUsage.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if cbKeyUsage > 0 {
        unsafe {
            std::ptr::write_bytes(pbKeyUsage, 0xFF, cbKeyUsage as usize);
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertStrToNameW(
    _dwCertEncodingType: u32,
    _pszX500: *const u16,
    _dwStrType: u32,
    _pvReserved: *mut c_void,
    pbEncoded: *mut u8,
    pcbEncoded: *mut u32,
    ppszError: *mut *const u16,
) -> i32 {
    if pcbEncoded.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let required = 1u32;
    if pbEncoded.is_null() {
        unsafe {
            *pcbEncoded = required;
            if !ppszError.is_null() {
                *ppszError = std::ptr::null();
            }
        }
        set_last_error(ERROR_SUCCESS);
        return 1;
    }

    unsafe {
        if *pcbEncoded < required {
            *pcbEncoded = required;
            if !ppszError.is_null() {
                *ppszError = std::ptr::null();
            }
            set_last_error(ERROR_MORE_DATA);
            return 0;
        }

        *pbEncoded = 0;
        *pcbEncoded = required;
        if !ppszError.is_null() {
            *ppszError = std::ptr::null();
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CertVerifyCertificateChainPolicy(
    _pszPolicyOID: *const i8,
    _pChainContext: *const c_void,
    _pPolicyPara: *const CertChainPolicyPara,
    pPolicyStatus: *mut CertChainPolicyStatus,
) -> i32 {
    if pPolicyStatus.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        (*pPolicyStatus).dwError = 0;
        (*pPolicyStatus).lChainIndex = -1;
        (*pPolicyStatus).lElementIndex = -1;
        (*pPolicyStatus).pvExtraPolicyStatus = std::ptr::null_mut();
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("CertOpenStore", CertOpenStore as usize);
    exports.insert("CertCloseStore", CertCloseStore as usize);
    exports.insert("CertOpenSystemStoreA", CertOpenSystemStoreA as usize);
    exports.insert("CertOpenSystemStoreW", CertOpenSystemStoreW as usize);
    exports.insert("CertEnumCertificatesInStore", CertEnumCertificatesInStore as usize);
    exports.insert("CertFindCertificateInStore", CertFindCertificateInStore as usize);
    exports.insert("CertGetCertificateChain", CertGetCertificateChain as usize);
    exports.insert("CertFreeCertificateChain", CertFreeCertificateChain as usize);
    exports.insert("CertAddEncodedCertificateToStore", CertAddEncodedCertificateToStore as usize);
    exports.insert("CertGetCertificateContextProperty", CertGetCertificateContextProperty as usize);
    exports.insert("CertFreeCertificateContext", CertFreeCertificateContext as usize);
    exports.insert("CertDuplicateCertificateContext", CertDuplicateCertificateContext as usize);
    exports.insert("CertGetNameStringW", CertGetNameStringW as usize);
    exports.insert("CertGetIntendedKeyUsage", CertGetIntendedKeyUsage as usize);
    exports.insert("CertStrToNameW", CertStrToNameW as usize);
    exports.insert("CertVerifyCertificateChainPolicy", CertVerifyCertificateChainPolicy as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_open_store_returns_nonzero_handle() {
        let handle = CertOpenStore(std::ptr::null(), 0, 0, 0, std::ptr::null());
        assert_ne!(handle, 0);
        assert_eq!(CertCloseStore(handle, 0), 1);
    }

    #[test]
    fn cert_get_certificate_chain_returns_synthetic_context() {
        let mut chain = std::ptr::null();
        assert_eq!(
            CertGetCertificateChain(
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &mut chain,
            ),
            1
        );
        assert!(!chain.is_null());
        CertFreeCertificateChain(chain);
    }

    #[test]
    fn cert_get_name_string_w_reports_required_size() {
        assert_eq!(
            CertGetNameStringW(std::ptr::null(), 0, 0, std::ptr::null(), std::ptr::null_mut(), 0),
            1
        );
    }

    #[test]
    fn cert_str_to_name_w_supports_probe_then_fill() {
        let mut required = 0u32;
        assert_eq!(
            CertStrToNameW(
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut required,
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(required, 1);

        let mut encoded = [0xAAu8; 1];
        assert_eq!(
            CertStrToNameW(
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                encoded.as_mut_ptr(),
                &mut required,
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(encoded[0], 0);
    }
}
