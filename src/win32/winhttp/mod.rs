#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! winhttp.dll stubs.

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn WinHttpCheckPlatform() -> i32 {
    trace!("WinHttpCheckPlatform — stub");
    1 // TRUE — platform is supported
}

extern "win64" fn WinHttpOpen(
    _pwszUserAgent: *const u16,
    _dwAccessType: u32,
    _pwszProxyName: *const u16,
    _pwszProxyBypass: *const u16,
    _dwFlags: u32,
) -> usize {
    trace!("WinHttpOpen — stub");
    0
}

extern "win64" fn WinHttpCloseHandle(_hInternet: usize) -> i32 {
    trace!("WinHttpCloseHandle — stub");
    0
}

#[repr(C)]
pub struct WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
    pub fAutoDetect: i32,
    pub lpszAutoConfigUrl: *mut u16,
    pub lpszProxy: *mut u16,
    pub lpszProxyBypass: *mut u16,
}

extern "win64" fn WinHttpGetIEProxyConfigForCurrentUser(
    pProxyConfig: *mut WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
) -> i32 {
    trace!("WinHttpGetIEProxyConfigForCurrentUser — stub");
    if pProxyConfig.is_null() {
        return 0; // FALSE
    }
    unsafe {
        (*pProxyConfig).fAutoDetect = 0;
        (*pProxyConfig).lpszAutoConfigUrl = std::ptr::null_mut();
        (*pProxyConfig).lpszProxy = std::ptr::null_mut();
        (*pProxyConfig).lpszProxyBypass = std::ptr::null_mut();
    }
    1 // TRUE
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("WinHttpCheckPlatform", WinHttpCheckPlatform as usize);
    exports.insert("WinHttpOpen", WinHttpOpen as usize);
    exports.insert("WinHttpCloseHandle", WinHttpCloseHandle as usize);
    exports.insert("WinHttpGetIEProxyConfigForCurrentUser", WinHttpGetIEProxyConfigForCurrentUser as usize);
    exports
}
