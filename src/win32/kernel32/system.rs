//! System information APIs - GetSystemInfo, GetVersionEx, etc.

use std::mem;

// Windows constants
const VER_PLATFORM_WIN32_NT: u32 = 2;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;

#[repr(C)]
#[allow(non_snake_case)]
pub struct SYSTEM_INFO {
    pub wProcessorArchitecture: u16,
    pub wReserved: u16,
    pub dwPageSize: u32,
    pub lpMinimumApplicationAddress: usize,
    pub lpMaximumApplicationAddress: usize,
    pub dwActiveProcessorMask: usize,
    pub dwNumberOfProcessors: u32,
    pub dwProcessorType: u32,
    pub dwAllocationGranularity: u32,
    pub wProcessorLevel: u16,
    pub wProcessorRevision: u16,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct OSVERSIONINFOA {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u8; 128],
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct OSVERSIONINFOW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u16; 128],
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct OSVERSIONINFOEXA {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u8; 128],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct OSVERSIONINFOEXW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u16; 128],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}

/// GetSystemInfo - Returns system information
#[no_mangle]
pub extern "win64" fn GetSystemInfo(lpSystemInfo: *mut SYSTEM_INFO) {
    tracing::debug!("GetSystemInfo called");

    if lpSystemInfo.is_null() {
        return;
    }

    unsafe {
        // Get number of processors from system
        let num_cpus = num_cpus_from_system();

        // Get page size
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as u32;

        // Determine architecture
        let arch = if cfg!(target_arch = "x86_64") {
            PROCESSOR_ARCHITECTURE_AMD64
        } else {
            PROCESSOR_ARCHITECTURE_INTEL
        };

        (*lpSystemInfo) = SYSTEM_INFO {
            wProcessorArchitecture: arch,
            wReserved: 0,
            dwPageSize: page_size,
            lpMinimumApplicationAddress: 0x10000, // 64KB - standard Windows minimum
            lpMaximumApplicationAddress: if cfg!(target_arch = "x86_64") {
                0x00007FFFFFFEFFFF // x64 user-mode max
            } else {
                0x7FFEFFFF // x86 user-mode max
            },
            dwActiveProcessorMask: (1 << num_cpus) - 1, // Bitmask of active processors
            dwNumberOfProcessors: num_cpus,
            dwProcessorType: if cfg!(target_arch = "x86_64") {
                8664 // PROCESSOR_AMD_X8664
            } else {
                586 // PROCESSOR_INTEL_PENTIUM
            },
            dwAllocationGranularity: 65536, // 64KB - Windows allocation granularity
            wProcessorLevel: 6, // Intel family 6 or AMD equivalent
            wProcessorRevision: 0,
        };
    }
}

/// GetVersionExA - Returns Windows version information (ANSI)
#[no_mangle]
pub extern "win64" fn GetVersionExA(lpVersionInformation: *mut OSVERSIONINFOA) -> i32 {
    tracing::debug!("GetVersionExA called");

    if lpVersionInformation.is_null() {
        return 0;
    }

    unsafe {
        let size = (*lpVersionInformation).dwOSVersionInfoSize;

        // Fill in Windows 10 version info
        (*lpVersionInformation).dwMajorVersion = 10;
        (*lpVersionInformation).dwMinorVersion = 0;
        (*lpVersionInformation).dwBuildNumber = 19045; // Windows 10 22H2
        (*lpVersionInformation).dwPlatformId = VER_PLATFORM_WIN32_NT;

        // Service pack version (empty for Windows 10)
        (*lpVersionInformation).szCSDVersion = [0; 128];

        // If extended structure, fill additional fields
        if size >= mem::size_of::<OSVERSIONINFOEXA>() as u32 {
            let lpVersionInfoEx = lpVersionInformation as *mut OSVERSIONINFOEXA;
            (*lpVersionInfoEx).wServicePackMajor = 0;
            (*lpVersionInfoEx).wServicePackMinor = 0;
            (*lpVersionInfoEx).wSuiteMask = 0x100; // VER_SUITE_PERSONAL
            (*lpVersionInfoEx).wProductType = 1; // VER_NT_WORKSTATION
            (*lpVersionInfoEx).wReserved = 0;
        }
    }

    1 // TRUE
}

/// GetVersionExW - Returns Windows version information (Unicode)
#[no_mangle]
pub extern "win64" fn GetVersionExW(lpVersionInformation: *mut OSVERSIONINFOW) -> i32 {
    tracing::debug!("GetVersionExW called");

    if lpVersionInformation.is_null() {
        return 0;
    }

    unsafe {
        let size = (*lpVersionInformation).dwOSVersionInfoSize;

        // Fill in Windows 10 version info
        (*lpVersionInformation).dwMajorVersion = 10;
        (*lpVersionInformation).dwMinorVersion = 0;
        (*lpVersionInformation).dwBuildNumber = 19045; // Windows 10 22H2
        (*lpVersionInformation).dwPlatformId = VER_PLATFORM_WIN32_NT;

        // Service pack version (empty for Windows 10)
        (*lpVersionInformation).szCSDVersion = [0; 128];

        // If extended structure, fill additional fields
        if size >= mem::size_of::<OSVERSIONINFOEXW>() as u32 {
            let lpVersionInfoEx = lpVersionInformation as *mut OSVERSIONINFOEXW;
            (*lpVersionInfoEx).wServicePackMajor = 0;
            (*lpVersionInfoEx).wServicePackMinor = 0;
            (*lpVersionInfoEx).wSuiteMask = 0x100; // VER_SUITE_PERSONAL
            (*lpVersionInfoEx).wProductType = 1; // VER_NT_WORKSTATION
            (*lpVersionInfoEx).wReserved = 0;
        }
    }

    1 // TRUE
}

/// GetVersion - Returns packed Windows version
#[no_mangle]
pub extern "win64" fn GetVersion() -> u32 {
    tracing::debug!("GetVersion called");

    // Pack version: low byte = major, next byte = minor, high word = build
    // Windows 10.0.19045
    let major = 10u32;
    let minor = 0u32;
    let build = 19045u32;

    (build << 16) | (minor << 8) | major
}

/// GetComputerNameA - Returns computer name (ANSI)
#[no_mangle]
pub extern "win64" fn GetComputerNameA(lpBuffer: *mut u8, nSize: *mut u32) -> i32 {
    tracing::debug!("GetComputerNameA called");

    if lpBuffer.is_null() || nSize.is_null() {
        return 0;
    }

    let hostname = get_hostname();
    let hostname_bytes = hostname.as_bytes();

    unsafe {
        let buffer_size = *nSize as usize;

        if buffer_size == 0 || buffer_size <= hostname_bytes.len() {
            // Buffer too small, return required size
            *nSize = (hostname_bytes.len() + 1) as u32;
            crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }

        // Copy hostname to buffer
        std::ptr::copy_nonoverlapping(
            hostname_bytes.as_ptr(),
            lpBuffer,
            hostname_bytes.len(),
        );

        // Null terminate
        *lpBuffer.add(hostname_bytes.len()) = 0;
        *nSize = hostname_bytes.len() as u32;
    }

    1 // TRUE
}

/// GetComputerNameW - Returns computer name (Unicode)
#[no_mangle]
pub extern "win64" fn GetComputerNameW(lpBuffer: *mut u16, nSize: *mut u32) -> i32 {
    tracing::debug!("GetComputerNameW called");

    if lpBuffer.is_null() || nSize.is_null() {
        return 0;
    }

    let hostname = get_hostname();
    let hostname_wide = crate::utils::wide_string::str_to_wide(&hostname);

    unsafe {
        let buffer_size = *nSize as usize;

        if buffer_size == 0 || buffer_size <= hostname_wide.len() {
            // Buffer too small, return required size
            *nSize = (hostname_wide.len() + 1) as u32;
            crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }

        // Copy hostname to buffer
        std::ptr::copy_nonoverlapping(
            hostname_wide.as_ptr(),
            lpBuffer,
            hostname_wide.len(),
        );

        // Null terminate
        *lpBuffer.add(hostname_wide.len()) = 0;
        *nSize = hostname_wide.len() as u32;
    }

    1 // TRUE
}

// Helper functions

fn num_cpus_from_system() -> u32 {
    unsafe {
        let count = libc::sysconf(libc::_SC_NPROCESSORS_ONLN);
        if count > 0 {
            count as u32
        } else {
            1 // Default to 1 if detection fails
        }
    }
}

fn get_hostname() -> String {
    use std::ffi::CStr;

    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
            if let Ok(hostname) = CStr::from_ptr(buf.as_ptr() as *const libc::c_char).to_str() {
                return hostname.to_string();
            }
        }
    }

    "TUXEXE-PC".to_string() // Default hostname
}
