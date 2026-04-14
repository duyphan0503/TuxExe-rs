//! System information APIs - GetSystemInfo, GetVersionEx, etc.

use std::mem;

// Windows constants
const VER_PLATFORM_WIN32_NT: u32 = 2;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;

#[repr(C)]
#[allow(non_snake_case)]
pub struct MEMORYSTATUSEX {
    pub dwLength: u32,
    pub dwMemoryLoad: u32,
    pub ullTotalPhys: u64,
    pub ullAvailPhys: u64,
    pub ullTotalPageFile: u64,
    pub ullAvailPageFile: u64,
    pub ullTotalVirtual: u64,
    pub ullAvailVirtual: u64,
    pub ullAvailExtendedVirtual: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
    pub ProcessorMask: usize,
    pub Relationship: u32,
    pub Reserved: [u8; 20],
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
    pub Relationship: u32,
    pub Size: u32,
    pub Reserved: [u8; 40],
}

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
            wProcessorLevel: 6,             // Intel family 6 or AMD equivalent
            wProcessorRevision: 0,
        };
    }
}

/// GetNativeSystemInfo - Returns native system architecture info.
#[no_mangle]
pub extern "win64" fn GetNativeSystemInfo(lpSystemInfo: *mut SYSTEM_INFO) {
    GetSystemInfo(lpSystemInfo);
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
        std::ptr::copy_nonoverlapping(hostname_bytes.as_ptr(), lpBuffer, hostname_bytes.len());

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
        std::ptr::copy_nonoverlapping(hostname_wide.as_ptr(), lpBuffer, hostname_wide.len());

        // Null terminate
        *lpBuffer.add(hostname_wide.len()) = 0;
        *nSize = hostname_wide.len() as u32;
    }

    1 // TRUE
}

/// GetWindowsDirectoryA - Returns Windows directory path (ANSI)
#[no_mangle]
pub extern "win64" fn GetWindowsDirectoryA(lpBuffer: *mut u8, uSize: u32) -> u32 {
    tracing::debug!("GetWindowsDirectoryA called");
    copy_ansi_path_to_buffer("C:\\Windows", lpBuffer, uSize)
}

/// GetWindowsDirectoryW - Returns Windows directory path (Unicode)
#[no_mangle]
pub extern "win64" fn GetWindowsDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32 {
    tracing::debug!("GetWindowsDirectoryW called");
    copy_wide_path_to_buffer("C:\\Windows", lpBuffer, uSize)
}

/// GetSystemDirectoryA - Returns Windows system directory path (ANSI)
#[no_mangle]
pub extern "win64" fn GetSystemDirectoryA(lpBuffer: *mut u8, uSize: u32) -> u32 {
    tracing::debug!("GetSystemDirectoryA called");
    copy_ansi_path_to_buffer("C:\\Windows\\System32", lpBuffer, uSize)
}

/// GetSystemDirectoryW - Returns Windows system directory path (Unicode)
#[no_mangle]
pub extern "win64" fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32 {
    tracing::debug!("GetSystemDirectoryW called");
    copy_wide_path_to_buffer("C:\\Windows\\System32", lpBuffer, uSize)
}

// Helper functions

fn copy_ansi_path_to_buffer(path: &str, lp_buffer: *mut u8, u_size: u32) -> u32 {
    let bytes = path.as_bytes();
    let required = bytes.len() + 1;

    if lp_buffer.is_null() || u_size == 0 {
        crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return required as u32;
    }

    if required > u_size as usize {
        crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return required as u32;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
        *lp_buffer.add(bytes.len()) = 0;
    }
    crate::win32::kernel32::error::set_last_error(0);
    bytes.len() as u32
}

fn copy_wide_path_to_buffer(path: &str, lp_buffer: *mut u16, u_size: u32) -> u32 {
    let wide: Vec<u16> = path.encode_utf16().collect();
    let required = wide.len() + 1;

    if lp_buffer.is_null() || u_size == 0 {
        crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return required as u32;
    }

    if required > u_size as usize {
        crate::win32::kernel32::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return required as u32;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_buffer, wide.len());
        *lp_buffer.add(wide.len()) = 0;
    }
    crate::win32::kernel32::error::set_last_error(0);
    wide.len() as u32
}

/// GetLogicalProcessorInformation - minimal topology with a single entry.
#[no_mangle]
pub extern "win64" fn GetLogicalProcessorInformation(
    Buffer: *mut SYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    ReturnedLength: *mut u32,
) -> i32 {
    if ReturnedLength.is_null() {
        return 0;
    }

    let required = std::mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>() as u32;
    unsafe {
        if Buffer.is_null() || *ReturnedLength < required {
            *ReturnedLength = required;
            crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
    }

    let num_cpus = num_cpus_from_system().max(1).min(usize::BITS as u32);
    let mask = if num_cpus as usize >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << num_cpus) - 1
    };

    unsafe {
        *Buffer = SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
            ProcessorMask: mask,
            Relationship: 0,
            Reserved: [0; 20],
        };
        *ReturnedLength = required;
    }
    crate::win32::kernel32::error::set_last_error(0);
    1
}

/// GetLogicalProcessorInformationEx - minimal topology with a single entry.
#[no_mangle]
pub extern "win64" fn GetLogicalProcessorInformationEx(
    RelationshipType: u32,
    Buffer: *mut SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
    ReturnedLength: *mut u32,
) -> i32 {
    if ReturnedLength.is_null() {
        return 0;
    }

    let required = std::mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>() as u32;
    unsafe {
        if Buffer.is_null() || *ReturnedLength < required {
            *ReturnedLength = required;
            crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        *Buffer = SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
            Relationship: RelationshipType,
            Size: required,
            Reserved: [0; 40],
        };
        *ReturnedLength = required;
    }
    crate::win32::kernel32::error::set_last_error(0);
    1
}

#[no_mangle]
pub extern "win64" fn GetNumaHighestNodeNumber(HighestNodeNumber: *mut u32) -> i32 {
    if HighestNodeNumber.is_null() {
        return 0;
    }

    unsafe {
        *HighestNodeNumber = 0;
    }
    crate::win32::kernel32::error::set_last_error(0);
    1
}

#[no_mangle]
pub extern "win64" fn GlobalMemoryStatusEx(lpBuffer: *mut MEMORYSTATUSEX) -> i32 {
    if lpBuffer.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let expected_len = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    unsafe {
        if (*lpBuffer).dwLength != expected_len {
            crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    }

    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::sysinfo(&mut info) };
    if rc != 0 {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let unit = (info.mem_unit as u64).max(1);
    let total_phys =
        (info.totalram as u128).saturating_mul(unit as u128).min(u64::MAX as u128) as u64;
    let avail_phys =
        (info.freeram as u128).saturating_mul(unit as u128).min(u64::MAX as u128) as u64;
    let total_swap =
        (info.totalswap as u128).saturating_mul(unit as u128).min(u64::MAX as u128) as u64;
    let avail_swap =
        (info.freeswap as u128).saturating_mul(unit as u128).min(u64::MAX as u128) as u64;

    let total_page = total_phys.saturating_add(total_swap);
    let avail_page = avail_phys.saturating_add(avail_swap);
    let total_virtual = total_page;
    let avail_virtual = avail_page;

    let used_phys = total_phys.saturating_sub(avail_phys);
    let memory_load = if total_phys == 0 {
        0
    } else {
        ((used_phys as u128).saturating_mul(100) / total_phys as u128).min(100) as u32
    };

    unsafe {
        *lpBuffer = MEMORYSTATUSEX {
            dwLength: expected_len,
            dwMemoryLoad: memory_load,
            ullTotalPhys: total_phys,
            ullAvailPhys: avail_phys,
            ullTotalPageFile: total_page,
            ullAvailPageFile: avail_page,
            ullTotalVirtual: total_virtual,
            ullAvailVirtual: avail_virtual,
            ullAvailExtendedVirtual: 0,
        };
    }

    crate::win32::kernel32::error::set_last_error(0);
    1
}

#[no_mangle]
pub extern "win64" fn VerifyVersionInfoW(
    lpVersionInformation: *const OSVERSIONINFOEXW,
    _dwTypeMask: u32,
    _dwlConditionMask: u64,
) -> i32 {
    if lpVersionInformation.is_null() {
        crate::win32::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Compatibility path: report success for version probes used by game startup.
    crate::win32::kernel32::error::set_last_error(0);
    1
}

#[no_mangle]
pub extern "win64" fn VerSetConditionMask(
    mut ConditionMask: u64,
    TypeMask: u32,
    Condition: u8,
) -> u64 {
    let condition = (Condition & 0x7) as u64;

    // Windows encodes one 3-bit condition field per VER_* selector bit.
    for bit_index in 0..32 {
        let bit = 1u32 << bit_index;
        if (TypeMask & bit) == 0 {
            continue;
        }

        let shift = (bit_index * 3) as u64;
        let field_mask = 0x7u64 << shift;
        ConditionMask = (ConditionMask & !field_mask) | (condition << shift);
    }

    ConditionMask
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_memory_status_ex_populates_fields() {
        let mut mem = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            dwMemoryLoad: 0,
            ullTotalPhys: 0,
            ullAvailPhys: 0,
            ullTotalPageFile: 0,
            ullAvailPageFile: 0,
            ullTotalVirtual: 0,
            ullAvailVirtual: 0,
            ullAvailExtendedVirtual: 0,
        };

        assert_eq!(GlobalMemoryStatusEx(&mut mem as *mut MEMORYSTATUSEX), 1);
        assert!(mem.ullTotalPhys > 0);
        assert!(mem.ullAvailPhys <= mem.ullTotalPhys);
        assert!(mem.dwMemoryLoad <= 100);
    }

    #[test]
    fn verify_version_info_w_handles_null_and_success() {
        assert_eq!(VerifyVersionInfoW(std::ptr::null(), 0, 0), 0);

        let info = OSVERSIONINFOEXW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOEXW>() as u32,
            dwMajorVersion: 10,
            dwMinorVersion: 0,
            dwBuildNumber: 19045,
            dwPlatformId: VER_PLATFORM_WIN32_NT,
            szCSDVersion: [0; 128],
            wServicePackMajor: 0,
            wServicePackMinor: 0,
            wSuiteMask: 0,
            wProductType: 1,
            wReserved: 0,
        };
        assert_eq!(VerifyVersionInfoW(&info as *const OSVERSIONINFOEXW, 0, 0), 1);
    }

    #[test]
    fn ver_set_condition_mask_sets_bit_fields() {
        // VER_MAJORVERSION (0x2) -> field index 1 => shift 3
        let mask = VerSetConditionMask(0, 0x2, 3);
        assert_eq!(mask, 3u64 << 3);

        // VER_MINORVERSION (0x1) -> field index 0 => shift 0
        let combined = VerSetConditionMask(mask, 0x1, 5);
        assert_eq!(combined, (3u64 << 3) | 5u64);
    }
}
