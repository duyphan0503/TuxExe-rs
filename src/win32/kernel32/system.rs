//! System information APIs - GetSystemInfo, GetVersionEx, etc.

use std::mem;

// Windows constants
const VER_PLATFORM_WIN32_NT: u32 = 2;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;
const RELATION_GROUP: u32 = 4;

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
struct PROCESSOR_GROUP_INFO {
    MaximumProcessorCount: u8,
    ActiveProcessorCount: u8,
    Reserved: [u8; 38],
    ActiveProcessorMask: usize,
}

#[repr(C)]
#[allow(non_snake_case)]
struct GROUP_RELATIONSHIP {
    MaximumGroupCount: u16,
    ActiveGroupCount: u16,
    Reserved: [u8; 20],
    GroupInfo: [PROCESSOR_GROUP_INFO; 1],
}

#[repr(C)]
#[allow(non_snake_case)]
struct SYSTEM_LOGICAL_PROCESSOR_GROUP_INFORMATION {
    Relationship: u32,
    Size: u32,
    Group: GROUP_RELATIONSHIP,
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

        // Windows exposes the active processor set as a native-word bitmask.
        // Linux hosts can report more logical CPUs than fit in that mask; do
        // not let the shift overflow (or panic in debug builds).
        let active_processor_mask =
            if num_cpus >= usize::BITS { usize::MAX } else { (1usize << num_cpus) - 1 };

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
            dwActiveProcessorMask: active_processor_mask,
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

/// RtlGetVersion - Returns Windows version information (NT status)
#[no_mangle]
pub extern "win64" fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOW) -> u32 {
    tracing::debug!("RtlGetVersion called");
    if lpVersionInformation.is_null() {
        return 0xC000000D; // STATUS_INVALID_PARAMETER
    }
    if GetVersionExW(lpVersionInformation) != 0 {
        0 // STATUS_SUCCESS
    } else {
        0xC0000001 // STATUS_UNSUCCESSFUL
    }
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

    let required = if RelationshipType == RELATION_GROUP {
        std::mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_GROUP_INFORMATION>() as u32
    } else {
        std::mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>() as u32
    };
    unsafe {
        if Buffer.is_null() || *ReturnedLength < required {
            *ReturnedLength = required;
            crate::win32::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        if RelationshipType == RELATION_GROUP {
            let num_cpus = num_cpus_from_system().max(1).min(usize::BITS);
            let active_processor_mask =
                if num_cpus >= usize::BITS { usize::MAX } else { (1usize << num_cpus) - 1 };
            Buffer.cast::<SYSTEM_LOGICAL_PROCESSOR_GROUP_INFORMATION>().write_unaligned(
                SYSTEM_LOGICAL_PROCESSOR_GROUP_INFORMATION {
                    Relationship: RELATION_GROUP,
                    Size: required,
                    Group: GROUP_RELATIONSHIP {
                        MaximumGroupCount: 1,
                        ActiveGroupCount: 1,
                        Reserved: [0; 20],
                        GroupInfo: [PROCESSOR_GROUP_INFO {
                            MaximumProcessorCount: num_cpus as u8,
                            ActiveProcessorCount: num_cpus as u8,
                            Reserved: [0; 38],
                            ActiveProcessorMask: active_processor_mask,
                        }],
                    },
                },
            );
        } else {
            Buffer.write_unaligned(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
                Relationship: RelationshipType,
                Size: required,
                Reserved: [0; 40],
            });
        }
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

static KUSER_INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn update_kuser_shared_data() {
    if !KUSER_INITIALIZED.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let base = 0x7ffe_0000 as *mut u8;
    let elapsed_nanos = crate::win32::kernel32::time::START_TIME.elapsed().as_nanos() as u64;
    let elapsed_100ns = elapsed_nanos / 100;
    let elapsed_ms = elapsed_nanos / 1_000_000;

    let unix_now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let system_100ns = (unix_now_nanos / 100).wrapping_add(116_444_736_000_000_000);

    unsafe {
        // 0x0000: TickCountLowDeprecated
        base.add(0x0000).cast::<u32>().write_unaligned((elapsed_ms & 0xffff_ffff) as u32);
        // 0x0004: TickCountMultiplier = 0x01000000 (1 << 24)
        base.add(0x0004).cast::<u32>().write_unaligned(0x01000000);

        // 0x0008: InterruptTime (LowPart, High1Time, High2Time)
        let int_low = (elapsed_100ns & 0xffff_ffff) as u32;
        let int_high = (elapsed_100ns >> 32) as i32;
        base.add(0x0008).cast::<u32>().write_unaligned(int_low);
        base.add(0x000c).cast::<i32>().write_unaligned(int_high);
        base.add(0x0010).cast::<i32>().write_unaligned(int_high);

        // 0x0014: SystemTime (LowPart, High1Time, High2Time)
        let sys_low = (system_100ns & 0xffff_ffff) as u32;
        let sys_high = (system_100ns >> 32) as i32;
        base.add(0x0014).cast::<u32>().write_unaligned(sys_low);
        base.add(0x0018).cast::<i32>().write_unaligned(sys_high);
        base.add(0x001c).cast::<i32>().write_unaligned(sys_high);

        // 0x0320: TickCount (64-bit millisecond count)
        let tick_low = (elapsed_ms & 0xffff_ffff) as u32;
        let tick_high = (elapsed_ms >> 32) as i32;
        base.add(0x0320).cast::<u32>().write_unaligned(tick_low);
        base.add(0x0324).cast::<i32>().write_unaligned(tick_high);
        base.add(0x0328).cast::<i32>().write_unaligned(tick_high);
    }
}

pub fn init_kuser_shared_data() {
    let ptr = unsafe {
        libc::mmap(
            0x7ffe_0000 as *mut libc::c_void,
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        tracing::warn!("Failed to map KUSER_SHARED_DATA at 0x7FFE0000");
        return;
    }
    unsafe {
        std::ptr::write_bytes(ptr as *mut u8, 0, 0x1000);
        // 0x02d8: QpcFrequency (u64) = 10_000_000
        ptr.add(0x02d8).cast::<u64>().write_unaligned(10_000_000);
        // 0x026c: NtMajorVersion (u32) = 10
        ptr.add(0x026c).cast::<u32>().write_unaligned(10);
        // 0x0270: NtMinorVersion (u32) = 0
        ptr.add(0x0270).cast::<u32>().write_unaligned(0);
        // 0x0260: NtBuildNumber (u32) = 19045
        ptr.add(0x0260).cast::<u32>().write_unaligned(19045);
        // 0x0264: NtProductType (u32) = 1 (NtProductWinNt)
        ptr.add(0x0264).cast::<u32>().write_unaligned(1);
        // 0x0274: ProcessorFeatures (u8 array, 64 entries)
        ptr.add(0x0274 + 2).cast::<u8>().write_unaligned(1); // PF_COMPARE_EXCHANGE_DOUBLE
        ptr.add(0x0274 + 3).cast::<u8>().write_unaligned(1); // PF_MMX_INSTRUCTIONS_AVAILABLE
        ptr.add(0x0274 + 6).cast::<u8>().write_unaligned(1); // PF_XMMI_INSTRUCTIONS_AVAILABLE
        ptr.add(0x0274 + 10).cast::<u8>().write_unaligned(1); // PF_XMMI64_INSTRUCTIONS_AVAILABLE
        ptr.add(0x0274 + 13).cast::<u8>().write_unaligned(1); // PF_SSE3_INSTRUCTIONS_AVAILABLE
        ptr.add(0x0274 + 14).cast::<u8>().write_unaligned(1); // PF_COMPARE_EXCHANGE128
        ptr.add(0x0274 + 17).cast::<u8>().write_unaligned(1); // PF_XSAVE_ENABLED
        ptr.add(0x0274 + 23).cast::<u8>().write_unaligned(1); // PF_AVX_INSTRUCTIONS_AVAILABLE
        ptr.add(0x0274 + 24).cast::<u8>().write_unaligned(1); // PF_AVX2_INSTRUCTIONS_AVAILABLE
                                                              // 0x03b0: QpcBypassEnabled = 0 (Forces fallback to QPC API)
        ptr.add(0x03b0).cast::<u8>().write_unaligned(0);
    }

    KUSER_INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    update_kuser_shared_data();

    // Spawn background updater for KUSER_SHARED_DATA timestamps
    std::thread::Builder::new()
        .name("kuser-shared-updater".to_string())
        .spawn(|| loop {
            update_kuser_shared_data();
            std::thread::sleep(std::time::Duration::from_millis(1));
        })
        .expect("Failed to spawn KUSER_SHARED_DATA updater thread");
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

    #[test]
    fn logical_processor_group_reports_at_least_one_active_cpu() {
        const GROUP_INFO_OFFSET: usize = 32;
        const ACTIVE_PROCESSOR_COUNT_OFFSET: usize = GROUP_INFO_OFFSET + 1;
        const ACTIVE_PROCESSOR_MASK_OFFSET: usize = GROUP_INFO_OFFSET + 40;

        let mut required = 0u32;
        assert_eq!(
            GetLogicalProcessorInformationEx(RELATION_GROUP, std::ptr::null_mut(), &mut required,),
            0
        );
        assert!(required as usize >= ACTIVE_PROCESSOR_MASK_OFFSET + std::mem::size_of::<usize>());

        let mut buffer = vec![0u8; required as usize];
        assert_eq!(
            GetLogicalProcessorInformationEx(
                RELATION_GROUP,
                buffer.as_mut_ptr().cast(),
                &mut required,
            ),
            1
        );

        assert!(buffer[ACTIVE_PROCESSOR_COUNT_OFFSET] > 0);
        let mask = unsafe {
            buffer.as_ptr().add(ACTIVE_PROCESSOR_MASK_OFFSET).cast::<usize>().read_unaligned()
        };
        assert_ne!(mask, 0);
    }
}
