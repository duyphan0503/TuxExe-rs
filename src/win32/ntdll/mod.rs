#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::nt_kernel::file::*;
use crate::utils::handle::Handle;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

#[repr(C)]
pub struct IoStatusBlock {
    pub status: u32,
    pub information: usize,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

struct DirectoryScanCursor {
    entries: Vec<DirectoryEntryInfo>,
    index: usize,
}

static DIR_SCANS: std::sync::OnceLock<Mutex<HashMap<Handle, DirectoryScanCursor>>> =
    std::sync::OnceLock::new();

fn dir_scans() -> &'static Mutex<HashMap<Handle, DirectoryScanCursor>> {
    DIR_SCANS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub extern "win64" fn NtQueryDirectoryFile(
    file_handle: Handle,
    _event: Handle,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    file_information: *mut u8,
    length: u32,
    file_information_class: u32,
    return_single_entry: u8,
    _file_name: *const UnicodeString,
    restart_scan: u8,
) -> u32 {
    if io_status_block.is_null() || file_information.is_null() || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let mut scans = dir_scans().lock().expect("dir_scans poisoned");
    if restart_scan != 0 || !scans.contains_key(&file_handle) {
        match nt_query_directory_file(file_handle) {
            Ok(entries) => {
                scans.insert(file_handle, DirectoryScanCursor { entries, index: 0 });
            }
            Err(status) => {
                unsafe {
                    (*io_status_block).status = status;
                    (*io_status_block).information = 0;
                }
                return status;
            }
        }
    }

    let cursor = scans.get_mut(&file_handle).unwrap();
    if cursor.index >= cursor.entries.len() {
        unsafe {
            (*io_status_block).status = STATUS_NO_MORE_FILES;
            (*io_status_block).information = 0;
        }
        return STATUS_NO_MORE_FILES;
    }

    let mut written = 0usize;
    let mut prev_offset_ptr: *mut u32 = std::ptr::null_mut();

    while cursor.index < cursor.entries.len() {
        let entry = &cursor.entries[cursor.index];
        let name_utf16: Vec<u16> = entry.file_name.encode_utf16().collect();
        let name_bytes = name_utf16.len() * 2;

        let header_size = match file_information_class {
            1 => 64,   // FileDirectoryInformation
            2 => 72,   // FileFullDirectoryInformation
            3 => 94,   // FileBothDirectoryInformation
            37 => 104, // FileIdBothDirectoryInformation
            12 => 8,   // FileNamesInformation
            _ => 64,
        };

        let total_entry_size = (header_size + name_bytes + 7) & !7;
        if written + total_entry_size > length as usize {
            if written == 0 {
                return 0xC000_0023; // STATUS_BUFFER_TOO_SMALL
            }
            break;
        }

        if !prev_offset_ptr.is_null() {
            unsafe {
                *prev_offset_ptr =
                    (written - (prev_offset_ptr as usize - file_information as usize)) as u32;
            }
        }

        let entry_ptr = unsafe { file_information.add(written) };
        unsafe {
            std::ptr::write_bytes(entry_ptr, 0, total_entry_size);
        }

        let next_offset_ptr = entry_ptr as *mut u32;
        prev_offset_ptr = next_offset_ptr;

        let file_attributes: u32 = if entry.is_directory { 0x10 } else { 0x80 };
        let file_size: u64 = entry.file_size;

        unsafe {
            match file_information_class {
                1 => {
                    entry_ptr.add(40).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(48).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(56).cast::<u32>().write_unaligned(file_attributes);
                    entry_ptr.add(60).cast::<u32>().write_unaligned(name_bytes as u32);
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(64),
                        name_bytes,
                    );
                }
                3 | 37 => {
                    entry_ptr.add(40).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(48).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(56).cast::<u32>().write_unaligned(file_attributes);
                    entry_ptr.add(60).cast::<u32>().write_unaligned(name_bytes as u32);
                    let name_offset = if file_information_class == 37 { 104 } else { 94 };
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(name_offset),
                        name_bytes,
                    );
                }
                12 => {
                    entry_ptr.add(4).cast::<u32>().write_unaligned(name_bytes as u32);
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(8),
                        name_bytes,
                    );
                }
                _ => {
                    entry_ptr.add(40).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(48).cast::<u64>().write_unaligned(file_size);
                    entry_ptr.add(56).cast::<u32>().write_unaligned(file_attributes);
                    entry_ptr.add(60).cast::<u32>().write_unaligned(name_bytes as u32);
                    std::ptr::copy_nonoverlapping(
                        name_utf16.as_ptr() as *const u8,
                        entry_ptr.add(64),
                        name_bytes,
                    );
                }
            }
        }

        written += total_entry_size;
        cursor.index += 1;

        if return_single_entry != 0 {
            break;
        }
    }

    unsafe {
        (*io_status_block).status = STATUS_SUCCESS;
        (*io_status_block).information = written;
    }

    STATUS_SUCCESS
}

fn current_filetime_now() -> u64 {
    let now = std::time::SystemTime::now();
    let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = since_epoch.as_secs() + 11_644_473_600;
    let nanos = since_epoch.subsec_nanos() as u64;
    (secs * 10_000_000) + (nanos / 100)
}

pub extern "win64" fn NtDelayExecution(_alertable: u8, delay_interval: *const i64) -> u32 {
    if delay_interval.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let interval = unsafe { *delay_interval };
    if interval < 0 {
        let nanos = (-interval as u64).saturating_mul(100);
        let duration = std::time::Duration::from_nanos(nanos);
        if duration.is_zero() {
            std::thread::yield_now();
        } else {
            std::thread::sleep(duration);
        }
    } else if interval > 0 {
        let now_ft = current_filetime_now();
        let target_ft = interval as u64;
        if target_ft > now_ft {
            let diff_100ns = target_ft - now_ft;
            let duration = std::time::Duration::from_nanos(diff_100ns.saturating_mul(100));
            std::thread::sleep(duration);
        } else {
            std::thread::yield_now();
        }
    } else {
        std::thread::yield_now();
    }
    STATUS_SUCCESS
}

pub extern "win64" fn NtQueryPerformanceCounter(
    performance_counter: *mut u64,
    performance_frequency: *mut u64,
) -> u32 {
    crate::win32::kernel32::system::update_kuser_shared_data();
    if !performance_counter.is_null() {
        let elapsed_ticks =
            (crate::win32::kernel32::time::START_TIME.elapsed().as_nanos() / 100) as u64;
        unsafe {
            *performance_counter = elapsed_ticks;
        }
    }
    if !performance_frequency.is_null() {
        unsafe {
            *performance_frequency = 10_000_000;
        }
    }
    STATUS_SUCCESS
}

/// `RtlQueryPerformanceCounter` has a one-argument BOOLEAN ABI. It must not be
/// aliased to `NtQueryPerformanceCounter`, whose second argument is an optional
/// frequency output pointer.
pub extern "win64" fn RtlQueryPerformanceCounter(performance_counter: *mut u64) -> u8 {
    (crate::win32::kernel32::time::query_performance_counter(performance_counter) != 0) as u8
}

pub extern "win64" fn RtlQueryPerformanceFrequency(performance_frequency: *mut u64) -> u8 {
    (crate::win32::kernel32::time::query_performance_frequency(performance_frequency) != 0) as u8
}

pub extern "win64" fn NtQuerySystemTime(system_time: *mut u64) -> u32 {
    if system_time.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    crate::win32::kernel32::system::update_kuser_shared_data();
    unsafe {
        *system_time = current_filetime_now();
    }
    STATUS_SUCCESS
}

pub extern "win64" fn NtQueryTimerResolution(
    min_resolution: *mut u32,
    max_resolution: *mut u32,
    current_resolution: *mut u32,
) -> u32 {
    if !min_resolution.is_null() {
        unsafe {
            *min_resolution = 156_250;
        } // 15.625ms in 100ns units
    }
    if !max_resolution.is_null() {
        unsafe {
            *max_resolution = 5_000;
        } // 0.5ms in 100ns units
    }
    if !current_resolution.is_null() {
        unsafe {
            *current_resolution = 10_000;
        } // 1.0ms in 100ns units
    }
    STATUS_SUCCESS
}

pub extern "win64" fn NtSetTimerResolution(
    desired_resolution: u32,
    _set_resolution: u8,
    current_resolution: *mut u32,
) -> u32 {
    if !current_resolution.is_null() {
        unsafe {
            *current_resolution = desired_resolution.clamp(5_000, 156_250);
        }
    }
    STATUS_SUCCESS
}

pub extern "win64" fn NtGetTickCount() -> u32 {
    crate::win32::kernel32::time::get_tick_count()
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("NtQueryDirectoryFile", NtQueryDirectoryFile as usize);
    exports.insert("ZwQueryDirectoryFile", NtQueryDirectoryFile as usize);
    exports.insert("NtDelayExecution", NtDelayExecution as usize);
    exports.insert("ZwDelayExecution", NtDelayExecution as usize);
    exports.insert("NtQueryPerformanceCounter", NtQueryPerformanceCounter as usize);
    exports.insert("ZwQueryPerformanceCounter", NtQueryPerformanceCounter as usize);
    exports.insert("RtlQueryPerformanceCounter", RtlQueryPerformanceCounter as usize);
    exports.insert("RtlQueryPerformanceFrequency", RtlQueryPerformanceFrequency as usize);
    exports.insert("NtQuerySystemTime", NtQuerySystemTime as usize);
    exports.insert("ZwQuerySystemTime", NtQuerySystemTime as usize);
    exports.insert("NtQueryTimerResolution", NtQueryTimerResolution as usize);
    exports.insert("ZwQueryTimerResolution", NtQueryTimerResolution as usize);
    exports.insert("NtSetTimerResolution", NtSetTimerResolution as usize);
    exports.insert("ZwSetTimerResolution", NtSetTimerResolution as usize);
    exports.insert("NtGetTickCount", NtGetTickCount as usize);
    exports.insert("RtlGetVersion", crate::win32::kernel32::system::RtlGetVersion as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtl_qpc_exports_use_their_one_argument_abi() {
        let mut before = 0_u64;
        let mut after = 0_u64;
        let mut frequency = 0_u64;

        assert_eq!(RtlQueryPerformanceCounter(&mut before), 1);
        assert_eq!(RtlQueryPerformanceFrequency(&mut frequency), 1);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(RtlQueryPerformanceCounter(&mut after), 1);

        assert_eq!(frequency, 10_000_000);
        assert!((100_000..=1_000_000).contains(&(after - before)));
        assert_eq!(
            get_exports().get("RtlQueryPerformanceCounter"),
            Some(&(RtlQueryPerformanceCounter as usize))
        );
    }
}
