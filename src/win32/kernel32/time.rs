#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! GetSystemTimeAsFileTime, QueryPerformanceCounter, GetTickCount, Sleep.

use std::thread;
use std::time::{Duration, Instant, SystemTime as StdSystemTime, UNIX_EPOCH};
use tracing::trace;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTime {
    pub wYear: u16,
    pub wMonth: u16,
    pub wDayOfWeek: u16,
    pub wDay: u16,
    pub wHour: u16,
    pub wMinute: u16,
    pub wSecond: u16,
    pub wMilliseconds: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(non_snake_case)]
pub struct TimeZoneInformation {
    pub Bias: i32,
    pub StandardName: [u16; 32],
    pub StandardDate: SystemTime,
    pub StandardBias: i32,
    pub DaylightName: [u16; 32],
    pub DaylightDate: SystemTime,
    pub DaylightBias: i32,
}

const WINDOWS_EPOCH_DIFF_SECS: u64 = 11_644_473_600;
const TIME_ZONE_ID_UNKNOWN: u32 = 0;

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Howard Hinnant's algorithm: days since Unix epoch for civil date.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) as i64
}

fn system_time_to_filetime_value(st: &SystemTime) -> Option<u64> {
    let year = st.wYear as i32;
    let month = st.wMonth as u32;
    let day = st.wDay as u32;
    let hour = st.wHour as u32;
    let minute = st.wMinute as u32;
    let second = st.wSecond as u32;
    let millis = st.wMilliseconds as u32;

    if year < 1601 || !(1..=12).contains(&month) || day == 0 {
        return None;
    }

    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    if day > max_day || hour > 23 || minute > 59 || second > 59 || millis > 999 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let secs_of_day = (hour * 3600 + minute * 60 + second) as i64;
    let unix_secs = days.checked_mul(86_400)?.checked_add(secs_of_day)?;
    let windows_secs = unix_secs.checked_add(WINDOWS_EPOCH_DIFF_SECS as i64)?;
    if windows_secs < 0 {
        return None;
    }
    let intervals = (windows_secs as u64)
        .checked_mul(10_000_000)?
        .checked_add((millis as u64).checked_mul(10_000)?)?;
    Some(intervals)
}

fn current_system_time(local: bool) -> Option<SystemTime> {
    let mut now: libc::time_t = 0;
    unsafe {
        libc::time(&mut now);
    }

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tm_ptr = if local {
        unsafe { libc::localtime_r(&now, &mut tm) }
    } else {
        unsafe { libc::gmtime_r(&now, &mut tm) }
    };

    if tm_ptr.is_null() {
        return None;
    }

    let millis = match StdSystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.subsec_millis() as u16,
        Err(_) => 0,
    };

    Some(SystemTime {
        wYear: (tm.tm_year + 1900) as u16,
        wMonth: (tm.tm_mon + 1) as u16,
        wDayOfWeek: tm.tm_wday as u16,
        wDay: tm.tm_mday as u16,
        wHour: tm.tm_hour as u16,
        wMinute: tm.tm_min as u16,
        wSecond: tm.tm_sec as u16,
        wMilliseconds: millis,
    })
}

pub extern "win64" fn sleep(dw_milliseconds: u32) {
    if dw_milliseconds == 0 {
        thread::yield_now();
        return;
    }
    thread::sleep(Duration::from_millis(dw_milliseconds as u64));
}

lazy_static::lazy_static! {
    static ref START_TIME: Instant = Instant::now();
}

pub extern "win64" fn get_tick_count() -> u32 {
    START_TIME.elapsed().as_millis() as u32
}

pub extern "win64" fn get_tick_count_64() -> u64 {
    START_TIME.elapsed().as_millis() as u64
}

pub extern "win64" fn get_system_time_as_file_time(lp_system_time_as_file_time: *mut u64) {
    if !lp_system_time_as_file_time.is_null() {
        let now = StdSystemTime::now();
        let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

        // Windows epoch is Jan 1, 1601. Unix is Jan 1, 1970.
        // Difference is 11644473600 seconds.
        // FILETIME is in 100-nanosecond intervals.
        let secs = since_the_epoch.as_secs() + WINDOWS_EPOCH_DIFF_SECS;
        let nanos = since_the_epoch.subsec_nanos() as u64;

        let filetime = (secs * 10_000_000) + (nanos / 100);

        unsafe {
            *lp_system_time_as_file_time = filetime;
        }
    }
}

pub extern "win64" fn system_time_to_file_time(
    lp_system_time: *const SystemTime,
    lp_file_time: *mut u64,
) -> i32 {
    if lp_system_time.is_null() || lp_file_time.is_null() {
        return 0;
    }

    let st = unsafe { *lp_system_time };
    match system_time_to_filetime_value(&st) {
        Some(filetime) => {
            unsafe {
                *lp_file_time = filetime;
            }
            1
        }
        None => 0,
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn system_time_to_tz_specific_local_time(
    _lp_time_zone_information: *const TimeZoneInformation,
    lp_universal_time: *const SystemTime,
    lp_local_time: *mut SystemTime,
) -> i32 {
    if lp_local_time.is_null() {
        crate::win32::kernel32::error::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let value = if lp_universal_time.is_null() {
        current_system_time(true).unwrap_or_default()
    } else {
        unsafe { *lp_universal_time }
    };

    unsafe {
        *lp_local_time = value;
    }
    crate::win32::kernel32::error::set_last_error(0);
    1
}

/// Convert a local SYSTEMTIME to UTC. When no explicit Windows timezone is
/// supplied, use the host's timezone database through `mktime`, which also
/// accounts for daylight-saving time.
pub extern "win64" fn tz_specific_local_time_to_system_time(
    lp_time_zone_information: *const TimeZoneInformation,
    lp_local_time: *const SystemTime,
    lp_universal_time: *mut SystemTime,
) -> i32 {
    if lp_local_time.is_null() || lp_universal_time.is_null() {
        crate::win32::kernel32::error::set_last_error(87);
        return 0;
    }
    let local = unsafe { *lp_local_time };
    if system_time_to_filetime_value(&local).is_none() {
        crate::win32::kernel32::error::set_last_error(87);
        return 0;
    }

    let unix_seconds = if lp_time_zone_information.is_null() {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = local.wYear as i32 - 1900;
        tm.tm_mon = local.wMonth as i32 - 1;
        tm.tm_mday = local.wDay as i32;
        tm.tm_hour = local.wHour as i32;
        tm.tm_min = local.wMinute as i32;
        tm.tm_sec = local.wSecond as i32;
        tm.tm_isdst = -1;
        let value = unsafe { libc::mktime(&mut tm) };
        if value == -1 {
            crate::win32::kernel32::error::set_last_error(87);
            return 0;
        }
        value
    } else {
        let bias_seconds = unsafe { (*lp_time_zone_information).Bias as i64 * 60 };
        let filetime = system_time_to_filetime_value(&local).expect("validated above");
        let local_seconds = (filetime / 10_000_000) as i64 - WINDOWS_EPOCH_DIFF_SECS as i64;
        match local_seconds.checked_add(bias_seconds) {
            Some(value) => value as libc::time_t,
            None => {
                crate::win32::kernel32::error::set_last_error(87);
                return 0;
            }
        }
    };

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&unix_seconds, &mut tm) }.is_null() {
        crate::win32::kernel32::error::set_last_error(87);
        return 0;
    }
    unsafe {
        *lp_universal_time = SystemTime {
            wYear: (tm.tm_year + 1900) as u16,
            wMonth: (tm.tm_mon + 1) as u16,
            wDayOfWeek: tm.tm_wday as u16,
            wDay: tm.tm_mday as u16,
            wHour: tm.tm_hour as u16,
            wMinute: tm.tm_min as u16,
            wSecond: tm.tm_sec as u16,
            wMilliseconds: local.wMilliseconds,
        };
    }
    crate::win32::kernel32::error::set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn file_time_to_system_time(
    lp_file_time: *const u64,
    lp_system_time: *mut SystemTime,
) -> i32 {
    if lp_file_time.is_null() || lp_system_time.is_null() {
        crate::win32::kernel32::error::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let file_time = unsafe { *lp_file_time };
    let unix_epoch_ticks = WINDOWS_EPOCH_DIFF_SECS.saturating_mul(10_000_000);
    if file_time < unix_epoch_ticks {
        crate::win32::kernel32::error::set_last_error(87);
        return 0;
    }

    let ticks_since_unix = file_time - unix_epoch_ticks;
    let unix_secs = (ticks_since_unix / 10_000_000) as libc::time_t;
    let millis = ((ticks_since_unix % 10_000_000) / 10_000) as u16;

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tm_ptr = unsafe { libc::gmtime_r(&unix_secs, &mut tm) };
    if tm_ptr.is_null() {
        crate::win32::kernel32::error::set_last_error(87);
        return 0;
    }

    unsafe {
        *lp_system_time = SystemTime {
            wYear: (tm.tm_year + 1900) as u16,
            wMonth: (tm.tm_mon + 1) as u16,
            wDayOfWeek: tm.tm_wday as u16,
            wDay: tm.tm_mday as u16,
            wHour: tm.tm_hour as u16,
            wMinute: tm.tm_min as u16,
            wSecond: tm.tm_sec as u16,
            wMilliseconds: millis,
        };
    }

    crate::win32::kernel32::error::set_last_error(0);
    1
}

pub extern "win64" fn get_system_time(lp_system_time: *mut SystemTime) {
    if lp_system_time.is_null() {
        return;
    }

    if let Some(value) = current_system_time(false) {
        unsafe {
            *lp_system_time = value;
        }
    }
}

pub extern "win64" fn get_local_time(lp_system_time: *mut SystemTime) {
    if lp_system_time.is_null() {
        return;
    }

    if let Some(value) = current_system_time(true) {
        unsafe {
            *lp_system_time = value;
        }
    }
}

pub extern "win64" fn query_performance_counter(lp_performance_count: *mut u64) -> i32 {
    if !lp_performance_count.is_null() {
        // Standard Windows 10/11 QPC frequency is 10 MHz (10,000,000 Hz, 100 ns ticks).
        let elapsed_ticks = (START_TIME.elapsed().as_nanos() / 100) as u64;
        unsafe {
            *lp_performance_count = elapsed_ticks;
        }
    }
    1
}

pub extern "win64" fn query_performance_frequency(lp_frequency: *mut u64) -> i32 {
    if !lp_frequency.is_null() {
        unsafe {
            // Standard Windows 10/11 QPC frequency: 10,000,000 counts per second (10 MHz).
            *lp_frequency = 10_000_000;
        }
    }
    1
}

pub extern "win64" fn get_time_zone_information(
    lp_time_zone_information: *mut TimeZoneInformation,
) -> u32 {
    if lp_time_zone_information.is_null() {
        crate::win32::kernel32::error::set_last_error(87); // ERROR_INVALID_PARAMETER
        return TIME_ZONE_ID_UNKNOWN;
    }

    let standard_name: Vec<u16> = "UTC".encode_utf16().collect();
    let daylight_name: Vec<u16> = "UTC".encode_utf16().collect();
    let mut tzi = TimeZoneInformation { Bias: 0, ..TimeZoneInformation::default() };
    for (idx, ch) in standard_name.iter().enumerate().take(31) {
        tzi.StandardName[idx] = *ch;
    }
    for (idx, ch) in daylight_name.iter().enumerate().take(31) {
        tzi.DaylightName[idx] = *ch;
    }

    unsafe {
        *lp_time_zone_information = tzi;
    }
    crate::win32::kernel32::error::set_last_error(0);
    TIME_ZONE_ID_UNKNOWN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_time_populates_basic_fields() {
        let mut st = SystemTime::default();
        get_system_time(&mut st);

        assert!(st.wYear >= 1970);
        assert!((1..=12).contains(&st.wMonth));
        assert!((1..=31).contains(&st.wDay));
        assert!(st.wHour <= 23);
        assert!(st.wMinute <= 59);
        assert!(st.wSecond <= 60);
        assert!(st.wMilliseconds <= 999);
    }

    #[test]
    fn system_time_to_file_time_converts_unix_epoch() {
        let st = SystemTime {
            wYear: 1970,
            wMonth: 1,
            wDay: 1,
            wHour: 0,
            wMinute: 0,
            wSecond: 0,
            wMilliseconds: 0,
            ..SystemTime::default()
        };

        let mut ft = 0u64;
        assert_eq!(system_time_to_file_time(&st, &mut ft), 1);
        assert_eq!(ft, 116_444_736_000_000_000);
    }
}
