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
    trace!("Sleep({})", dw_milliseconds);
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
        let secs = since_the_epoch.as_secs() + 11_644_473_600;
        let nanos = since_the_epoch.subsec_nanos() as u64;

        let filetime = (secs * 10_000_000) + (nanos / 100);

        unsafe {
            *lp_system_time_as_file_time = filetime;
        }
    }
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
        let elapsed = START_TIME.elapsed().as_nanos() as u64;
        unsafe {
            *lp_performance_count = elapsed;
        }
    }
    1
}

pub extern "win64" fn query_performance_frequency(lp_frequency: *mut u64) -> i32 {
    if !lp_frequency.is_null() {
        unsafe {
            // We measure QPC in nanoseconds, so frequency is 1_000_000_000 per second.
            *lp_frequency = 1_000_000_000;
        }
    }
    1
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
}
