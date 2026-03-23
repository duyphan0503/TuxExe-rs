//! GetSystemTimeAsFileTime, QueryPerformanceCounter, GetTickCount, Sleep.

use tracing::trace;
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};
use std::thread;

pub extern "win64" fn sleep(dw_milliseconds: u32) {
    trace!("Sleep({})", dw_milliseconds);
    thread::sleep(Duration::from_millis(dw_milliseconds as u64));
}

lazy_static::lazy_static! {
    static ref START_TIME: Instant = Instant::now();
}

pub extern "win64" fn get_tick_count() -> u32 {
    let elapsed = START_TIME.elapsed().as_millis() as u32;
    // trace!("GetTickCount() -> {}", elapsed);
    elapsed
}

pub extern "win64" fn get_tick_count_64() -> u64 {
    let elapsed = START_TIME.elapsed().as_millis() as u64;
    // trace!("GetTickCount64() -> {}", elapsed);
    elapsed
}

pub extern "win64" fn get_system_time_as_file_time(lp_system_time_as_file_time: *mut u64) {
    if !lp_system_time_as_file_time.is_null() {
        let now = SystemTime::now();
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
