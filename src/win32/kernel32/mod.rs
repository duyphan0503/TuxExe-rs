//! kernel32.dll reimplementation — file I/O, process, thread, memory, console, sync.

pub mod console;
pub mod error;
pub mod file;
pub mod memory;
pub mod process;
pub mod string;
pub mod sync;
pub mod thread;
pub mod time;

use std::collections::HashMap;

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    
    // Console
    exports.insert("GetStdHandle", console::get_std_handle as usize);
    exports.insert("WriteConsoleA", console::write_console_a as usize);
    exports.insert("WriteConsoleW", console::write_console_w as usize);
    
    // File
    exports.insert("WriteFile", file::write_file as usize);
    exports.insert("ReadFile", file::read_file as usize);
    
    // Process
    exports.insert("ExitProcess", process::exit_process as usize);
    exports.insert("GetModuleHandleA", process::get_module_handle_a as usize);
    exports.insert("GetCommandLineA", process::get_command_line_a as usize);
    exports.insert("GetCommandLineW", process::get_command_line_w as usize);
    exports.insert("GetStartupInfoA", process::get_startup_info_a as usize);
    exports.insert("GetStartupInfoW", process::get_startup_info_w as usize);
    exports.insert("GetCurrentProcessId", process::get_current_process_id as usize);
    exports.insert("GetCurrentThreadId", process::get_current_thread_id as usize);
    exports.insert("IsProcessorFeaturePresent", process::is_processor_feature_present as usize);
    
    // Error
    exports.insert("GetLastError", error::get_last_error as usize);
    exports.insert("SetLastError", error::set_last_error as usize);
    exports.insert("SetUnhandledExceptionFilter", error::set_unhandled_exception_filter as usize);
    
    // Sync
    exports.insert("InitializeCriticalSection", sync::InitializeCriticalSection as usize);
    exports.insert("EnterCriticalSection", sync::EnterCriticalSection as usize);
    exports.insert("LeaveCriticalSection", sync::LeaveCriticalSection as usize);
    exports.insert("DeleteCriticalSection", sync::DeleteCriticalSection as usize);
    
    // Memory
    exports.insert("VirtualProtect", memory::VirtualProtect as usize);
    exports.insert("VirtualQuery", memory::VirtualQuery as usize);
    
    // String
    exports.insert("IsDBCSLeadByteEx", string::IsDBCSLeadByteEx as usize);
    exports.insert("MultiByteToWideChar", string::MultiByteToWideChar as usize);
    exports.insert("WideCharToMultiByte", string::WideCharToMultiByte as usize);
    
    // Thread
    exports.insert("TlsGetValue", thread::TlsGetValue as usize);
    
    // Time
    exports.insert("Sleep", time::sleep as usize);
    exports.insert("GetTickCount", time::get_tick_count as usize);
    exports.insert("GetTickCount64", time::get_tick_count_64 as usize);
    exports.insert("GetSystemTimeAsFileTime", time::get_system_time_as_file_time as usize);
    exports.insert("QueryPerformanceCounter", time::query_performance_counter as usize);
    exports.insert("QueryPerformanceFrequency", time::query_performance_frequency as usize);

    exports
}
