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
    exports.insert("CreateFileA", file::create_file_a as usize);
    exports.insert("CreateFileW", file::create_file_w as usize);
    exports.insert("CloseHandle", file::close_handle as usize);
    exports.insert("GetFileSizeEx", file::get_file_size_ex as usize);
    exports.insert("SetFilePointerEx", file::set_file_pointer_ex as usize);
    exports.insert("GetFileAttributesA", file::get_file_attributes_a as usize);
    exports.insert("GetFileAttributesW", file::get_file_attributes_w as usize);
    exports.insert("FindFirstFileA", file::find_first_file_a as usize);
    exports.insert("FindNextFileA", file::find_next_file_a as usize);
    exports.insert("FindClose", file::find_close as usize);

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
    exports.insert("WaitForSingleObject", sync::WaitForSingleObject as usize);
    exports.insert("WaitForMultipleObjects", sync::WaitForMultipleObjects as usize);
    exports.insert("CreateMutexA", sync::CreateMutexA as usize);
    exports.insert("CreateMutexW", sync::CreateMutexW as usize);
    exports.insert("ReleaseMutex", sync::ReleaseMutex as usize);
    exports.insert("CreateEventA", sync::CreateEventA as usize);
    exports.insert("CreateEventW", sync::CreateEventW as usize);
    exports.insert("SetEvent", sync::SetEvent as usize);
    exports.insert("ResetEvent", sync::ResetEvent as usize);
    exports.insert("CreateSemaphoreA", sync::CreateSemaphoreA as usize);
    exports.insert("CreateSemaphoreW", sync::CreateSemaphoreW as usize);
    exports.insert("ReleaseSemaphore", sync::ReleaseSemaphore as usize);

    // Memory
    exports.insert("VirtualAlloc", memory::VirtualAlloc as usize);
    exports.insert("VirtualFree", memory::VirtualFree as usize);
    exports.insert("VirtualProtect", memory::VirtualProtect as usize);
    exports.insert("VirtualQuery", memory::VirtualQuery as usize);
    exports.insert("HeapCreate", memory::HeapCreate as usize);
    exports.insert("HeapAlloc", memory::HeapAlloc as usize);
    exports.insert("HeapFree", memory::HeapFree as usize);
    exports.insert("HeapDestroy", memory::HeapDestroy as usize);
    exports.insert("GetProcessHeap", memory::GetProcessHeap as usize);

    // String
    exports.insert("IsDBCSLeadByteEx", string::IsDBCSLeadByteEx as usize);
    exports.insert("MultiByteToWideChar", string::MultiByteToWideChar as usize);
    exports.insert("WideCharToMultiByte", string::WideCharToMultiByte as usize);

    // Thread
    exports.insert("TlsAlloc", thread::TlsAlloc as usize);
    exports.insert("TlsFree", thread::TlsFree as usize);
    exports.insert("TlsSetValue", thread::TlsSetValue as usize);
    exports.insert("TlsGetValue", thread::TlsGetValue as usize);
    exports.insert("CreateThread", thread::CreateThread as usize);
    exports.insert("ExitThread", thread::ExitThread as usize);
    exports.insert("GetCurrentThread", thread::GetCurrentThread as usize);
    exports.insert("SuspendThread", thread::SuspendThread as usize);
    exports.insert("ResumeThread", thread::ResumeThread as usize);

    // Time
    exports.insert("Sleep", time::sleep as usize);
    exports.insert("GetTickCount", time::get_tick_count as usize);
    exports.insert("GetTickCount64", time::get_tick_count_64 as usize);
    exports.insert("GetSystemTimeAsFileTime", time::get_system_time_as_file_time as usize);
    exports.insert("QueryPerformanceCounter", time::query_performance_counter as usize);
    exports.insert("QueryPerformanceFrequency", time::query_performance_frequency as usize);

    exports
}
