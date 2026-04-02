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
    exports.insert("SetStdHandle", console::set_std_handle as usize);
    exports.insert("WriteConsoleA", console::write_console_a as usize);
    exports.insert("WriteConsoleW", console::write_console_w as usize);
    exports.insert("GetConsoleCP", console::get_console_cp as usize);
    exports.insert("GetConsoleMode", console::get_console_mode as usize);

    // File
    exports.insert("WriteFile", file::write_file as usize);
    exports.insert("ReadFile", file::read_file as usize);
    exports.insert("CreateFileA", file::create_file_a as usize);
    exports.insert("CreateFileW", file::create_file_w as usize);
    exports.insert("CreateDirectoryA", file::create_directory_a as usize);
    exports.insert("CreateDirectoryW", file::create_directory_w as usize);
    exports.insert("RemoveDirectoryA", file::remove_directory_a as usize);
    exports.insert("RemoveDirectoryW", file::remove_directory_w as usize);
    exports.insert("DeleteFileA", file::delete_file_a as usize);
    exports.insert("DeleteFileW", file::delete_file_w as usize);
    exports.insert("CopyFileA", file::copy_file_a as usize);
    exports.insert("CopyFileW", file::copy_file_w as usize);
    exports.insert("MoveFileA", file::move_file_a as usize);
    exports.insert("MoveFileW", file::move_file_w as usize);
    exports.insert("MoveFileExA", file::move_file_ex_a as usize);
    exports.insert("MoveFileExW", file::move_file_ex_w as usize);
    exports.insert("ReplaceFileA", file::replace_file_a as usize);
    exports.insert("ReplaceFileW", file::replace_file_w as usize);
    exports.insert("GetTempPathA", file::get_temp_path_a as usize);
    exports.insert("GetTempPathW", file::get_temp_path_w as usize);
    exports.insert("GetTempFileNameA", file::get_temp_file_name_a as usize);
    exports.insert("GetTempFileNameW", file::get_temp_file_name_w as usize);
    exports.insert("GetDiskFreeSpaceExA", file::get_disk_free_space_ex_a as usize);
    exports.insert("GetDiskFreeSpaceExW", file::get_disk_free_space_ex_w as usize);
    exports.insert("GetDiskFreeSpaceA", file::get_disk_free_space_a as usize);
    exports.insert("GetDiskFreeSpaceW", file::get_disk_free_space_w as usize);
    exports.insert("CloseHandle", file::close_handle as usize);
    exports.insert("GetFileType", file::get_file_type as usize);
    exports.insert("GetFileSizeEx", file::get_file_size_ex as usize);
    exports.insert("SetFilePointer", file::set_file_pointer as usize);
    exports.insert("SetFilePointerEx", file::set_file_pointer_ex as usize);
    exports.insert("GetFileAttributesA", file::get_file_attributes_a as usize);
    exports.insert("K32GetProcessMemoryInfo", process::k32_get_process_memory_info as usize);
    exports.insert("GetFileAttributesW", file::get_file_attributes_w as usize);
    exports.insert("SetFileAttributesA", file::set_file_attributes_a as usize);
    exports.insert("SetFileAttributesW", file::set_file_attributes_w as usize);
    exports.insert("GetFileAttributesExA", file::get_file_attributes_ex_a as usize);
    exports.insert("GetFileAttributesExW", file::get_file_attributes_ex_w as usize);
    exports.insert("FlushFileBuffers", file::flush_file_buffers as usize);
    exports.insert("SetEndOfFile", file::set_end_of_file as usize);
    exports.insert("SetFileTime", file::set_file_time as usize);
    exports.insert("FindFirstFileA", file::find_first_file_a as usize);
    exports.insert("FindFirstFileW", file::find_first_file_w as usize);
    exports.insert("FindFirstFileExA", file::find_first_file_ex_a as usize);
    exports.insert("FindFirstFileExW", file::find_first_file_ex_w as usize);
    exports.insert("FindNextFileA", file::find_next_file_a as usize);
    exports.insert("FindNextFileW", file::find_next_file_w as usize);
    exports.insert("FindClose", file::find_close as usize);

    // Process
    exports.insert("ExitProcess", process::exit_process as usize);
    exports.insert("GetModuleHandleA", process::get_module_handle_a as usize);
    exports.insert("GetModuleHandleW", process::get_module_handle_w as usize);
    exports.insert("GetModuleHandleExA", process::get_module_handle_ex_a as usize);
    exports.insert("GetModuleHandleExW", process::get_module_handle_ex_w as usize);
    exports.insert("GetModuleFileNameA", process::get_module_file_name_a as usize);
    exports.insert("GetModuleFileNameW", process::get_module_file_name_w as usize);
    exports.insert("LoadLibraryA", process::load_library_a as usize);
    exports.insert("LoadLibraryW", process::load_library_w as usize);
    exports.insert("LoadLibraryExA", process::load_library_ex_a as usize);
    exports.insert("LoadLibraryExW", process::load_library_ex_w as usize);
    exports.insert("FreeLibrary", process::free_library_api as usize);
    exports.insert("GetProcAddress", process::get_proc_address as usize);
    exports.insert("GetCommandLineA", process::get_command_line_a as usize);
    exports.insert("GetCommandLineW", process::get_command_line_w as usize);
    exports.insert("GetEnvironmentStringsA", process::get_environment_strings_a as usize);
    exports.insert("GetEnvironmentStringsW", process::get_environment_strings_w as usize);
    exports.insert("FreeEnvironmentStringsA", process::free_environment_strings_a as usize);
    exports.insert("FreeEnvironmentStringsW", process::free_environment_strings_w as usize);
    exports.insert("GetEnvironmentVariableA", process::get_environment_variable_a as usize);
    exports.insert("GetEnvironmentVariableW", process::get_environment_variable_w as usize);
    exports.insert("ExpandEnvironmentStringsA", process::expand_environment_strings_a as usize);
    exports.insert("ExpandEnvironmentStringsW", process::expand_environment_strings_w as usize);
    exports.insert("GetStartupInfoA", process::get_startup_info_a as usize);
    exports.insert("GetStartupInfoW", process::get_startup_info_w as usize);
    exports.insert("GetCurrentProcess", process::get_current_process as usize);
    exports.insert("GetCurrentProcessId", process::get_current_process_id as usize);
    exports.insert("GetProcessId", process::get_process_id as usize);
    exports.insert("TerminateProcess", process::terminate_process as usize);
    exports.insert("GetCurrentThreadId", process::get_current_thread_id as usize);
    exports.insert("GetSystemPowerStatus", process::get_system_power_status as usize);
    exports.insert("GetCurrentDirectoryA", process::get_current_directory_a as usize);
    exports.insert("GetCurrentDirectoryW", process::get_current_directory_w as usize);
    exports.insert("CreateToolhelp32Snapshot", process::create_toolhelp32_snapshot as usize);
    exports.insert("Process32FirstW", process::process32_first_w as usize);
    exports.insert("Process32NextW", process::process32_next_w as usize);
    exports.insert("Process32First", process::process32_first_a as usize);
    exports.insert("Process32Next", process::process32_next_a as usize);
    exports.insert("SetDllDirectoryW", process::set_dll_directory_w as usize);
    exports.insert("GetComputerNameW", process::get_computer_name_w as usize);
    exports.insert(
        "InitializeProcThreadAttributeList",
        process::initialize_proc_thread_attribute_list as usize,
    );
    exports.insert(
        "DeleteProcThreadAttributeList",
        process::delete_proc_thread_attribute_list as usize,
    );
    exports.insert("UpdateProcThreadAttribute", process::update_proc_thread_attribute as usize);
    exports.insert("CreateProcessW", process::create_process_w as usize);
    exports.insert("EncodePointer", process::encode_pointer as usize);
    exports.insert("DecodePointer", process::decode_pointer as usize);
    exports.insert("OutputDebugStringA", process::output_debug_string_a as usize);
    exports.insert("DebugBreak", process::debug_break as usize);
    exports.insert("SwitchToThread", process::switch_to_thread as usize);
    exports.insert("SleepEx", process::sleep_ex as usize);
    exports.insert("IsDebuggerPresent", process::is_debugger_present as usize);
    exports.insert("IsProcessorFeaturePresent", process::is_processor_feature_present as usize);
    exports.insert("RtlCaptureContext", process::rtl_capture_context as usize);
    exports.insert("RtlLookupFunctionEntry", process::rtl_lookup_function_entry as usize);
    exports.insert("RtlVirtualUnwind", process::rtl_virtual_unwind as usize);
    exports.insert("RtlUnwindEx", process::rtl_unwind_ex as usize);
    exports.insert("RtlUnwind", process::rtl_unwind as usize);

    // Error
    exports.insert("GetLastError", error::get_last_error as usize);
    exports.insert("SetLastError", error::set_last_error as usize);
    exports.insert("RaiseException", error::raise_exception as usize);
    exports.insert("SetUnhandledExceptionFilter", error::set_unhandled_exception_filter as usize);
    exports.insert("UnhandledExceptionFilter", error::unhandled_exception_filter as usize);

    // Sync
    exports.insert("InitializeCriticalSection", sync::InitializeCriticalSection as usize);
    exports.insert(
        "InitializeCriticalSectionAndSpinCount",
        sync::InitializeCriticalSectionAndSpinCount as usize,
    );
    exports.insert("InitializeCriticalSectionEx", sync::InitializeCriticalSectionEx as usize);
    exports.insert("EnterCriticalSection", sync::EnterCriticalSection as usize);
    exports.insert("LeaveCriticalSection", sync::LeaveCriticalSection as usize);
    exports.insert("DeleteCriticalSection", sync::DeleteCriticalSection as usize);
    exports.insert("WaitForSingleObject", sync::WaitForSingleObject as usize);
    exports.insert("WaitForMultipleObjects", sync::WaitForMultipleObjects as usize);
    exports.insert("WaitForSingleObjectEx", sync::WaitForSingleObjectEx as usize);
    exports.insert("WaitForMultipleObjectsEx", sync::WaitForMultipleObjectsEx as usize);
    exports.insert("CreateMutexA", sync::CreateMutexA as usize);
    exports.insert("CreateMutexW", sync::CreateMutexW as usize);
    exports.insert("ReleaseMutex", sync::ReleaseMutex as usize);
    exports.insert("CreateEventA", sync::CreateEventA as usize);
    exports.insert("CreateEventW", sync::CreateEventW as usize);
    exports.insert("CreateEventExW", sync::CreateEventExW as usize);
    exports.insert("SetEvent", sync::SetEvent as usize);
    exports.insert("ResetEvent", sync::ResetEvent as usize);
    exports.insert("CreateSemaphoreA", sync::CreateSemaphoreA as usize);
    exports.insert("CreateSemaphoreW", sync::CreateSemaphoreW as usize);
    exports.insert("CreateSemaphoreExW", sync::CreateSemaphoreExW as usize);
    exports.insert("ReleaseSemaphore", sync::ReleaseSemaphore as usize);
    exports.insert("InitializeSListHead", sync::InitializeSListHead as usize);
    exports.insert("InterlockedPushEntrySList", sync::InterlockedPushEntrySList as usize);
    exports.insert("InterlockedPopEntrySList", sync::InterlockedPopEntrySList as usize);
    exports.insert("InterlockedFlushSList", sync::InterlockedFlushSList as usize);
    exports.insert("QueryDepthSList", sync::QueryDepthSList as usize);

    // Memory
    exports.insert("VirtualAlloc", memory::VirtualAlloc as usize);
    exports.insert("VirtualFree", memory::VirtualFree as usize);
    exports.insert("VirtualProtect", memory::VirtualProtect as usize);
    exports.insert("VirtualQuery", memory::VirtualQuery as usize);
    exports.insert("HeapCreate", memory::HeapCreate as usize);
    exports.insert("HeapAlloc", memory::HeapAlloc as usize);
    exports.insert("HeapFree", memory::HeapFree as usize);
    exports.insert("HeapReAlloc", memory::HeapReAlloc as usize);
    exports.insert("HeapSize", memory::HeapSize as usize);
    exports.insert("HeapReAlloc", memory::HeapReAlloc as usize);
    exports.insert("HeapSize", memory::HeapSize as usize);
    exports.insert("HeapDestroy", memory::HeapDestroy as usize);
    exports.insert("GetProcessHeap", memory::GetProcessHeap as usize);
    exports.insert("GlobalAlloc", memory::GlobalAlloc as usize);
    exports.insert("GlobalFree", memory::GlobalFree as usize);
    exports.insert("GlobalLock", memory::GlobalLock as usize);
    exports.insert("GlobalUnlock", memory::GlobalUnlock as usize);
    exports.insert("GlobalReAlloc", memory::GlobalReAlloc as usize);
    exports.insert("GlobalSize", memory::GlobalSize as usize);
    exports.insert("GlobalFlags", memory::GlobalFlags as usize);
    exports.insert("GlobalHandle", memory::GlobalHandle as usize);
    exports.insert("LocalAlloc", memory::LocalAlloc as usize);
    exports.insert("LocalReAlloc", memory::LocalReAlloc as usize);
    exports.insert("LocalLock", memory::LocalLock as usize);
    exports.insert("LocalUnlock", memory::LocalUnlock as usize);
    exports.insert("LocalSize", memory::LocalSize as usize);
    exports.insert("LocalFlags", memory::LocalFlags as usize);
    exports.insert("LocalHandle", memory::LocalHandle as usize);
    exports.insert("LocalFree", memory::LocalFree as usize);
    exports.insert("CreateFileMappingA", memory::CreateFileMappingA as usize);
    exports.insert("CreateFileMappingW", memory::CreateFileMappingW as usize);
    exports.insert("MapViewOfFile", memory::MapViewOfFile as usize);
    exports.insert("UnmapViewOfFile", memory::UnmapViewOfFile as usize);

    // String
    exports.insert("IsDBCSLeadByteEx", string::IsDBCSLeadByteEx as usize);
    exports.insert("IsValidCodePage", string::IsValidCodePage as usize);
    exports.insert("GetACP", string::GetACP as usize);
    exports.insert("GetOEMCP", string::GetOEMCP as usize);
    exports.insert("GetCPInfo", string::GetCPInfo as usize);
    exports.insert("GetStringTypeW", string::GetStringTypeW as usize);
    exports.insert("LCMapStringW", string::LCMapStringW as usize);
    exports.insert("CompareStringW", string::CompareStringW as usize);
    exports.insert("GetLocaleInfoW", string::GetLocaleInfoW as usize);
    exports.insert("EnumSystemLocalesA", string::EnumSystemLocalesA as usize);
    exports.insert("EnumSystemLocalesW", string::EnumSystemLocalesW as usize);
    exports.insert("IsValidLocale", string::IsValidLocale as usize);
    exports.insert("GetUserDefaultLocaleName", string::GetUserDefaultLocaleName as usize);
    exports.insert("GetUserDefaultLCID", string::GetUserDefaultLCID as usize);
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
    exports.insert("GetSystemTime", time::get_system_time as usize);
    exports.insert("GetLocalTime", time::get_local_time as usize);
    exports.insert("GetTickCount", time::get_tick_count as usize);
    exports.insert("GetTickCount64", time::get_tick_count_64 as usize);
    exports.insert("GetSystemTimeAsFileTime", time::get_system_time_as_file_time as usize);
    exports.insert("QueryPerformanceCounter", time::query_performance_counter as usize);
    exports.insert("QueryPerformanceFrequency", time::query_performance_frequency as usize);

    exports
}
