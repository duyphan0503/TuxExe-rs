#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! dbghelp.dll stubs — crash reporting and symbol support for Unity.

use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use tracing::trace;

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

// ─── Symbol Initialization ───

pub extern "win64" fn SymInitialize(
    _hProcess: usize,
    _UserSearchPath: *const u8,
    _fInvadeProcess: i32,
) -> i32 {
    trace!("SymInitialize — stub (returning TRUE)");
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SymCleanup(_hProcess: usize) -> i32 {
    trace!("SymCleanup — stub (returning TRUE)");
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SymGetOptions() -> u32 {
    trace!("SymGetOptions — stub");
    0
}

pub extern "win64" fn SymSetOptions(_SymOptions: u32) -> u32 {
    trace!("SymSetOptions — stub");
    0
}

// ─── Module Loading ───

pub extern "win64" fn SymLoadModule64(
    _hProcess: usize,
    _hFile: usize,
    _ImageName: *const c_char,
    _ModuleName: *const c_char,
    _BaseOfDll: u64,
    _SizeOfDll: u32,
) -> u64 {
    trace!("SymLoadModule64 — stub (returning BaseOfDll)");
    _BaseOfDll
}

pub extern "win64" fn SymLoadModuleExW(
    _hProcess: usize,
    _hFile: usize,
    _ImageName: *const u16,
    _ModuleName: *const u16,
    _BaseOfDll: u64,
    _SizeOfDll: u32,
    _Data: *mut c_void,
    _Flags: u32,
) -> u64 {
    trace!("SymLoadModuleExW — stub (returning BaseOfDll)");
    _BaseOfDll
}

pub extern "win64" fn SymGetModuleBase64(_hProcess: usize, _dwAddr: u64) -> u64 {
    trace!("SymGetModuleBase64 — stub");
    _dwAddr & 0xFFFFFFFFFFF00000 // Return a plausible module base
}

// ─── Module Info ───

#[repr(C)]
pub struct IMAGEHLP_MODULE64 {
    pub SizeOfStruct: u32,
    pub BaseOfImage: u64,
    pub ImageSize: u32,
    pub TimeDateStamp: u32,
    pub CheckSum: u32,
    pub NumSyms: u32,
    pub SymType: u32,
    pub ModuleName: [c_char; 32],
    pub ImageName: [c_char; 256],
    pub LoadedImageName: [c_char; 256],
    pub LoadedPdbName: [c_char; 256],
    pub CVSig: u32,
    pub CVData: [c_char; 772],
    pub PdbSig: u32,
    pub PdbSig70: [u8; 16],
    pub PdbAge: u32,
    pub PdbUnmatched: i32,
    pub DbgUnmatched: i32,
    pub LineNumbers: i32,
    pub GlobalSymbols: i32,
    pub TypeInfo: i32,
    pub SourceIndexed: i32,
    pub Publics: i32,
}

pub extern "win64" fn SymGetModuleInfo64(
    _hProcess: usize,
    dwAddr: u64,
    ModuleInfo: *mut IMAGEHLP_MODULE64,
) -> i32 {
    trace!("SymGetModuleInfo64 — stub (returning TRUE with fake module info)");
    if ModuleInfo.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    unsafe {
        (*ModuleInfo).SizeOfStruct = std::mem::size_of::<IMAGEHLP_MODULE64>() as u32;
        (*ModuleInfo).BaseOfImage = dwAddr & 0xFFFFFFFFFFF00000;
        (*ModuleInfo).ImageSize = 0x2000000;
        (*ModuleInfo).TimeDateStamp = 0;
        (*ModuleInfo).CheckSum = 0;
        (*ModuleInfo).NumSyms = 0;
        (*ModuleInfo).SymType = 3; // SymNone
        (*ModuleInfo).ModuleName[0] = 0;
        (*ModuleInfo).ImageName[0] = 0;
        (*ModuleInfo).LoadedImageName[0] = 0;
        (*ModuleInfo).LoadedPdbName[0] = 0;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

// ─── Symbol Lookup ───

pub extern "win64" fn SymFromAddr(
    _hProcess: usize,
    _Address: u64,
    _Displacement: *mut u64,
    _Symbol: *mut c_void,
) -> i32 {
    trace!("SymFromAddr — stub (returning FALSE - no symbols)");
    0
}

pub extern "win64" fn SymGetSymFromAddr64(
    _hProcess: usize,
    _dwAddr: u64,
    _pdwDisplacement: *mut u64,
    _pSymbol: *mut c_void,
) -> i32 {
    trace!("SymGetSymFromAddr64 — stub (returning FALSE - no symbols)");
    0
}

pub extern "win64" fn SymGetLineFromAddr64(
    _hProcess: usize,
    _dwAddr: u64,
    _pdwDisplacement: *mut u32,
    _Line: *mut c_void,
) -> i32 {
    trace!("SymGetLineFromAddr64 — stub (returning FALSE)");
    0
}

// ─── Stack Walking ───

pub extern "win64" fn StackWalk64(
    _MachineType: u32,
    _hProcess: usize,
    _hThread: usize,
    _StackFrame: *mut c_void,
    _ContextRecord: *mut c_void,
    _ReadMemoryRoutine: *mut c_void,
    _FunctionTableAccessRoutine: *mut c_void,
    _GetModuleBaseRoutine: *mut c_void,
    _TranslateAddress: *mut c_void,
) -> i32 {
    trace!("StackWalk64 — stub (returning FALSE)");
    0
}

pub extern "win64" fn SymFunctionTableAccess64(_hProcess: usize, _AddrBase: u64) -> *mut c_void {
    trace!("SymFunctionTableAccess64 — stub");
    std::ptr::null_mut()
}

// ─── Search Path ───

pub extern "win64" fn SymGetSearchPath(
    _hProcess: usize,
    _SearchPath: *mut c_char,
    _SearchPathLength: u32,
) -> i32 {
    trace!("SymGetSearchPath — stub (returning FALSE)");
    0
}

pub extern "win64" fn SymSetSearchPath(_hProcess: usize, _SearchPath: *const c_char) -> i32 {
    trace!("SymSetSearchPath — stub (returning TRUE)");
    set_last_error(ERROR_SUCCESS);
    1
}

// ─── Name Undecoration ───

pub extern "win64" fn UnDecorateSymbolName(
    _DecoratedName: *const c_char,
    _OutputString: *mut c_char,
    _UndecoratedLength: u32,
    _Flags: u32,
) -> u32 {
    trace!("UnDecorateSymbolName — stub (returning 0)");
    0
}

// ─── MiniDump ───

pub extern "win64" fn MiniDumpWriteDump(
    _hProcess: usize,
    _ProcessId: u32,
    _hFile: usize,
    _DumpType: u32,
    _ExceptionParam: *mut c_void,
    _UserStreamParam: *mut c_void,
    _CallbackParam: *mut c_void,
) -> i32 {
    trace!("MiniDumpWriteDump — stub (returning FALSE)");
    0
}

// ─── Export Table ───

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("SymInitialize", SymInitialize as usize);
    exports.insert("SymCleanup", SymCleanup as usize);
    exports.insert("SymGetOptions", SymGetOptions as usize);
    exports.insert("SymSetOptions", SymSetOptions as usize);
    exports.insert("SymFunctionTableAccess64", SymFunctionTableAccess64 as usize);
    exports.insert("SymGetModuleBase64", SymGetModuleBase64 as usize);
    exports.insert("StackWalk64", StackWalk64 as usize);
    exports.insert("MiniDumpWriteDump", MiniDumpWriteDump as usize);
    exports.insert("SymFromAddr", SymFromAddr as usize);
    exports.insert("SymGetLineFromAddr64", SymGetLineFromAddr64 as usize);
    exports.insert("SymGetModuleInfo64", SymGetModuleInfo64 as usize);
    exports.insert("SymGetSymFromAddr64", SymGetSymFromAddr64 as usize);
    exports.insert("UnDecorateSymbolName", UnDecorateSymbolName as usize);
    exports.insert("SymLoadModule64", SymLoadModule64 as usize);
    exports.insert("SymGetSearchPath", SymGetSearchPath as usize);
    exports.insert("SymLoadModuleExW", SymLoadModuleExW as usize);
    exports.insert("SymSetSearchPath", SymSetSearchPath as usize);
    exports
}
