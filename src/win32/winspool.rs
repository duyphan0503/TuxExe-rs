//! WINSPOOL.DRV implementation

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn GetDefaultPrinterA(_buffer: *mut i8, _pcch_buffer: *mut u32) -> i32 {
    trace!("GetDefaultPrinterA stub called");
    0
}

extern "win64" fn GetDefaultPrinterW(_buffer: *mut u16, _pcch_buffer: *mut u32) -> i32 {
    trace!("GetDefaultPrinterW stub called");
    0
}

extern "win64" fn OpenPrinterA(_printer_name: *const i8, ph_printer: *mut usize, _p_defaults: *const u8) -> i32 {
    trace!("OpenPrinterA stub called");
    if !ph_printer.is_null() {
        unsafe { *ph_printer = 0; }
    }
    0
}

extern "win64" fn OpenPrinterW(_printer_name: *const u16, ph_printer: *mut usize, _p_defaults: *const u8) -> i32 {
    trace!("OpenPrinterW stub called");
    if !ph_printer.is_null() {
        unsafe { *ph_printer = 0; }
    }
    0
}

extern "win64" fn ClosePrinter(_h_printer: usize) -> i32 {
    trace!("ClosePrinter stub called");
    1
}

extern "win64" fn EnumPrintersA(
    _flags: u32,
    _name: *const i8,
    _level: u32,
    _p_printer_enum: *mut u8,
    _cb_buf: u32,
    pcb_needed: *mut u32,
    pc_returned: *mut u32,
) -> i32 {
    if !pcb_needed.is_null() {
        unsafe { *pcb_needed = 0; }
    }
    if !pc_returned.is_null() {
        unsafe { *pc_returned = 0; }
    }
    0
}

extern "win64" fn EnumPrintersW(
    _flags: u32,
    _name: *const u16,
    _level: u32,
    _p_printer_enum: *mut u8,
    _cb_buf: u32,
    pcb_needed: *mut u32,
    pc_returned: *mut u32,
) -> i32 {
    if !pcb_needed.is_null() {
        unsafe { *pcb_needed = 0; }
    }
    if !pc_returned.is_null() {
        unsafe { *pc_returned = 0; }
    }
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("GetDefaultPrinterA", GetDefaultPrinterA as usize);
    exports.insert("GetDefaultPrinterW", GetDefaultPrinterW as usize);
    exports.insert("OpenPrinterA", OpenPrinterA as usize);
    exports.insert("OpenPrinterW", OpenPrinterW as usize);
    exports.insert("ClosePrinter", ClosePrinter as usize);
    exports.insert("EnumPrintersA", EnumPrintersA as usize);
    exports.insert("EnumPrintersW", EnumPrintersW as usize);
    exports
}
