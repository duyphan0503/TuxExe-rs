#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! hid.dll stubs.

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn HidD_GetHidGuid(_HidGuid: *mut u8) {
    trace!("HidD_GetHidGuid — stub");
    if !_HidGuid.is_null() {
        unsafe {
            std::ptr::write_bytes(_HidGuid, 0, 16);
        }
    }
}

extern "win64" fn HidD_GetAttributes(_HidDeviceObject: usize, _Attributes: *mut u8) -> i32 {
    trace!("HidD_GetAttributes — stub");
    0
}

extern "win64" fn HidD_GetPreparsedData(
    _HidDeviceObject: usize,
    _PreparsedData: *mut usize,
) -> i32 {
    trace!("HidD_GetPreparsedData — stub");
    0
}

extern "win64" fn HidD_FreePreparsedData(_PreparsedData: usize) -> i32 {
    trace!("HidD_FreePreparsedData — stub");
    0
}

extern "win64" fn HidD_GetProductString(
    _HidDeviceObject: usize,
    _Buffer: *mut u8,
    _BufferLength: u32,
) -> i32 {
    trace!("HidD_GetProductString — stub");
    0
}

extern "win64" fn HidD_GetManufacturerString(
    _HidDeviceObject: usize,
    _Buffer: *mut u8,
    _BufferLength: u32,
) -> i32 {
    trace!("HidD_GetManufacturerString — stub");
    0
}

extern "win64" fn HidD_GetSerialNumberString(
    _HidDeviceObject: usize,
    _Buffer: *mut u8,
    _BufferLength: u32,
) -> i32 {
    trace!("HidD_GetSerialNumberString — stub");
    0
}

extern "win64" fn HidP_GetCaps(_PreparsedData: usize, _Capabilities: *mut u8) -> i32 {
    trace!("HidP_GetCaps — stub");
    0
}

extern "win64" fn HidP_GetButtonCaps(
    _ReportType: u16,
    _ButtonCaps: *mut u8,
    _ButtonCapsLength: *mut u16,
    _PreparsedData: usize,
) -> i32 {
    trace!("HidP_GetButtonCaps — stub");
    0
}

extern "win64" fn HidP_GetValueCaps(
    _ReportType: u16,
    _ValueCaps: *mut u8,
    _ValueCapsLength: *mut u16,
    _PreparsedData: usize,
) -> i32 {
    trace!("HidP_GetValueCaps — stub");
    0
}

extern "win64" fn HidP_GetData(
    _ReportType: u16,
    _DataList: *mut u8,
    _DataLength: *mut u32,
    _PreparsedData: usize,
    _Report: *mut u8,
    _ReportLength: u32,
) -> i32 {
    trace!("HidP_GetData — stub");
    0
}

extern "win64" fn HidP_MaxDataListLength(_ReportType: u16, _PreparsedData: usize) -> u32 {
    trace!("HidP_MaxDataListLength — stub");
    0
}

extern "win64" fn HidP_SetUsageValue(
    _ReportType: u16,
    _UsagePage: u16,
    _LinkCollection: u16,
    _Usage: u16,
    _UsageValue: u32,
    _PreparsedData: usize,
    _Report: *mut u8,
    _ReportLength: u32,
) -> i32 {
    trace!("HidP_SetUsageValue — stub");
    0
}

extern "win64" fn HidP_SetUsages(
    _ReportType: u16,
    _UsagePage: u16,
    _LinkCollection: u16,
    _UsageList: *mut u16,
    _UsageLength: *mut u32,
    _PreparsedData: usize,
    _Report: *mut u8,
    _ReportLength: u32,
) -> i32 {
    trace!("HidP_SetUsages — stub");
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("HidD_GetHidGuid", HidD_GetHidGuid as usize);
    exports.insert("HidD_GetAttributes", HidD_GetAttributes as usize);
    exports.insert("HidD_GetPreparsedData", HidD_GetPreparsedData as usize);
    exports.insert("HidD_FreePreparsedData", HidD_FreePreparsedData as usize);
    exports.insert("HidD_GetProductString", HidD_GetProductString as usize);
    exports.insert("HidD_GetManufacturerString", HidD_GetManufacturerString as usize);
    exports.insert("HidD_GetSerialNumberString", HidD_GetSerialNumberString as usize);
    exports.insert("HidP_GetCaps", HidP_GetCaps as usize);
    exports.insert("HidP_GetButtonCaps", HidP_GetButtonCaps as usize);
    exports.insert("HidP_GetValueCaps", HidP_GetValueCaps as usize);
    exports.insert("HidP_GetData", HidP_GetData as usize);
    exports.insert("HidP_MaxDataListLength", HidP_MaxDataListLength as usize);
    exports.insert("HidP_SetUsageValue", HidP_SetUsageValue as usize);
    exports.insert("HidP_SetUsages", HidP_SetUsages as usize);
    exports
}
