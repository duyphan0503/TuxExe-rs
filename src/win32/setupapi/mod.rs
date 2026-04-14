#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! setupapi.dll stubs.

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn SetupDiGetClassDevsW(
    _ClassGuid: *const u8,
    _Enumerator: *const u16,
    _hwndParent: usize,
    _Flags: u32,
) -> usize {
    trace!("SetupDiGetClassDevsW — stub");
    0
}

extern "win64" fn SetupDiEnumDeviceInfo(
    _DeviceInfoSet: usize,
    _MemberIndex: u32,
    _DeviceInfoData: *mut u8,
) -> i32 {
    trace!("SetupDiEnumDeviceInfo — stub");
    0
}

extern "win64" fn SetupDiGetDeviceRegistryPropertyW(
    _DeviceInfoSet: usize,
    _DeviceInfoData: *mut u8,
    _Property: u32,
    _PropertyRegDataType: *mut u32,
    _PropertyBuffer: *mut u8,
    _PropertyBufferSize: u32,
    _RequiredSize: *mut u32,
) -> i32 {
    trace!("SetupDiGetDeviceRegistryPropertyW — stub");
    0
}

extern "win64" fn SetupDiDestroyDeviceInfoList(_DeviceInfoSet: usize) -> i32 {
    trace!("SetupDiDestroyDeviceInfoList — stub");
    0
}

extern "win64" fn SetupDiEnumDeviceInterfaces(
    _DeviceInfoSet: usize,
    _DeviceInfoData: *mut u8,
    _InterfaceClassGuid: *const u8,
    _MemberIndex: u32,
    _DeviceInterfaceData: *mut u8,
) -> i32 {
    trace!("SetupDiEnumDeviceInterfaces — stub");
    0
}

extern "win64" fn SetupDiGetDeviceInterfaceDetailW(
    _DeviceInfoSet: usize,
    _DeviceInterfaceData: *mut u8,
    _DeviceInterfaceDetailData: *mut u8,
    _DeviceInterfaceDetailDataSize: u32,
    _RequiredSize: *mut u32,
    _DeviceInfoData: *mut u8,
) -> i32 {
    trace!("SetupDiGetDeviceInterfaceDetailW — stub");
    0
}

extern "win64" fn SetupDiGetClassDevsA(
    _ClassGuid: *const u8,
    _Enumerator: *const i8,
    _hwndParent: usize,
    _Flags: u32,
) -> usize {
    trace!("SetupDiGetClassDevsA — stub");
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("SetupDiGetClassDevsW", SetupDiGetClassDevsW as usize);
    exports.insert("SetupDiEnumDeviceInfo", SetupDiEnumDeviceInfo as usize);
    exports.insert("SetupDiGetDeviceRegistryPropertyW", SetupDiGetDeviceRegistryPropertyW as usize);
    exports.insert("SetupDiDestroyDeviceInfoList", SetupDiDestroyDeviceInfoList as usize);
    exports.insert("SetupDiEnumDeviceInterfaces", SetupDiEnumDeviceInterfaces as usize);
    exports.insert("SetupDiGetDeviceInterfaceDetailW", SetupDiGetDeviceInterfaceDetailW as usize);
    exports.insert("SetupDiGetClassDevsA", SetupDiGetClassDevsA as usize);
    exports
}
