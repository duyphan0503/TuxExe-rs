#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Minimal winmm.dll stubs for Unity games.

use std::collections::HashMap;
use tracing::trace;

extern "win64" fn timeGetTime() -> u32 {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (ts.as_millis() & 0xFFFFFFFF) as u32
}

extern "win64" fn timeBeginPeriod(_uPeriod: u32) -> u32 {
    trace!("timeBeginPeriod({}) — stub", _uPeriod);
    0 // TIMERR_NOERROR
}

extern "win64" fn timeEndPeriod(_uPeriod: u32) -> u32 {
    trace!("timeEndPeriod({}) — stub", _uPeriod);
    0
}

extern "win64" fn waveOutGetNumDevs() -> u32 {
    trace!("waveOutGetNumDevs — stub");
    0
}

extern "win64" fn waveOutGetDevCapsW(_uDeviceID: usize, _pwoc: *mut u8, _cbwoc: u32) -> u32 {
    trace!("waveOutGetDevCapsW — stub");
    1 // MMSYSERR_ERROR
}

extern "win64" fn waveOutGetDevCapsA(_uDeviceID: usize, _pwoc: *mut u8, _cbwoc: u32) -> u32 {
    trace!("waveOutGetDevCapsA — stub");
    1
}

extern "win64" fn waveOutOpen(
    _phwo: *mut usize,
    _uDeviceID: u32,
    _pwfx: *mut u8,
    _dwCallback: usize,
    _dwInstance: usize,
    _fdwOpen: u32,
) -> u32 {
    trace!("waveOutOpen — stub");
    if !_phwo.is_null() {
        unsafe {
            *_phwo = 0;
        }
    }
    1
}

extern "win64" fn waveOutClose(_hwo: usize) -> u32 {
    trace!("waveOutClose — stub");
    0
}

extern "win64" fn waveOutPrepareHeader(_hwo: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    trace!("waveOutPrepareHeader — stub");
    0
}

extern "win64" fn waveOutWrite(_hwo: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    trace!("waveOutWrite — stub");
    0
}

extern "win64" fn waveOutUnprepareHeader(_hwo: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    trace!("waveOutUnprepareHeader — stub");
    0
}

extern "win64" fn waveOutReset(_hwo: usize) -> u32 {
    trace!("waveOutReset — stub");
    0
}

extern "win64" fn waveOutGetPosition(_hwo: usize, _pmmt: *mut u8, _cbmmt: u32) -> u32 {
    trace!("waveOutGetPosition — stub");
    0
}

extern "win64" fn waveOutGetErrorTextW(_mmr: u32, _pszText: *mut u16, _cchText: u32) -> u32 {
    trace!("waveOutGetErrorTextW — stub");
    0
}

extern "win64" fn waveInGetNumDevs() -> u32 {
    trace!("waveInGetNumDevs — stub");
    0
}

extern "win64" fn waveInGetDevCapsW(_uDeviceID: usize, _pwic: *mut u8, _cbwic: u32) -> u32 {
    trace!("waveInGetDevCapsW — stub");
    1
}

extern "win64" fn waveInGetDevCapsA(_uDeviceID: usize, _pwic: *mut u8, _cbwic: u32) -> u32 {
    trace!("waveInGetDevCapsA — stub");
    1
}

extern "win64" fn waveInOpen(
    _phwi: *mut usize,
    _uDeviceID: u32,
    _pwfx: *mut u8,
    _dwCallback: usize,
    _dwInstance: usize,
    _fdwOpen: u32,
) -> u32 {
    trace!("waveInOpen — stub");
    if !_phwi.is_null() {
        unsafe {
            *_phwi = 0;
        }
    }
    1
}

extern "win64" fn waveInClose(_hwi: usize) -> u32 {
    trace!("waveInClose — stub");
    0
}

extern "win64" fn waveInPrepareHeader(_hwi: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    trace!("waveInPrepareHeader — stub");
    0
}

extern "win64" fn waveInAddBuffer(_hwi: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    trace!("waveInAddBuffer — stub");
    0
}

extern "win64" fn waveInStart(_hwi: usize) -> u32 {
    trace!("waveInStart — stub");
    0
}

extern "win64" fn waveInReset(_hwi: usize) -> u32 {
    trace!("waveInReset — stub");
    0
}

extern "win64" fn waveInUnprepareHeader(_hwi: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    trace!("waveInUnprepareHeader — stub");
    0
}

extern "win64" fn midiOutGetNumDevs() -> u32 {
    trace!("midiOutGetNumDevs — stub");
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("timeGetTime", timeGetTime as usize);
    exports.insert("timeBeginPeriod", timeBeginPeriod as usize);
    exports.insert("timeEndPeriod", timeEndPeriod as usize);
    exports.insert("waveOutGetNumDevs", waveOutGetNumDevs as usize);
    exports.insert("waveOutGetDevCapsW", waveOutGetDevCapsW as usize);
    exports.insert("waveOutGetDevCapsA", waveOutGetDevCapsA as usize);
    exports.insert("waveOutOpen", waveOutOpen as usize);
    exports.insert("waveOutClose", waveOutClose as usize);
    exports.insert("waveOutPrepareHeader", waveOutPrepareHeader as usize);
    exports.insert("waveOutWrite", waveOutWrite as usize);
    exports.insert("waveOutUnprepareHeader", waveOutUnprepareHeader as usize);
    exports.insert("waveOutReset", waveOutReset as usize);
    exports.insert("waveOutGetPosition", waveOutGetPosition as usize);
    exports.insert("waveOutGetErrorTextW", waveOutGetErrorTextW as usize);
    exports.insert("waveInGetNumDevs", waveInGetNumDevs as usize);
    exports.insert("waveInGetDevCapsW", waveInGetDevCapsW as usize);
    exports.insert("waveInGetDevCapsA", waveInGetDevCapsA as usize);
    exports.insert("waveInOpen", waveInOpen as usize);
    exports.insert("waveInClose", waveInClose as usize);
    exports.insert("waveInPrepareHeader", waveInPrepareHeader as usize);
    exports.insert("waveInAddBuffer", waveInAddBuffer as usize);
    exports.insert("waveInStart", waveInStart as usize);
    exports.insert("waveInReset", waveInReset as usize);
    exports.insert("waveInUnprepareHeader", waveInUnprepareHeader as usize);
    exports.insert("midiOutGetNumDevs", midiOutGetNumDevs as usize);
    exports
}
