#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock, RwLock,
};

const ERROR_SUCCESS: i32 = 0;
const ERROR_INVALID_PARAMETER: i32 = 87;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioBackend {
    PipeWire,
    PulseAudio,
    Null,
}

#[derive(Debug, Clone, Copy)]
struct DirectSoundDevice {
    backend: AudioBackend,
}

fn registry() -> &'static RwLock<HashMap<usize, DirectSoundDevice>> {
    static REGISTRY: OnceLock<RwLock<HashMap<usize, DirectSoundDevice>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

fn set_last_error(value: i32) {
    crate::win32::kernel32::error::set_last_error(value as u32);
}

fn next_device_handle() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0xD500_0000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub fn detect_audio_backend() -> AudioBackend {
    if let Ok(backend) = std::env::var("TUXEXE_AUDIO_BACKEND") {
        return match backend.to_ascii_lowercase().as_str() {
            "pipewire" => AudioBackend::PipeWire,
            "pulse" | "pulseaudio" => AudioBackend::PulseAudio,
            _ => AudioBackend::Null,
        };
    }

    if Path::new("/run/pipewire-0").exists() {
        return AudioBackend::PipeWire;
    }

    if std::env::var("PULSE_SERVER").is_ok() {
        return AudioBackend::PulseAudio;
    }

    AudioBackend::Null
}

fn register_device() -> usize {
    let handle = next_device_handle();
    let backend = detect_audio_backend();

    registry()
        .write()
        .expect("directsound registry poisoned")
        .insert(handle, DirectSoundDevice { backend });

    handle
}

pub fn backend_for_device(handle: usize) -> Option<AudioBackend> {
    registry()
        .read()
        .expect("directsound registry poisoned")
        .get(&handle)
        .map(|device| device.backend)
}

pub extern "win64" fn DirectSoundCreate(
    _lpcGuid: *const c_void,
    ppDS: *mut usize,
    _pUnkOuter: *mut c_void,
) -> i32 {
    if ppDS.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }

    unsafe {
        *ppDS = register_device();
    }

    set_last_error(ERROR_SUCCESS);
    ERROR_SUCCESS
}

pub extern "win64" fn DirectSoundCaptureCreate(
    _lpcGuidCapture: *const c_void,
    ppDSCapture: *mut usize,
    _pUnkOuter: *mut c_void,
) -> i32 {
    if ppDSCapture.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }

    unsafe {
        *ppDSCapture = register_device();
    }

    set_last_error(ERROR_SUCCESS);
    ERROR_SUCCESS
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("DirectSoundCreate", DirectSoundCreate as usize);
    exports.insert("DirectSoundCaptureCreate", DirectSoundCaptureCreate as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn env_override_selects_backend() {
        let _guard = serial_guard();
        std::env::set_var("TUXEXE_AUDIO_BACKEND", "pulse");
        assert_eq!(detect_audio_backend(), AudioBackend::PulseAudio);
        std::env::remove_var("TUXEXE_AUDIO_BACKEND");
    }

    #[test]
    fn directsound_create_returns_registered_device() {
        let _guard = serial_guard();
        let mut handle = 0usize;
        let status = DirectSoundCreate(std::ptr::null(), &raw mut handle, std::ptr::null_mut());
        assert_eq!(status, ERROR_SUCCESS);
        assert_ne!(handle, 0);
        assert!(backend_for_device(handle).is_some());
    }
}
