#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = -1073741811; // 0xC000000D

fn prng_state() -> &'static AtomicU64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    &STATE
}

fn next_u64() -> u64 {
    let state = prng_state();
    let mut current = state.load(Ordering::Relaxed);

    if current == 0 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        current = nanos ^ 0xA5A5_5A5A_C3C3_3C3C;
        if current == 0 {
            current = 0x6A09_E667_F3BC_C908;
        }
    }

    loop {
        let mut x = current;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x == 0 {
            x = 0xBB67_AE85_84CA_A73B;
        }

        match state.compare_exchange(current, x, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return x,
            Err(observed) => current = observed,
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn BCryptGenRandom(
    _hAlgorithm: usize,
    pbBuffer: *mut u8,
    cbBuffer: u32,
    _dwFlags: u32,
) -> i32 {
    if cbBuffer == 0 {
        return STATUS_SUCCESS;
    }

    if pbBuffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let out = unsafe { std::slice::from_raw_parts_mut(pbBuffer, cbBuffer as usize) };
    let mut offset = 0usize;
    while offset < out.len() {
        let block = next_u64().to_le_bytes();
        let remaining = out.len() - offset;
        let to_copy = remaining.min(block.len());
        out[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
        offset += to_copy;
    }

    STATUS_SUCCESS
}

pub extern "win64" fn BCryptOpenAlgorithmProvider(
    phAlgorithm: *mut usize,
    _pszAlgId: *const u16,
    _pszImplementation: *const u16,
    _dwFlags: u32,
) -> i32 {
    if !phAlgorithm.is_null() {
        unsafe {
            *phAlgorithm = 0xBC00_0001;
        }
    }
    STATUS_SUCCESS
}

pub extern "win64" fn BCryptCloseAlgorithmProvider(
    _hAlgorithm: usize,
    _dwFlags: u32,
) -> i32 {
    STATUS_SUCCESS
}

pub extern "win64" fn BCryptGetProperty(
    _hObject: usize,
    _pszProperty: *const u16,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    pcbResult: *mut u32,
    _dwFlags: u32,
) -> i32 {
    if !pcbResult.is_null() {
        unsafe {
            *pcbResult = 0;
        }
    }
    STATUS_SUCCESS
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("BCryptGenRandom", BCryptGenRandom as usize);
    exports.insert("BCryptOpenAlgorithmProvider", BCryptOpenAlgorithmProvider as usize);
    exports.insert("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider as usize);
    exports.insert("BCryptGetProperty", BCryptGetProperty as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcrypt_gen_random_fills_requested_buffer() {
        let mut bytes = [0u8; 32];
        let status = BCryptGenRandom(0, bytes.as_mut_ptr(), bytes.len() as u32, 0);
        assert_eq!(status, STATUS_SUCCESS);
        assert!(bytes.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn bcrypt_gen_random_rejects_null_output_with_nonzero_size() {
        let status = BCryptGenRandom(0, std::ptr::null_mut(), 16, 0);
        assert_eq!(status, STATUS_INVALID_PARAMETER);
    }
}
