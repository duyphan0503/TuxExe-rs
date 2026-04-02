//! UTF-16LE ↔ UTF-8 conversion utilities.
//!
//! Windows APIs use `LPCWSTR` / `LPWSTR` — 16-bit little-endian Unicode strings.
//! This module provides ergonomic, well-tested conversion between UTF-16LE byte
//! slices and Rust `String`s (UTF-8).

use std::ffi::OsString;

/// Error type for wide-string conversion failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WideStringError {
    /// Byte slice length is odd — UTF-16LE requires an even number of bytes.
    #[error("UTF-16LE byte slice has odd length ({0})")]
    OddLength(usize),

    /// The UTF-16 code unit sequence is not valid Unicode.
    #[error("Invalid UTF-16 sequence: {0}")]
    InvalidUtf16(#[from] std::char::DecodeUtf16Error),

    /// An interior null was encountered at string position {0}.
    #[error("Interior null code unit at position {0}")]
    InteriorNull(usize),
}

// ── UTF-16LE bytes → Rust String ──────────────────────────────────────────────

/// Decode a null-terminated UTF-16LE C-string (`LPCWSTR`) at the given raw pointer.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for the entire null-terminated string.
/// - The string must be terminated by a `\0\0` (UTF-16 null) within accessible memory.
pub unsafe fn from_wide_ptr(ptr: *const u16) -> Result<String, WideStringError> {
    assert!(!ptr.is_null(), "from_wide_ptr: null pointer");

    let mut len = 0usize;
    while *ptr.add(len) != 0u16 {
        len += 1;
    }

    let code_units = std::slice::from_raw_parts(ptr, len);
    decode_utf16_units(code_units)
}

/// Decode a UTF-16LE byte slice (little-endian pairs) into a `String`.
///
/// Does **not** strip a trailing null; use `from_wide_bytes_null_terminated` for that.
pub fn from_wide_bytes(bytes: &[u8]) -> Result<String, WideStringError> {
    if bytes.len() % 2 != 0 {
        return Err(WideStringError::OddLength(bytes.len()));
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    decode_utf16_units(&units)
}

/// Decode a null-terminated UTF-16LE byte slice, stripping the trailing `\0\0`.
///
/// Returns an error if the slice has an odd length or invalid UTF-16.
pub fn from_wide_bytes_null_terminated(bytes: &[u8]) -> Result<String, WideStringError> {
    if bytes.len() % 2 != 0 {
        return Err(WideStringError::OddLength(bytes.len()));
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    // Strip trailing null(s).
    let units = units.strip_suffix(&[0u16]).unwrap_or(units.as_slice());
    decode_utf16_units(units)
}

/// Decode a slice of UTF-16 code units into a `String`.
pub fn decode_utf16_units(units: &[u16]) -> Result<String, WideStringError> {
    std::char::decode_utf16(units.iter().copied())
        .collect::<Result<String, _>>()
        .map_err(WideStringError::from)
}

// ── Rust `&str` / `String` → UTF-16LE ─────────────────────────────────────────

/// Encode a Rust `&str` as a null-terminated UTF-16LE `Vec<u16>`.
///
/// The returned vector ends with a `0u16` null terminator — suitable for
/// passing to Windows APIs as `LPCWSTR`.
pub fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// Encode a Rust `&str` as UTF-16LE bytes (little-endian), **without** null terminator.
pub fn to_wide_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Encode a Rust `&str` as null-terminated UTF-16LE bytes (little-endian).
pub fn to_wide_bytes_null(s: &str) -> Vec<u8> {
    let mut v = to_wide_bytes(s);
    v.push(0);
    v.push(0);
    v
}

// ── OsString helpers ──────────────────────────────────────────────────────────

/// Convert UTF-16LE bytes to an `OsString` (via UTF-8 roundtrip).
pub fn from_wide_bytes_os(bytes: &[u8]) -> Result<OsString, WideStringError> {
    from_wide_bytes(bytes).map(OsString::from)
}

// ── Helper functions for common patterns ─────────────────────────────────────

/// Convert a null-terminated UTF-16 pointer to a Rust String
/// This is a convenience wrapper around from_wide_ptr
pub fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { from_wide_ptr(ptr).unwrap_or_default() }
}

/// Convert a Rust string to a null-terminated UTF-16 vector
/// This is a convenience wrapper around to_wide_null
pub fn str_to_wide(s: &str) -> Vec<u16> {
    to_wide_null(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ascii() {
        let original = "Hello, World!";
        let wide = to_wide_bytes(original);
        let back = from_wide_bytes(&wide).expect("round-trip failed");
        assert_eq!(back, original);
    }

    #[test]
    fn round_trip_unicode() {
        let original = "Thư viện 📚 Rust";
        let wide = to_wide_bytes(original);
        let back = from_wide_bytes(&wide).expect("round-trip failed");
        assert_eq!(back, original);
    }

    #[test]
    fn null_termination() {
        let wide = to_wide_null("abc");
        // Should be 4 u16s: 'a', 'b', 'c', 0.
        assert_eq!(wide.len(), 4);
        assert_eq!(*wide.last().unwrap(), 0u16);
    }

    #[test]
    fn null_terminated_bytes_roundtrip() {
        let original = "test";
        let bytes = to_wide_bytes_null(original);
        let back = from_wide_bytes_null_terminated(&bytes).expect("roundtrip failed");
        assert_eq!(back, original);
    }

    #[test]
    fn odd_length_error() {
        let odd = vec![0x48u8, 0x00, 0x69]; // 3 bytes — odd
        assert_eq!(from_wide_bytes(&odd), Err(WideStringError::OddLength(3)));
    }

    #[test]
    fn empty_string() {
        let s = "";
        let wide = to_wide_bytes(s);
        assert!(wide.is_empty());
        let back = from_wide_bytes(&wide).expect("empty roundtrip failed");
        assert_eq!(back, s);
    }

    #[test]
    fn empty_null_terminated() {
        // Just the null terminator.
        let bytes = to_wide_bytes_null("");
        assert_eq!(bytes.len(), 2);
        let back = from_wide_bytes_null_terminated(&bytes).expect("failed");
        assert_eq!(back, "");
    }

    #[test]
    fn emoji_surrogate_pair() {
        // 🦀 is U+1F980, encoded as surrogate pair D83E DD80 in UTF-16.
        let crab = "🦀";
        assert_eq!(crab.encode_utf16().count(), 2, "crab should be a surrogate pair");
        let wide = to_wide_bytes(crab);
        let back = from_wide_bytes(&wide).expect("surrogate pair roundtrip failed");
        assert_eq!(back, crab);
    }

    #[test]
    fn decode_utf16_units_direct() {
        let units: Vec<u16> = "Rust".encode_utf16().collect();
        let s = decode_utf16_units(&units).expect("decode failed");
        assert_eq!(s, "Rust");
    }

    #[test]
    fn to_wide_bytes_le_correct() {
        // 'A' = 0x0041 → LE bytes [0x41, 0x00]
        let bytes = to_wide_bytes("A");
        assert_eq!(bytes, vec![0x41u8, 0x00]);
    }

    #[test]
    fn null_ptr_safety_with_valid_slice() {
        // Test from_wide_ptr with a local slice — safe context.
        let units = to_wide_null("hello");
        let result = unsafe { from_wide_ptr(units.as_ptr()) };
        assert_eq!(result.expect("failed"), "hello");
    }
}
