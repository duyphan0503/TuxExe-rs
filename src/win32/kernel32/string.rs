#![allow(non_snake_case)]

// use std::ffi::c_void;
use crate::win32::kernel32::error::set_last_error;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const SYSTEM_ACP: u32 = 65001; // UTF-8
const SYSTEM_OEMCP: u32 = 437;
const CSTR_LESS_THAN: i32 = 1;
const CSTR_EQUAL: i32 = 2;
const CSTR_GREATER_THAN: i32 = 3;
const LOCALE_ALL: u32 = 0x0000;
const LOCALE_WINDOWS: u32 = 0x0001;
const LOCALE_SUPPLEMENTAL: u32 = 0x0002;
const LOCALE_ALTERNATE_SORTS: u32 = 0x0004;

const SAMPLE_LOCALE_W: [u16; 9] = [
    b'0' as u16,
    b'0' as u16,
    b'0' as u16,
    b'0' as u16,
    b'0' as u16,
    b'4' as u16,
    b'0' as u16,
    b'9' as u16,
    0,
];
const SAMPLE_LOCALE_A: &[u8] = b"00000409\0";

fn format_system_date_ascii(date: &super::time::SystemTime) -> String {
    format!("{:02}/{:02}/{:04}", date.wMonth, date.wDay, date.wYear)
}

fn format_system_time_ascii(time: &super::time::SystemTime) -> String {
    format!("{:02}:{:02}:{:02}", time.wHour, time.wMinute, time.wSecond)
}

fn get_effective_date(lp_date: *const super::time::SystemTime) -> super::time::SystemTime {
    if lp_date.is_null() {
        let mut local = super::time::SystemTime::default();
        super::time::get_local_time(&mut local as *mut _);
        local
    } else {
        // SAFETY: caller guarantees pointer validity when passing a non-null SYSTEMTIME.
        unsafe { *lp_date }
    }
}

#[repr(C)]
pub struct CpInfo {
    pub max_char_size: u32,
    pub default_char: [u8; 2],
    pub lead_byte: [u8; 12],
}

fn is_supported_code_page(code_page: u32) -> bool {
    matches!(
        code_page,
        0 // CP_ACP
            | 1 // CP_OEMCP
            | 2 // CP_MACCP
            | 3 // CP_THREAD_ACP
            | 42 // CP_SYMBOL
            | 437
            | 850
            | 852
            | 855
            | 857
            | 858
            | 860
            | 861
            | 862
            | 863
            | 865
            | 866
            | 874
            | 932
            | 936
            | 949
            | 950
            | 1200 // UTF-16LE
            | 1201 // UTF-16BE
            | 1250
            | 1251
            | 1252
            | 1253
            | 1254
            | 1255
            | 1256
            | 1257
            | 1258
            | 65000 // UTF-7
            | 65001 // UTF-8
    )
}

unsafe fn write_cp_info(ptr: *mut CpInfo, info: CpInfo) {
    // SAFETY: Caller guarantees `ptr` is valid and writable.
    unsafe { *ptr = info };
}

pub extern "win64" fn IsDBCSLeadByteEx(_code_page: u32, _test_char: u8) -> i32 {
    0 // False
}

pub extern "win64" fn IsValidCodePage(code_page: u32) -> i32 {
    i32::from(is_supported_code_page(code_page))
}

pub extern "win64" fn GetACP() -> u32 {
    SYSTEM_ACP
}

pub extern "win64" fn GetOEMCP() -> u32 {
    SYSTEM_OEMCP
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetCPInfo(code_page: u32, cp_info: *mut CpInfo) -> i32 {
    if cp_info.is_null() || !is_supported_code_page(code_page) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let resolved_code_page = match code_page {
        0 => SYSTEM_ACP,
        1 => SYSTEM_OEMCP,
        _ => code_page,
    };
    let max_char_size = if resolved_code_page == 65001 { 4 } else { 2 };
    let default_char = [b'?', 0];

    // SAFETY: `cp_info` is validated non-null above and points to writable caller memory.
    unsafe {
        write_cp_info(cp_info, CpInfo { max_char_size, default_char, lead_byte: [0; 12] });
    }

    1
}

pub extern "win64" fn MultiByteToWideChar(
    code_page: u32,
    _flags: u32,
    mb_str: *const u8,
    mb_len: i32,
    wide_str: *mut u16,
    wide_len: i32,
) -> i32 {
    if mb_str.is_null() || wide_len < 0 || mb_len < -1 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let cp = if code_page == 0 { SYSTEM_ACP } else { code_page };
    if cp != 65001 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let src_bytes: Vec<u8> = if mb_len == -1 {
        let mut len = 0usize;
        // SAFETY: caller provides NUL-terminated input when cbMultiByte == -1.
        unsafe {
            while *mb_str.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(mb_str, len).to_vec()
        }
    } else {
        // SAFETY: caller-provided length for source bytes.
        unsafe { std::slice::from_raw_parts(mb_str, mb_len as usize).to_vec() }
    };

    let Ok(decoded) = std::str::from_utf8(&src_bytes) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let wide: Vec<u16> = decoded.encode_utf16().collect();

    if wide_str.is_null() || wide_len == 0 {
        set_last_error(0);
        return wide.len() as i32;
    }

    if (wide_len as usize) < wide.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination buffer size validated above.
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), wide_str, wide.len());
    }
    set_last_error(0);
    wide.len() as i32
}

pub extern "win64" fn WideCharToMultiByte(
    code_page: u32,
    _flags: u32,
    wide_str: *const u16,
    wide_len: i32,
    mb_str: *mut u8,
    mb_len: i32,
    _default_char: *const u8,
    _used_default: *mut i32,
) -> i32 {
    tracing::trace!("WideCharToMultiByte cp={} wide_len={} mb_len={}", code_page, wide_len, mb_len);
    if wide_str.is_null() || mb_len < 0 || wide_len < -1 {
        tracing::trace!("WideCharToMultiByte: Invalid parameter (null or negative)");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let cp = if code_page == 0 { SYSTEM_ACP } else { code_page };
    if cp != 65001 {
        tracing::trace!("WideCharToMultiByte: Unsupported codepage {}", cp);
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let wide_slice: Vec<u16> = if wide_len == -1 {
        let mut len = 0usize;
        // SAFETY: caller provides NUL-terminated wide string for cchWideChar == -1.
        unsafe {
            while *wide_str.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(wide_str, len).to_vec()
        }
    } else {
        // SAFETY: caller-provided length for source UTF-16 data.
        unsafe { std::slice::from_raw_parts(wide_str, wide_len as usize).to_vec() }
    };

    let Ok(decoded) = String::from_utf16(&wide_slice) else {
        tracing::trace!("WideCharToMultiByte: Invalid UTF-16");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let bytes = decoded.as_bytes();

    if mb_str.is_null() || mb_len == 0 {
        set_last_error(0);
        let ret = bytes.len() as i32;
        tracing::trace!("WideCharToMultiByte: Returning length {}", ret);
        return ret;
    }

    if (mb_len as usize) < bytes.len() {
        tracing::trace!("WideCharToMultiByte: Insufficient buffer");
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination buffer size validated above.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mb_str, bytes.len());
    }
    set_last_error(0);
    tracing::trace!("WideCharToMultiByte: Success, returning {}", bytes.len());
    bytes.len() as i32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetStringTypeW(
    _info_type: u32,
    src: *const u16,
    src_len: i32,
    char_type: *mut u16,
) -> i32 {
    if src.is_null() || char_type.is_null() || src_len == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut count = src_len;
    if count < 0 {
        count = 0;
        // SAFETY: `src` is non-null and is expected to point to a NUL-terminated UTF-16 string.
        unsafe {
            while *src.add(count as usize) != 0 {
                count += 1;
            }
        }
    }

    if count <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Provide a conservative classification bit (C1_DEFINED-like behavior).
    // SAFETY: caller provided writable buffer for at least `count` UTF-16 code units.
    unsafe {
        for idx in 0..count as usize {
            *char_type.add(idx) = 1;
        }
    }

    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn LCMapStringW(
    _locale: u32,
    _dw_map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
) -> i32 {
    if lp_src_str.is_null() || cch_src < -1 || cch_dest < 0 {
        super::error::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let src_len = if cch_src == -1 {
        let mut len = 0usize;
        loop {
            let ch = unsafe { *lp_src_str.add(len) };
            len += 1;
            if ch == 0 {
                break;
            }
        }
        len
    } else {
        cch_src as usize
    };

    if lp_dest_str.is_null() || cch_dest == 0 {
        super::error::set_last_error(0);
        return src_len as i32;
    }

    if (cch_dest as usize) < src_len {
        super::error::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(lp_src_str, lp_dest_str, src_len);
    }
    super::error::set_last_error(0);
    src_len as i32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn CompareStringW(
    _locale: u32,
    _dw_cmp_flags: u32,
    lp_string1: *const u16,
    cch_count1: i32,
    lp_string2: *const u16,
    cch_count2: i32,
) -> i32 {
    if lp_string1.is_null() || lp_string2.is_null() || cch_count1 < -1 || cch_count2 < -1 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let read_len = |ptr: *const u16, len: i32| -> usize {
        if len >= 0 {
            len as usize
        } else {
            let mut idx = 0usize;
            // SAFETY: caller provides NUL-terminated UTF-16 when len == -1.
            unsafe {
                while *ptr.add(idx) != 0 {
                    idx += 1;
                }
            }
            idx
        }
    };

    let len1 = read_len(lp_string1, cch_count1);
    let len2 = read_len(lp_string2, cch_count2);
    // SAFETY: lengths are computed from valid pointers.
    let s1 = unsafe { std::slice::from_raw_parts(lp_string1, len1) };
    // SAFETY: lengths are computed from valid pointers.
    let s2 = unsafe { std::slice::from_raw_parts(lp_string2, len2) };

    set_last_error(0);
    match s1.cmp(s2) {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetLocaleInfoW(
    _locale: u32,
    _lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    if cch_data < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let value: Vec<u16> = "en-US".encode_utf16().chain(std::iter::once(0)).collect();
    if lp_lc_data.is_null() || cch_data == 0 {
        set_last_error(0);
        return value.len() as i32;
    }

    if (cch_data as usize) < value.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination validated above.
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), lp_lc_data, value.len());
    }
    set_last_error(0);
    value.len() as i32
}

pub extern "win64" fn IsValidLocale(_locale: u32, _dw_flags: u32) -> i32 {
    1
}

type LocaleEnumProcW = extern "win64" fn(*const u16) -> i32;
type LocaleEnumProcA = extern "win64" fn(*const i8) -> i32;

pub extern "win64" fn EnumSystemLocalesW(lp_locale_enum_proc: usize, dw_flags: u32) -> i32 {
    if lp_locale_enum_proc == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let supported = (dw_flags == 0)
        || (dw_flags
            & (LOCALE_ALL | LOCALE_WINDOWS | LOCALE_SUPPLEMENTAL | LOCALE_ALTERNATE_SORTS)
            != 0);
    if !supported {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let callback: LocaleEnumProcW = unsafe { std::mem::transmute(lp_locale_enum_proc) };
    let keep_going = callback(SAMPLE_LOCALE_W.as_ptr());
    if keep_going == 0 {
        set_last_error(0);
        return 0;
    }

    set_last_error(0);
    1
}

pub extern "win64" fn EnumSystemLocalesA(lp_locale_enum_proc: usize, dw_flags: u32) -> i32 {
    if lp_locale_enum_proc == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let supported = (dw_flags == 0)
        || (dw_flags
            & (LOCALE_ALL | LOCALE_WINDOWS | LOCALE_SUPPLEMENTAL | LOCALE_ALTERNATE_SORTS)
            != 0);
    if !supported {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let callback: LocaleEnumProcA = unsafe { std::mem::transmute(lp_locale_enum_proc) };
    let keep_going = callback(SAMPLE_LOCALE_A.as_ptr().cast::<i8>());
    if keep_going == 0 {
        set_last_error(0);
        return 0;
    }

    set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetUserDefaultLocaleName(
    lp_locale_name: *mut u16,
    cch_locale_name: i32,
) -> i32 {
    if cch_locale_name <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let locale: Vec<u16> = "en-US".encode_utf16().chain(std::iter::once(0)).collect();
    if (cch_locale_name as usize) < locale.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: destination validated above.
    unsafe {
        std::ptr::copy_nonoverlapping(locale.as_ptr(), lp_locale_name, locale.len());
    }
    set_last_error(0);
    locale.len() as i32
}

pub extern "win64" fn GetUserDefaultLCID() -> u32 {
    0x0409 // en-US
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetDateFormatW(
    _locale: u32,
    _dw_flags: u32,
    lp_date: *const super::time::SystemTime,
    _lp_format: *const u16,
    lp_date_str: *mut u16,
    cch_date: i32,
) -> i32 {
    if cch_date < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let date = get_effective_date(lp_date);
    let formatted: Vec<u16> =
        format_system_date_ascii(&date).encode_utf16().chain(std::iter::once(0)).collect();

    if cch_date == 0 {
        set_last_error(0);
        return formatted.len() as i32;
    }

    if lp_date_str.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (cch_date as usize) < formatted.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination pointer is non-null and large enough per checks above.
    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr(), lp_date_str, formatted.len());
    }
    set_last_error(0);
    formatted.len() as i32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetDateFormatA(
    _locale: u32,
    _dw_flags: u32,
    lp_date: *const super::time::SystemTime,
    _lp_format: *const i8,
    lp_date_str: *mut i8,
    cch_date: i32,
) -> i32 {
    if cch_date < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let date = get_effective_date(lp_date);
    let mut formatted = format_system_date_ascii(&date).into_bytes();
    formatted.push(0);

    if cch_date == 0 {
        set_last_error(0);
        return formatted.len() as i32;
    }

    if lp_date_str.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (cch_date as usize) < formatted.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination pointer is non-null and large enough per checks above.
    unsafe {
        std::ptr::copy_nonoverlapping(
            formatted.as_ptr().cast::<i8>(),
            lp_date_str,
            formatted.len(),
        );
    }
    set_last_error(0);
    formatted.len() as i32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetTimeFormatW(
    _locale: u32,
    _dw_flags: u32,
    lp_time: *const super::time::SystemTime,
    _lp_format: *const u16,
    lp_time_str: *mut u16,
    cch_time: i32,
) -> i32 {
    if cch_time < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let time = get_effective_date(lp_time);
    let formatted: Vec<u16> =
        format_system_time_ascii(&time).encode_utf16().chain(std::iter::once(0)).collect();

    if cch_time == 0 {
        set_last_error(0);
        return formatted.len() as i32;
    }

    if lp_time_str.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (cch_time as usize) < formatted.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination pointer is non-null and large enough per checks above.
    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr(), lp_time_str, formatted.len());
    }
    set_last_error(0);
    formatted.len() as i32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetTimeFormatA(
    _locale: u32,
    _dw_flags: u32,
    lp_time: *const super::time::SystemTime,
    _lp_format: *const i8,
    lp_time_str: *mut i8,
    cch_time: i32,
) -> i32 {
    if cch_time < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let time = get_effective_date(lp_time);
    let mut formatted = format_system_time_ascii(&time).into_bytes();
    formatted.push(0);

    if cch_time == 0 {
        set_last_error(0);
        return formatted.len() as i32;
    }

    if lp_time_str.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (cch_time as usize) < formatted.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    // SAFETY: destination pointer is non-null and large enough per checks above.
    unsafe {
        std::ptr::copy_nonoverlapping(
            formatted.as_ptr().cast::<i8>(),
            lp_time_str,
            formatted.len(),
        );
    }
    set_last_error(0);
    formatted.len() as i32
}

#[cfg(test)]
mod tests {
    use super::LCMapStringW;
    use super::{
        CpInfo, EnumSystemLocalesA, EnumSystemLocalesW, GetACP, GetCPInfo, GetDateFormatW,
        GetOEMCP, GetStringTypeW, GetTimeFormatW, IsValidCodePage,
    };
    use std::ffi::CStr;

    #[test]
    fn is_valid_code_page_accepts_common_pages() {
        assert_eq!(IsValidCodePage(0), 1);
        assert_eq!(IsValidCodePage(1252), 1);
        assert_eq!(IsValidCodePage(65001), 1);
    }

    #[test]
    fn is_valid_code_page_rejects_unknown_pages() {
        assert_eq!(IsValidCodePage(999_999), 0);
    }

    #[test]
    fn get_acp_and_oemcp_return_stable_values() {
        assert_eq!(GetACP(), 65001);
        assert_eq!(GetOEMCP(), 437);
    }

    #[test]
    fn get_cp_info_populates_struct_for_valid_code_page() {
        let mut info = CpInfo { max_char_size: 0, default_char: [0; 2], lead_byte: [0; 12] };

        assert_eq!(GetCPInfo(65001, &mut info), 1);
        assert_eq!(info.max_char_size, 4);
    }

    #[test]
    fn get_string_type_w_writes_classifications() {
        let src = [b'A' as u16, b'1' as u16, 0];
        let mut types = [0u16; 2];
        assert_eq!(GetStringTypeW(0, src.as_ptr(), 2, types.as_mut_ptr()), 1);
        assert_eq!(types, [1, 1]);
    }

    #[test]
    fn lcmap_string_w_reports_required_size_and_copies_source() {
        let src: Vec<u16> = "AbC".encode_utf16().chain(std::iter::once(0)).collect();
        let required = LCMapStringW(0, 0, src.as_ptr(), -1, std::ptr::null_mut(), 0);
        assert_eq!(required, src.len() as i32);

        let mut dest = vec![0u16; src.len()];
        let written = LCMapStringW(0, 0, src.as_ptr(), -1, dest.as_mut_ptr(), dest.len() as i32);
        assert_eq!(written, src.len() as i32);
        assert_eq!(dest, src);
    }

    extern "win64" fn locale_cb_w(locale: *const u16) -> i32 {
        if locale.is_null() {
            return 0;
        }
        let mut len = 0usize;
        unsafe {
            while *locale.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(locale, len);
            i32::from(slice == "00000409".encode_utf16().collect::<Vec<_>>().as_slice())
        }
    }

    extern "win64" fn locale_cb_a(locale: *const i8) -> i32 {
        if locale.is_null() {
            return 0;
        }
        unsafe { i32::from(CStr::from_ptr(locale).to_bytes() == b"00000409") }
    }

    #[test]
    fn enum_system_locales_w_invokes_callback() {
        assert_eq!(EnumSystemLocalesW(locale_cb_w as usize, 1), 1);
    }

    #[test]
    fn enum_system_locales_a_invokes_callback() {
        assert_eq!(EnumSystemLocalesA(locale_cb_a as usize, 1), 1);
    }

    #[test]
    fn get_date_format_w_formats_explicit_date() {
        let date = super::super::time::SystemTime {
            wYear: 2024,
            wMonth: 7,
            wDay: 9,
            ..super::super::time::SystemTime::default()
        };

        let required =
            GetDateFormatW(0, 0, &date as *const _, std::ptr::null(), std::ptr::null_mut(), 0);
        assert_eq!(required, 11);

        let mut buffer = vec![0u16; required as usize];
        let written = GetDateFormatW(
            0,
            0,
            &date as *const _,
            std::ptr::null(),
            buffer.as_mut_ptr(),
            buffer.len() as i32,
        );
        assert_eq!(written, required);
        let rendered = String::from_utf16_lossy(&buffer[..(written as usize - 1)]);
        assert_eq!(rendered, "07/09/2024");
    }

    #[test]
    fn get_time_format_w_formats_explicit_time() {
        let time = super::super::time::SystemTime {
            wHour: 14,
            wMinute: 5,
            wSecond: 9,
            ..super::super::time::SystemTime::default()
        };

        let required =
            GetTimeFormatW(0, 0, &time as *const _, std::ptr::null(), std::ptr::null_mut(), 0);
        assert_eq!(required, 9);

        let mut buffer = vec![0u16; required as usize];
        let written = GetTimeFormatW(
            0,
            0,
            &time as *const _,
            std::ptr::null(),
            buffer.as_mut_ptr(),
            buffer.len() as i32,
        );
        assert_eq!(written, required);
        let rendered = String::from_utf16_lossy(&buffer[..(written as usize - 1)]);
        assert_eq!(rendered, "14:05:09");
    }
}
