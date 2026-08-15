#![allow(non_snake_case)]

use super::{
    WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEMOVE,
    WM_PAINT, WM_RBUTTONDOWN, WM_RBUTTONUP,
};

pub const VK_BACK: u32 = 0x08;
pub const VK_TAB: u32 = 0x09;
pub const VK_RETURN: u32 = 0x0D;
pub const VK_ESCAPE: u32 = 0x1B;
pub const VK_SPACE: u32 = 0x20;
pub const VK_LEFT: u32 = 0x25;
pub const VK_UP: u32 = 0x26;
pub const VK_RIGHT: u32 = 0x27;
pub const VK_DOWN: u32 = 0x28;

const MAPVK_VK_TO_VSC: u32 = 0;
const MAPVK_VSC_TO_VK: u32 = 1;
const MAPVK_VK_TO_CHAR: u32 = 2;
const MAPVK_VSC_TO_VK_EX: u32 = 3;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const RIDI_DEVICENAME: u32 = 0x2000_0007;
const KEYBOARD_LAYOUT_NAME_LEN: usize = 9;
const DEFAULT_HKL: usize = 0x0409_0409;

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

fn active_keyboard_layout() -> &'static std::sync::atomic::AtomicUsize {
    static ACTIVE_LAYOUT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(DEFAULT_HKL);
    &ACTIVE_LAYOUT
}

pub const X11_KEY_PRESS: u32 = 2;
pub const X11_KEY_RELEASE: u32 = 3;
pub const X11_BUTTON_PRESS: u32 = 4;
pub const X11_BUTTON_RELEASE: u32 = 5;
pub const X11_MOTION_NOTIFY: u32 = 6;
pub const X11_EXPOSE: u32 = 12;

pub fn map_x11_event_to_windows_message(event_type: u32, detail: u32) -> Option<u32> {
    match event_type {
        X11_KEY_PRESS => Some(WM_KEYDOWN),
        X11_KEY_RELEASE => Some(WM_KEYUP),
        X11_MOTION_NOTIFY => Some(WM_MOUSEMOVE),
        X11_EXPOSE => Some(WM_PAINT),
        X11_BUTTON_PRESS => match detail {
            1 => Some(WM_LBUTTONDOWN),
            2 => Some(WM_MBUTTONDOWN),
            3 => Some(WM_RBUTTONDOWN),
            _ => None,
        },
        X11_BUTTON_RELEASE => match detail {
            1 => Some(WM_LBUTTONUP),
            2 => Some(WM_MBUTTONUP),
            3 => Some(WM_RBUTTONUP),
            _ => None,
        },
        _ => None,
    }
}

pub fn map_x11_keysym_to_vk(keysym: u32) -> u32 {
    match keysym {
        0x0030..=0x0039 => keysym,
        0x0041..=0x005A => keysym,
        0x0061..=0x007A => keysym - 0x20,
        0xFF08 => VK_BACK,
        0xFF09 => VK_TAB,
        0xFF0D => VK_RETURN,
        0xFF1B => VK_ESCAPE,
        0x0020 => VK_SPACE,
        0xFF51 => VK_LEFT,
        0xFF52 => VK_UP,
        0xFF53 => VK_RIGHT,
        0xFF54 => VK_DOWN,
        _ => 0,
    }
}

pub fn vk_to_char(vk: u32) -> Option<u32> {
    match vk {
        0x30..=0x39 => Some(vk),
        0x41..=0x5A => Some(vk),
        VK_SPACE => Some(b' ' as u32),
        VK_RETURN => Some(0x0D),
        VK_TAB => Some(0x09),
        VK_BACK => Some(0x08),
        VK_ESCAPE => Some(0x1B),
        _ => None,
    }
}

pub extern "win64" fn MapVirtualKeyA(uCode: u32, uMapType: u32) -> u32 {
    match uMapType {
        MAPVK_VK_TO_CHAR => vk_to_char(uCode).unwrap_or(0),
        MAPVK_VK_TO_VSC | MAPVK_VSC_TO_VK | MAPVK_VSC_TO_VK_EX => uCode,
        _ => 0,
    }
}

pub extern "win64" fn MapVirtualKeyW(uCode: u32, uMapType: u32) -> u32 {
    MapVirtualKeyA(uCode, uMapType)
}

pub extern "win64" fn MapVirtualKeyExA(uCode: u32, uMapType: u32, _dwhkl: usize) -> u32 {
    MapVirtualKeyA(uCode, uMapType)
}

pub extern "win64" fn MapVirtualKeyExW(uCode: u32, uMapType: u32, _dwhkl: usize) -> u32 {
    MapVirtualKeyW(uCode, uMapType)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn ToUnicode(
    w_virt_key: u32,
    _w_scan_code: u32,
    _lp_key_state: *const u8,
    pwsz_buff: *mut u16,
    cch_buff: i32,
    _w_flags: u32,
) -> i32 {
    if pwsz_buff.is_null() || cch_buff <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let Some(ch) = vk_to_char(w_virt_key) else {
        set_last_error(0);
        return 0;
    };

    unsafe {
        *pwsz_buff = ch as u16;
        if cch_buff > 1 {
            *pwsz_buff.add(1) = 0;
        }
    }

    set_last_error(0);
    1
}

pub extern "win64" fn ToUnicodeEx(
    w_virt_key: u32,
    w_scan_code: u32,
    lp_key_state: *const u8,
    pwsz_buff: *mut u16,
    cch_buff: i32,
    w_flags: u32,
    _dwhkl: usize,
) -> i32 {
    ToUnicode(w_virt_key, w_scan_code, lp_key_state, pwsz_buff, cch_buff, w_flags)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetKeyNameTextW(_l_param: i32, lp_string: *mut u16, cch_size: i32) -> i32 {
    if lp_string.is_null() || cch_size <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let text: Vec<u16> = "Key".encode_utf16().collect();
    let copy_len = text.len().min((cch_size - 1).max(0) as usize);

    unsafe {
        if copy_len > 0 {
            std::ptr::copy_nonoverlapping(text.as_ptr(), lp_string, copy_len);
        }
        *lp_string.add(copy_len) = 0;
    }

    set_last_error(0);
    copy_len as i32
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetKeyNameTextA(_l_param: i32, lp_string: *mut u8, cch_size: i32) -> i32 {
    if lp_string.is_null() || cch_size <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let text = b"Key";
    let copy_len = text.len().min((cch_size - 1).max(0) as usize);

    unsafe {
        if copy_len > 0 {
            std::ptr::copy_nonoverlapping(text.as_ptr(), lp_string, copy_len);
        }
        *lp_string.add(copy_len) = 0;
    }

    set_last_error(0);
    copy_len as i32
}

static KEY_STATE: [std::sync::atomic::AtomicU8; 256] = [const { std::sync::atomic::AtomicU8::new(0) }; 256];

pub fn set_key_down(vk: u32) {
    if (vk as usize) < KEY_STATE.len() {
        KEY_STATE[vk as usize].store(0x80, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn set_key_up(vk: u32) {
    if (vk as usize) < KEY_STATE.len() {
        KEY_STATE[vk as usize].store(0x00, std::sync::atomic::Ordering::Relaxed);
    }
}

pub extern "win64" fn GetAsyncKeyState(v_key: i32) -> i16 {
    if v_key >= 0 && (v_key as usize) < KEY_STATE.len() {
        let state = KEY_STATE[v_key as usize].load(std::sync::atomic::Ordering::Relaxed);
        if (state & 0x80) != 0 {
            return -32768; // 0x8000
        }
    }
    set_last_error(0);
    0
}

pub extern "win64" fn GetKeyState(n_virt_key: i32) -> i16 {
    if n_virt_key >= 0 && (n_virt_key as usize) < KEY_STATE.len() {
        let state = KEY_STATE[n_virt_key as usize].load(std::sync::atomic::Ordering::Relaxed);
        if (state & 0x80) != 0 {
            return -128;
        }
    }
    set_last_error(0);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetKeyboardState(lp_key_state: *mut u8) -> i32 {
    if lp_key_state.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    unsafe {
        for i in 0..256 {
            *lp_key_state.add(i) = KEY_STATE[i].load(std::sync::atomic::Ordering::Relaxed);
        }
    }
    set_last_error(0);
    1
}

pub extern "win64" fn GetKeyboardLayout(_id_thread: u32) -> usize {
    set_last_error(0);
    active_keyboard_layout().load(std::sync::atomic::Ordering::Relaxed)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetKeyboardLayoutList(n_buff: i32, lp_list: *mut usize) -> i32 {
    if n_buff < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if n_buff == 0 {
        set_last_error(0);
        return 1;
    }

    if lp_list.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        *lp_list = GetKeyboardLayout(0);
    }
    set_last_error(0);
    1
}

pub extern "win64" fn ActivateKeyboardLayout(hkl: usize, _flags: u32) -> usize {
    if hkl == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let previous = active_keyboard_layout().swap(hkl, std::sync::atomic::Ordering::Relaxed);
    set_last_error(0);
    previous
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetKeyboardLayoutNameW(pwsz_k_lid: *mut u16) -> i32 {
    if pwsz_k_lid.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let klid: Vec<u16> = "00000409".encode_utf16().chain(std::iter::once(0)).collect();
    debug_assert_eq!(klid.len(), KEYBOARD_LAYOUT_NAME_LEN);

    unsafe {
        std::ptr::copy_nonoverlapping(klid.as_ptr(), pwsz_k_lid, klid.len());
    }

    set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetRawInputBuffer(
    _p_data: *mut std::ffi::c_void,
    pcb_size: *mut u32,
    _cb_size_header: u32,
) -> u32 {
    if pcb_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return u32::MAX;
    }

    unsafe {
        *pcb_size = 0;
    }
    set_last_error(0);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetRawInputData(
    _h_raw_input: usize,
    _ui_command: u32,
    _p_data: *mut std::ffi::c_void,
    pcb_size: *mut u32,
    _cb_size_header: u32,
) -> u32 {
    if pcb_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return u32::MAX;
    }

    unsafe {
        *pcb_size = 0;
    }
    set_last_error(0);
    0
}

pub extern "win64" fn RegisterRawInputDevices(
    _p_raw_input_devices: *const std::ffi::c_void,
    _ui_num_devices: u32,
    _cb_size: u32,
) -> i32 {
    set_last_error(0);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetRawInputDeviceInfoW(
    _h_device: usize,
    ui_command: u32,
    p_data: *mut std::ffi::c_void,
    pcb_size: *mut u32,
) -> u32 {
    if pcb_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return u32::MAX;
    }

    if ui_command == RIDI_DEVICENAME {
        let name: Vec<u16> =
            "TuxExeRawInputDevice".encode_utf16().chain(std::iter::once(0)).collect();
        let required = name.len() as u32;

        if p_data.is_null() {
            unsafe {
                *pcb_size = required;
            }
            set_last_error(0);
            return required;
        }

        unsafe {
            if *pcb_size < required {
                *pcb_size = required;
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return u32::MAX;
            }
            std::ptr::copy_nonoverlapping(name.as_ptr(), p_data.cast::<u16>(), name.len());
            *pcb_size = required;
        }
        set_last_error(0);
        return required;
    }

    // Default compatibility path for RIDI_DEVICEINFO/RIDI_PREPARSEDDATA.
    if p_data.is_null() {
        unsafe {
            *pcb_size = 0;
        }
    }
    set_last_error(0);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetRawInputDeviceInfoA(
    _h_device: usize,
    ui_command: u32,
    p_data: *mut std::ffi::c_void,
    pcb_size: *mut u32,
) -> u32 {
    if pcb_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return u32::MAX;
    }

    if ui_command == RIDI_DEVICENAME {
        let mut name = b"TuxExeRawInputDevice".to_vec();
        name.push(0);
        let required = name.len() as u32;

        if p_data.is_null() {
            unsafe {
                *pcb_size = required;
            }
            set_last_error(0);
            return required;
        }

        unsafe {
            if *pcb_size < required {
                *pcb_size = required;
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return u32::MAX;
            }
            std::ptr::copy_nonoverlapping(name.as_ptr(), p_data.cast::<u8>(), name.len());
            *pcb_size = required;
        }
        set_last_error(0);
        return required;
    }

    if p_data.is_null() {
        unsafe {
            *pcb_size = 0;
        }
    }
    set_last_error(0);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetRawInputDeviceList(
    _p_raw_input_device_list: *mut std::ffi::c_void,
    pui_num_devices: *mut u32,
    _cb_size: u32,
) -> u32 {
    if pui_num_devices.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return u32::MAX;
    }

    unsafe {
        *pui_num_devices = 0;
    }
    set_last_error(0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_x11_events_to_windows_messages() {
        assert_eq!(map_x11_event_to_windows_message(X11_KEY_PRESS, 0), Some(WM_KEYDOWN));
        assert_eq!(map_x11_event_to_windows_message(X11_BUTTON_PRESS, 1), Some(WM_LBUTTONDOWN));
        assert_eq!(map_x11_event_to_windows_message(X11_BUTTON_RELEASE, 3), Some(WM_RBUTTONUP));
        assert_eq!(map_x11_event_to_windows_message(999, 0), None);
    }

    #[test]
    fn maps_x11_keysyms_to_virtual_keys() {
        assert_eq!(map_x11_keysym_to_vk('a' as u32), 'A' as u32);
        assert_eq!(map_x11_keysym_to_vk('Z' as u32), 'Z' as u32);
        assert_eq!(map_x11_keysym_to_vk(0xFF0D), VK_RETURN);
        assert_eq!(map_x11_keysym_to_vk(0xFF51), VK_LEFT);
    }

    #[test]
    fn map_virtual_key_char_translation_works() {
        assert_eq!(MapVirtualKeyA('A' as u32, MAPVK_VK_TO_CHAR), 'A' as u32);
        assert_eq!(MapVirtualKeyW(VK_SPACE, MAPVK_VK_TO_CHAR), ' ' as u32);
        assert_eq!(MapVirtualKeyA(VK_RETURN, MAPVK_VK_TO_CHAR), 0x0D);
        assert_eq!(MapVirtualKeyA(0xFFFF, MAPVK_VK_TO_CHAR), 0);
    }

    #[test]
    fn map_virtual_key_ex_matches_base_mapping() {
        assert_eq!(
            MapVirtualKeyExA('A' as u32, MAPVK_VK_TO_CHAR, 0),
            MapVirtualKeyA('A' as u32, MAPVK_VK_TO_CHAR)
        );
        assert_eq!(
            MapVirtualKeyExW(VK_SPACE, MAPVK_VK_TO_CHAR, 0),
            MapVirtualKeyW(VK_SPACE, MAPVK_VK_TO_CHAR)
        );
    }

    #[test]
    fn to_unicode_converts_basic_virtual_keys() {
        let mut out = [0u16; 2];
        let written = ToUnicode('A' as u32, 0, std::ptr::null(), out.as_mut_ptr(), 2, 0);
        assert_eq!(written, 1);
        assert_eq!(out[0], 'A' as u16);
    }

    #[test]
    fn get_key_name_text_w_returns_stub_name() {
        let mut out = [0u16; 8];
        let written = GetKeyNameTextW(0, out.as_mut_ptr(), out.len() as i32);
        assert_eq!(written, 3);
        assert_eq!(out[0], 'K' as u16);
    }

    #[test]
    fn keyboard_state_queries_return_neutral_defaults() {
        assert_eq!(GetAsyncKeyState('A' as i32), 0);
        assert_eq!(GetKeyState('A' as i32), 0);

        let mut state = [0xFFu8; 256];
        assert_eq!(GetKeyboardState(state.as_mut_ptr()), 1);
        assert!(state.iter().all(|v| *v == 0));
    }

    #[test]
    fn keyboard_layout_api_returns_stable_defaults() {
        let current = GetKeyboardLayout(0);
        assert_ne!(current, 0);

        let mut layouts = [0usize; 1];
        assert_eq!(GetKeyboardLayoutList(0, std::ptr::null_mut()), 1);
        assert_eq!(GetKeyboardLayoutList(1, layouts.as_mut_ptr()), 1);
        assert_eq!(layouts[0], current);

        let previous = ActivateKeyboardLayout(DEFAULT_HKL, 0);
        assert_ne!(previous, 0);

        let mut name = [0u16; KEYBOARD_LAYOUT_NAME_LEN];
        assert_eq!(GetKeyboardLayoutNameW(name.as_mut_ptr()), 1);
        let decoded = String::from_utf16_lossy(&name[..8]);
        assert_eq!(decoded, "00000409");
    }

    #[test]
    fn raw_input_buffer_and_data_report_no_pending_input() {
        let mut size = 123u32;
        assert_eq!(GetRawInputBuffer(std::ptr::null_mut(), &mut size as *mut u32, 0), 0);
        assert_eq!(size, 0);

        size = 456;
        assert_eq!(GetRawInputData(0, 0, std::ptr::null_mut(), &mut size as *mut u32, 0), 0);
        assert_eq!(size, 0);
    }

    #[test]
    fn raw_input_device_info_name_query_returns_required_size() {
        let mut size = 0u32;
        let required = GetRawInputDeviceInfoW(0, RIDI_DEVICENAME, std::ptr::null_mut(), &mut size);
        assert_eq!(required, size);
        assert!(required > 1);
    }
}
