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
pub const VK_PRIOR: u32 = 0x21;  // Page Up
pub const VK_NEXT: u32 = 0x22;   // Page Down
pub const VK_END: u32 = 0x23;
pub const VK_HOME: u32 = 0x24;
pub const VK_LEFT: u32 = 0x25;
pub const VK_UP: u32 = 0x26;
pub const VK_RIGHT: u32 = 0x27;
pub const VK_DOWN: u32 = 0x28;
pub const VK_INSERT: u32 = 0x2D;
pub const VK_DELETE: u32 = 0x2E;
pub const VK_LWIN: u32 = 0x5B;
pub const VK_RWIN: u32 = 0x5C;
pub const VK_APPS: u32 = 0x5D;   // Context menu
pub const VK_NUMPAD0: u32 = 0x60;
pub const VK_NUMPAD1: u32 = 0x61;
pub const VK_NUMPAD2: u32 = 0x62;
pub const VK_NUMPAD3: u32 = 0x63;
pub const VK_NUMPAD4: u32 = 0x64;
pub const VK_NUMPAD5: u32 = 0x65;
pub const VK_NUMPAD6: u32 = 0x66;
pub const VK_NUMPAD7: u32 = 0x67;
pub const VK_NUMPAD8: u32 = 0x68;
pub const VK_NUMPAD9: u32 = 0x69;
pub const VK_MULTIPLY: u32 = 0x6A;
pub const VK_ADD: u32 = 0x6B;
pub const VK_SEPARATOR: u32 = 0x6C;
pub const VK_SUBTRACT: u32 = 0x6D;
pub const VK_DECIMAL: u32 = 0x6E;
pub const VK_DIVIDE: u32 = 0x6F;
pub const VK_F1: u32 = 0x70;
pub const VK_F2: u32 = 0x71;
pub const VK_F3: u32 = 0x72;
pub const VK_F4: u32 = 0x73;
pub const VK_F5: u32 = 0x74;
pub const VK_F6: u32 = 0x75;
pub const VK_F7: u32 = 0x76;
pub const VK_F8: u32 = 0x77;
pub const VK_F9: u32 = 0x78;
pub const VK_F10: u32 = 0x79;
pub const VK_F11: u32 = 0x7A;
pub const VK_F12: u32 = 0x7B;
pub const VK_NUMLOCK: u32 = 0x90;
pub const VK_SCROLL: u32 = 0x91;
pub const VK_LSHIFT: u32 = 0xA0;
pub const VK_RSHIFT: u32 = 0xA1;
pub const VK_LCONTROL: u32 = 0xA2;
pub const VK_RCONTROL: u32 = 0xA3;
pub const VK_LMENU: u32 = 0xA4;  // Left Alt
pub const VK_RMENU: u32 = 0xA5;  // Right Alt
pub const VK_OEM_1: u32 = 0xBA;  // ; :
pub const VK_OEM_PLUS: u32 = 0xBB;  // = +
pub const VK_OEM_COMMA: u32 = 0xBC; // , <
pub const VK_OEM_MINUS: u32 = 0xBD; // - _
pub const VK_OEM_PERIOD: u32 = 0xBE; // . >
pub const VK_OEM_2: u32 = 0xBF;  // / ?
pub const VK_OEM_3: u32 = 0xC0;  // ` ~
pub const VK_OEM_4: u32 = 0xDB;  // [ {
pub const VK_OEM_5: u32 = 0xDC;  // \ |
pub const VK_OEM_6: u32 = 0xDD;  // ] }
pub const VK_OEM_7: u32 = 0xDE;  // ' "
pub const VK_SHIFT: u32 = 0x10;
pub const VK_CONTROL: u32 = 0x11;
pub const VK_MENU: u32 = 0x12;   // Alt
pub const VK_CAPITAL: u32 = 0x14; // CapsLock
pub const VK_SNAPSHOT: u32 = 0x2C; // Print Screen
pub const VK_PAUSE: u32 = 0x13;

const MAPVK_VK_TO_VSC: u32 = 0;
const MAPVK_VSC_TO_VK: u32 = 1;
const MAPVK_VK_TO_CHAR: u32 = 2;
const MAPVK_VSC_TO_VK_EX: u32 = 3;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const RIDI_DEVICENAME: u32 = 0x2000_0007;
const KEYBOARD_LAYOUT_NAME_LEN: usize = 9;
const DEFAULT_HKL: usize = 0x0409_0409;

/// Extended key flag: these VKs generate scan codes with the E0 prefix.
/// In lParam, bit 24 is set for extended keys.
pub fn is_extended_key(vk: u32) -> bool {
    matches!(
        vk,
        VK_INSERT
            | VK_DELETE
            | VK_HOME
            | VK_END
            | VK_PRIOR
            | VK_NEXT
            | VK_LEFT
            | VK_UP
            | VK_RIGHT
            | VK_DOWN
            | VK_RCONTROL
            | VK_RMENU
            | VK_RWIN
            | VK_LWIN
            | VK_APPS
            | VK_DIVIDE   // Numpad /
            | VK_NUMLOCK
            | 0x0D        // VK_RETURN extended (numpad enter)
    )
}

/// Translate a Windows Virtual Key code to an AT/PS2 Set 1 scan code.
/// Returns 0 if no mapping is known.
/// Extended keys are flagged separately via `is_extended_key`.
pub fn vk_to_scan_code(vk: u32) -> u32 {
    match vk {
        VK_ESCAPE    => 0x01,
        0x31         => 0x02, // '1'
        0x32         => 0x03, // '2'
        0x33         => 0x04, // '3'
        0x34         => 0x05, // '4'
        0x35         => 0x06, // '5'
        0x36         => 0x07, // '6'
        0x37         => 0x08, // '7'
        0x38         => 0x09, // '8'
        0x39         => 0x0A, // '9'
        0x30         => 0x0B, // '0'
        VK_OEM_MINUS => 0x0C, // - _
        VK_OEM_PLUS  => 0x0D, // = +
        VK_BACK      => 0x0E,
        VK_TAB       => 0x0F,
        0x51         => 0x10, // 'Q'
        0x57         => 0x11, // 'W'
        0x45         => 0x12, // 'E'
        0x52         => 0x13, // 'R'
        0x54         => 0x14, // 'T'
        0x59         => 0x15, // 'Y'
        0x55         => 0x16, // 'U'
        0x49         => 0x17, // 'I'
        0x4F         => 0x18, // 'O'
        0x50         => 0x19, // 'P'
        VK_OEM_4     => 0x1A, // [ {
        VK_OEM_6     => 0x1B, // ] }
        VK_RETURN    => 0x1C,
        VK_LCONTROL  => 0x1D,
        VK_CONTROL   => 0x1D, // left ctrl
        0x41         => 0x1E, // 'A'
        0x53         => 0x1F, // 'S'
        0x44         => 0x20, // 'D'
        0x46         => 0x21, // 'F'
        0x47         => 0x22, // 'G'
        0x48         => 0x23, // 'H'
        0x4A         => 0x24, // 'J'
        0x4B         => 0x25, // 'K'
        0x4C         => 0x26, // 'L'
        VK_OEM_1     => 0x27, // ; :
        VK_OEM_7     => 0x28, // ' "
        VK_OEM_3     => 0x29, // ` ~
        VK_LSHIFT    => 0x2A,
        VK_SHIFT     => 0x2A, // left shift
        VK_OEM_5     => 0x2B, // \ |
        0x5A         => 0x2C, // 'Z'
        0x58         => 0x2D, // 'X'
        0x43         => 0x2E, // 'C'
        0x56         => 0x2F, // 'V'
        0x42         => 0x30, // 'B'
        0x4E         => 0x31, // 'N'
        0x4D         => 0x32, // 'M'
        VK_OEM_COMMA  => 0x33, // , <
        VK_OEM_PERIOD => 0x34, // . >
        VK_OEM_2     => 0x35, // / ?
        VK_RSHIFT    => 0x36,
        VK_MULTIPLY  => 0x37, // Numpad *
        VK_LMENU     => 0x38, // Left Alt
        VK_MENU      => 0x38, // Alt
        VK_SPACE     => 0x39,
        VK_CAPITAL   => 0x3A, // CapsLock
        VK_F1        => 0x3B,
        VK_F2        => 0x3C,
        VK_F3        => 0x3D,
        VK_F4        => 0x3E,
        VK_F5        => 0x3F,
        VK_F6        => 0x40,
        VK_F7        => 0x41,
        VK_F8        => 0x42,
        VK_F9        => 0x43,
        VK_F10       => 0x44,
        VK_NUMLOCK   => 0x45,
        VK_SCROLL    => 0x46,
        VK_NUMPAD7   => 0x47,
        VK_NUMPAD8   => 0x48,
        VK_NUMPAD9   => 0x49,
        VK_SUBTRACT  => 0x4A,
        VK_NUMPAD4   => 0x4B,
        VK_NUMPAD5   => 0x4C,
        VK_NUMPAD6   => 0x4D,
        VK_ADD       => 0x4E,
        VK_NUMPAD1   => 0x4F,
        VK_NUMPAD2   => 0x50,
        VK_NUMPAD3   => 0x51,
        VK_NUMPAD0   => 0x52,
        VK_DECIMAL   => 0x53,
        VK_F11       => 0x57,
        VK_F12       => 0x58,
        // Extended keys (E0 prefix on real hardware; bit 24 in lParam)
        VK_RCONTROL  => 0x1D, // same base scan as LCONTROL but extended
        VK_RMENU     => 0x38, // same base scan as LMENU but extended
        VK_DIVIDE    => 0x35, // same base scan as OEM_2 but extended
        VK_INSERT    => 0x52, // same base scan as NUMPAD0 but extended
        VK_DELETE    => 0x53, // same base as DECIMAL but extended
        VK_HOME      => 0x47,
        VK_END       => 0x4F,
        VK_PRIOR     => 0x49, // Page Up
        VK_NEXT      => 0x51, // Page Down
        VK_UP        => 0x48,
        VK_DOWN      => 0x50,
        VK_LEFT      => 0x4B,
        VK_RIGHT     => 0x4D,
        VK_LWIN      => 0x5B,
        VK_RWIN      => 0x5C,
        VK_APPS      => 0x5D,
        VK_SNAPSHOT  => 0x37, // Print Screen (extended)
        VK_PAUSE     => 0x45, // Pause/Break
        _            => 0,
    }
}

/// Translate an AT/PS2 Set 1 scan code back to a Windows Virtual Key code.
/// Returns 0 for unrecognised scan codes.
pub fn scan_code_to_vk(sc: u32) -> u32 {
    match sc {
        0x01 => VK_ESCAPE,
        0x02 => 0x31, // '1'
        0x03 => 0x32, // '2'
        0x04 => 0x33, // '3'
        0x05 => 0x34, // '4'
        0x06 => 0x35, // '5'
        0x07 => 0x36, // '6'
        0x08 => 0x37, // '7'
        0x09 => 0x38, // '8'
        0x0A => 0x39, // '9'
        0x0B => 0x30, // '0'
        0x0C => VK_OEM_MINUS,
        0x0D => VK_OEM_PLUS,
        0x0E => VK_BACK,
        0x0F => VK_TAB,
        0x10 => 0x51, // 'Q'
        0x11 => 0x57, // 'W'
        0x12 => 0x45, // 'E'
        0x13 => 0x52, // 'R'
        0x14 => 0x54, // 'T'
        0x15 => 0x59, // 'Y'
        0x16 => 0x55, // 'U'
        0x17 => 0x49, // 'I'
        0x18 => 0x4F, // 'O'
        0x19 => 0x50, // 'P'
        0x1A => VK_OEM_4,
        0x1B => VK_OEM_6,
        0x1C => VK_RETURN,
        0x1D => VK_LCONTROL,
        0x1E => 0x41, // 'A'
        0x1F => 0x53, // 'S'
        0x20 => 0x44, // 'D'
        0x21 => 0x46, // 'F'
        0x22 => 0x47, // 'G'
        0x23 => 0x48, // 'H'
        0x24 => 0x4A, // 'J'
        0x25 => 0x4B, // 'K'
        0x26 => 0x4C, // 'L'
        0x27 => VK_OEM_1,
        0x28 => VK_OEM_7,
        0x29 => VK_OEM_3,
        0x2A => VK_LSHIFT,
        0x2B => VK_OEM_5,
        0x2C => 0x5A, // 'Z'
        0x2D => 0x58, // 'X'
        0x2E => 0x43, // 'C'
        0x2F => 0x56, // 'V'
        0x30 => 0x42, // 'B'
        0x31 => 0x4E, // 'N'
        0x32 => 0x4D, // 'M'
        0x33 => VK_OEM_COMMA,
        0x34 => VK_OEM_PERIOD,
        0x35 => VK_OEM_2,
        0x36 => VK_RSHIFT,
        0x37 => VK_MULTIPLY,
        0x38 => VK_LMENU,
        0x39 => VK_SPACE,
        0x3A => VK_CAPITAL,
        0x3B => VK_F1,
        0x3C => VK_F2,
        0x3D => VK_F3,
        0x3E => VK_F4,
        0x3F => VK_F5,
        0x40 => VK_F6,
        0x41 => VK_F7,
        0x42 => VK_F8,
        0x43 => VK_F9,
        0x44 => VK_F10,
        0x45 => VK_NUMLOCK,
        0x46 => VK_SCROLL,
        0x47 => VK_NUMPAD7,
        0x48 => VK_NUMPAD8,
        0x49 => VK_NUMPAD9,
        0x4A => VK_SUBTRACT,
        0x4B => VK_NUMPAD4,
        0x4C => VK_NUMPAD5,
        0x4D => VK_NUMPAD6,
        0x4E => VK_ADD,
        0x4F => VK_NUMPAD1,
        0x50 => VK_NUMPAD2,
        0x51 => VK_NUMPAD3,
        0x52 => VK_NUMPAD0,
        0x53 => VK_DECIMAL,
        0x57 => VK_F11,
        0x58 => VK_F12,
        0x5B => VK_LWIN,
        0x5C => VK_RWIN,
        0x5D => VK_APPS,
        _    => 0,
    }
}

/// Get the key name string for a given scan code (from lParam bits 16-23, bit 24 = extended).
fn scan_code_to_name(scan_code: u32, extended: bool) -> &'static str {
    if extended {
        match scan_code {
            0x1C => "Num Enter",
            0x1D => "Right Ctrl",
            0x35 => "Num /",
            0x38 => "Right Alt",
            0x45 => "Num Lock",
            0x47 => "Home",
            0x48 => "Up",
            0x49 => "Page Up",
            0x4B => "Left",
            0x4D => "Right",
            0x4F => "End",
            0x50 => "Down",
            0x51 => "Page Down",
            0x52 => "Insert",
            0x53 => "Delete",
            0x5B => "Left Windows",
            0x5C => "Right Windows",
            0x5D => "Applications",
            _    => "Unknown",
        }
    } else {
        match scan_code {
            0x01 => "Escape",
            0x02 => "1",
            0x03 => "2",
            0x04 => "3",
            0x05 => "4",
            0x06 => "5",
            0x07 => "6",
            0x08 => "7",
            0x09 => "8",
            0x0A => "9",
            0x0B => "0",
            0x0C => "-",
            0x0D => "=",
            0x0E => "Backspace",
            0x0F => "Tab",
            0x10 => "Q",
            0x11 => "W",
            0x12 => "E",
            0x13 => "R",
            0x14 => "T",
            0x15 => "Y",
            0x16 => "U",
            0x17 => "I",
            0x18 => "O",
            0x19 => "P",
            0x1A => "[",
            0x1B => "]",
            0x1C => "Enter",
            0x1D => "Left Ctrl",
            0x1E => "A",
            0x1F => "S",
            0x20 => "D",
            0x21 => "F",
            0x22 => "G",
            0x23 => "H",
            0x24 => "J",
            0x25 => "K",
            0x26 => "L",
            0x27 => ";",
            0x28 => "'",
            0x29 => "`",
            0x2A => "Left Shift",
            0x2B => "\\",
            0x2C => "Z",
            0x2D => "X",
            0x2E => "C",
            0x2F => "V",
            0x30 => "B",
            0x31 => "N",
            0x32 => "M",
            0x33 => ",",
            0x34 => ".",
            0x35 => "/",
            0x36 => "Right Shift",
            0x37 => "Num *",
            0x38 => "Left Alt",
            0x39 => "Space",
            0x3A => "Caps Lock",
            0x3B => "F1",
            0x3C => "F2",
            0x3D => "F3",
            0x3E => "F4",
            0x3F => "F5",
            0x40 => "F6",
            0x41 => "F7",
            0x42 => "F8",
            0x43 => "F9",
            0x44 => "F10",
            0x45 => "Num Lock",
            0x46 => "Scroll Lock",
            0x47 => "Num 7",
            0x48 => "Num 8",
            0x49 => "Num 9",
            0x4A => "Num -",
            0x4B => "Num 4",
            0x4C => "Num 5",
            0x4D => "Num 6",
            0x4E => "Num +",
            0x4F => "Num 1",
            0x50 => "Num 2",
            0x51 => "Num 3",
            0x52 => "Num 0",
            0x53 => "Num Del",
            0x57 => "F11",
            0x58 => "F12",
            _    => "Unknown",
        }
    }
}

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
        0x60..=0x69 => Some(vk - 0x60 + 0x30), // Numpad 0..9
        VK_SPACE => Some(b' ' as u32),
        VK_RETURN => Some(0x0D),
        VK_TAB => Some(0x09),
        VK_BACK => Some(0x08),
        VK_ESCAPE => Some(0x1B),
        0x6A => Some(b'*' as u32), // VK_MULTIPLY
        0x6B => Some(b'+' as u32), // VK_ADD
        0x6D => Some(b'-' as u32), // VK_SUBTRACT
        0x6E => Some(b'.' as u32), // VK_DECIMAL
        0x6F => Some(b'/' as u32), // VK_DIVIDE
        0xBA => Some(b';' as u32), // VK_OEM_1
        0xBB => Some(b'=' as u32), // VK_OEM_PLUS
        0xBC => Some(b',' as u32), // VK_OEM_COMMA
        0xBD => Some(b'-' as u32), // VK_OEM_MINUS
        0xBE => Some(b'.' as u32), // VK_OEM_PERIOD
        0xBF => Some(b'/' as u32), // VK_OEM_2
        0xC0 => Some(b'`' as u32), // VK_OEM_3
        0xDB => Some(b'[' as u32), // VK_OEM_4
        0xDC => Some(b'\\' as u32), // VK_OEM_5
        0xDD => Some(b']' as u32), // VK_OEM_6
        0xDE => Some(b'\'' as u32), // VK_OEM_7
        _ => None,
    }
}

pub extern "win64" fn MapVirtualKeyA(uCode: u32, uMapType: u32) -> u32 {
    match uMapType {
        MAPVK_VK_TO_CHAR => vk_to_char(uCode).unwrap_or(0),
        MAPVK_VK_TO_VSC => vk_to_scan_code(uCode),
        MAPVK_VSC_TO_VK => scan_code_to_vk(uCode),
        MAPVK_VSC_TO_VK_EX => scan_code_to_vk(uCode),
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
pub extern "win64" fn GetKeyNameTextW(l_param: i32, lp_string: *mut u16, cch_size: i32) -> i32 {
    if lp_string.is_null() || cch_size <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // lParam encoding: bits 16-23 = scan code, bit 24 = extended flag
    let scan_code = ((l_param >> 16) & 0xFF) as u32;
    let extended = (l_param & (1 << 24)) != 0;
    let name = scan_code_to_name(scan_code, extended);
    let text: Vec<u16> = name.encode_utf16().collect();
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
pub extern "win64" fn GetKeyNameTextA(l_param: i32, lp_string: *mut u8, cch_size: i32) -> i32 {
    if lp_string.is_null() || cch_size <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let scan_code = ((l_param >> 16) & 0xFF) as u32;
    let extended = (l_param & (1 << 24)) != 0;
    let name = scan_code_to_name(scan_code, extended);
    let text = name.as_bytes();
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
        let prev = KEY_STATE[vk as usize].load(std::sync::atomic::Ordering::Relaxed);
        let toggle = if matches!(vk, 0x14 | 0x90 | 0x91) {
            (prev & 0x01) ^ 0x01
        } else {
            prev & 0x01
        };
        KEY_STATE[vk as usize].store(0x80 | toggle, std::sync::atomic::Ordering::Relaxed);

        // Synchronize generic modifiers
        match vk {
            0xA0 | 0xA1 => {
                let prev_gen = KEY_STATE[0x10].load(std::sync::atomic::Ordering::Relaxed);
                KEY_STATE[0x10].store(0x80 | (prev_gen & 0x01), std::sync::atomic::Ordering::Relaxed);
            }
            0xA2 | 0xA3 => {
                let prev_gen = KEY_STATE[0x11].load(std::sync::atomic::Ordering::Relaxed);
                KEY_STATE[0x11].store(0x80 | (prev_gen & 0x01), std::sync::atomic::Ordering::Relaxed);
            }
            0xA4 | 0xA5 => {
                let prev_gen = KEY_STATE[0x12].load(std::sync::atomic::Ordering::Relaxed);
                KEY_STATE[0x12].store(0x80 | (prev_gen & 0x01), std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

pub fn set_key_up(vk: u32) {
    if (vk as usize) < KEY_STATE.len() {
        let prev = KEY_STATE[vk as usize].load(std::sync::atomic::Ordering::Relaxed);
        KEY_STATE[vk as usize].store(prev & 0x01, std::sync::atomic::Ordering::Relaxed);

        // Synchronize generic modifiers
        match vk {
            0xA0 | 0xA1 => {
                let other = if vk == 0xA0 { 0xA1 } else { 0xA0 };
                if (KEY_STATE[other].load(std::sync::atomic::Ordering::Relaxed) & 0x80) == 0 {
                    let prev_gen = KEY_STATE[0x10].load(std::sync::atomic::Ordering::Relaxed);
                    KEY_STATE[0x10].store(prev_gen & 0x01, std::sync::atomic::Ordering::Relaxed);
                }
            }
            0xA2 | 0xA3 => {
                let other = if vk == 0xA2 { 0xA3 } else { 0xA2 };
                if (KEY_STATE[other].load(std::sync::atomic::Ordering::Relaxed) & 0x80) == 0 {
                    let prev_gen = KEY_STATE[0x11].load(std::sync::atomic::Ordering::Relaxed);
                    KEY_STATE[0x11].store(prev_gen & 0x01, std::sync::atomic::Ordering::Relaxed);
                }
            }
            0xA4 | 0xA5 => {
                let other = if vk == 0xA4 { 0xA5 } else { 0xA4 };
                if (KEY_STATE[other].load(std::sync::atomic::Ordering::Relaxed) & 0x80) == 0 {
                    let prev_gen = KEY_STATE[0x12].load(std::sync::atomic::Ordering::Relaxed);
                    KEY_STATE[0x12].store(prev_gen & 0x01, std::sync::atomic::Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
}

pub fn is_key_down(vk: u32) -> bool {
    if (vk as usize) < KEY_STATE.len() {
        (KEY_STATE[vk as usize].load(std::sync::atomic::Ordering::Relaxed) & 0x80) != 0
    } else {
        false
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
        let high = if (state & 0x80) != 0 { -128i16 } else { 0i16 };
        let low = (state & 0x01) as i16;
        return high | low;
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
    fn get_key_name_text_w_returns_real_key_names() {
        // Escape: scan code 0x01 -> "Escape" (len 6)
        let mut out = [0u16; 16];
        let lparam = (0x01i32) << 16;
        let written = GetKeyNameTextW(lparam, out.as_mut_ptr(), out.len() as i32);
        assert_eq!(written, 6);
        let name = String::from_utf16_lossy(&out[..6]);
        assert_eq!(name, "Escape");

        // Extended Up arrow: scan code 0x48 + bit 24 -> "Up" (len 2)
        let lparam_up = ((0x48i32) << 16) | (1 << 24);
        let written_up = GetKeyNameTextW(lparam_up, out.as_mut_ptr(), out.len() as i32);
        assert_eq!(written_up, 2);
        let name_up = String::from_utf16_lossy(&out[..2]);
        assert_eq!(name_up, "Up");
    }

    #[test]
    fn vk_and_scan_code_conversions_work() {
        assert_eq!(vk_to_scan_code(VK_ESCAPE), 0x01);
        assert_eq!(scan_code_to_vk(0x01), VK_ESCAPE);

        assert_eq!(vk_to_scan_code('W' as u32), 0x11);
        assert_eq!(scan_code_to_vk(0x11), 'W' as u32);

        assert_eq!(vk_to_scan_code('A' as u32), 0x1E);
        assert_eq!(scan_code_to_vk(0x1E), 'A' as u32);

        assert_eq!(vk_to_scan_code('S' as u32), 0x1F);
        assert_eq!(scan_code_to_vk(0x1F), 'S' as u32);

        assert_eq!(vk_to_scan_code('D' as u32), 0x20);
        assert_eq!(scan_code_to_vk(0x20), 'D' as u32);

        assert_eq!(vk_to_scan_code(VK_RETURN), 0x1C);
        assert_eq!(scan_code_to_vk(0x1C), VK_RETURN);

        assert_eq!(MapVirtualKeyA('W' as u32, MAPVK_VK_TO_VSC), 0x11);
        assert_eq!(MapVirtualKeyA(0x11, MAPVK_VSC_TO_VK), 'W' as u32);

        // Extended key flags
        assert!(!is_extended_key('W' as u32));
        assert!(!is_extended_key(VK_ESCAPE));
        assert!(is_extended_key(VK_UP));
        assert!(is_extended_key(VK_DOWN));
        assert!(is_extended_key(VK_LEFT));
        assert!(is_extended_key(VK_RIGHT));
        assert!(is_extended_key(VK_INSERT));
        assert!(is_extended_key(VK_DELETE));
    }

    #[test]
    fn key_state_set_and_query_work() {
        let vk = 'Z' as u32;
        set_key_up(vk);
        assert!(!is_key_down(vk));

        set_key_down(vk);
        assert!(is_key_down(vk));
        assert_eq!(GetAsyncKeyState(vk as i32), -32768);

        set_key_up(vk);
        assert!(!is_key_down(vk));
        assert_eq!(GetAsyncKeyState(vk as i32), 0);
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
