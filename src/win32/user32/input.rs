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
}
