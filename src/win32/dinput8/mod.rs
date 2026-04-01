#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

const ERROR_SUCCESS: i32 = 0;
const ERROR_INVALID_PARAMETER: i32 = 87;

const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;

const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;

const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxInputEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectInputEvent {
    KeyDown(u32),
    KeyUp(u32),
    MouseMove { dx: i32, dy: i32 },
    ButtonDown(u8),
    ButtonUp(u8),
}

pub fn map_evdev_event(event: LinuxInputEvent) -> Option<DirectInputEvent> {
    match event.event_type {
        EV_KEY => {
            if let Some(button_id) = map_button_code(event.code) {
                return Some(if event.value != 0 {
                    DirectInputEvent::ButtonDown(button_id)
                } else {
                    DirectInputEvent::ButtonUp(button_id)
                });
            }

            let dik = map_libinput_key_to_dik(event.code as u32);
            if dik == 0 {
                return None;
            }

            if event.value != 0 {
                Some(DirectInputEvent::KeyDown(dik))
            } else {
                Some(DirectInputEvent::KeyUp(dik))
            }
        }
        EV_REL => match event.code {
            REL_X => Some(DirectInputEvent::MouseMove { dx: event.value, dy: 0 }),
            REL_Y => Some(DirectInputEvent::MouseMove { dx: 0, dy: event.value }),
            _ => None,
        },
        _ => None,
    }
}

pub fn map_libinput_key_to_dik(scancode: u32) -> u32 {
    match scancode {
        // Letter row
        30 => 0x1E, // A
        31 => 0x1F, // S
        32 => 0x20, // D
        33 => 0x21, // F
        34 => 0x22, // G
        35 => 0x23, // H
        36 => 0x24, // J
        37 => 0x25, // K
        38 => 0x26, // L
        // Number row
        2 => 0x02,  // 1
        3 => 0x03,  // 2
        4 => 0x04,  // 3
        5 => 0x05,  // 4
        6 => 0x06,  // 5
        7 => 0x07,  // 6
        8 => 0x08,  // 7
        9 => 0x09,  // 8
        10 => 0x0A, // 9
        11 => 0x0B, // 0
        // Arrows
        103 => 0xC8, // Up
        108 => 0xD0, // Down
        105 => 0xCB, // Left
        106 => 0xCD, // Right
        _ => 0,
    }
}

fn map_button_code(code: u16) -> Option<u8> {
    match code {
        BTN_LEFT => Some(0),
        BTN_RIGHT => Some(1),
        BTN_MIDDLE => Some(2),
        _ => None,
    }
}

fn next_direct_input_handle() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0xD100_0000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn set_last_error(value: i32) {
    crate::win32::kernel32::error::set_last_error(value as u32);
}

pub extern "win64" fn DirectInput8Create(
    _hinst: usize,
    _version: u32,
    _riidltf: *const c_void,
    ppvOut: *mut usize,
    _punkOuter: *mut c_void,
) -> i32 {
    if ppvOut.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }

    unsafe {
        *ppvOut = next_direct_input_handle();
    }

    set_last_error(ERROR_SUCCESS);
    ERROR_SUCCESS
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("DirectInput8Create", DirectInput8Create as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_keyboard_events() {
        let down = map_evdev_event(LinuxInputEvent { event_type: EV_KEY, code: 30, value: 1 });
        assert_eq!(down, Some(DirectInputEvent::KeyDown(0x1E)));

        let up = map_evdev_event(LinuxInputEvent { event_type: EV_KEY, code: 30, value: 0 });
        assert_eq!(up, Some(DirectInputEvent::KeyUp(0x1E)));
    }

    #[test]
    fn maps_mouse_events() {
        let move_x =
            map_evdev_event(LinuxInputEvent { event_type: EV_REL, code: REL_X, value: 12 });
        assert_eq!(move_x, Some(DirectInputEvent::MouseMove { dx: 12, dy: 0 }));

        let click =
            map_evdev_event(LinuxInputEvent { event_type: EV_KEY, code: BTN_LEFT, value: 1 });
        assert_eq!(click, Some(DirectInputEvent::ButtonDown(0)));
    }
}
