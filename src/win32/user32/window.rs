#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_void, CStr};

use crate::utils::wide_string::from_wide_ptr;

use super::{
    create_window, enqueue_message, find_class, register_class, remove_window,
    set_window_visibility, update_window_rect, Msg, WndClassA, WndClassW, WM_CREATE, WM_DESTROY,
    WM_PAINT, WM_SHOWWINDOW,
};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_CANNOT_FIND_WND_CLASS: u32 = 1407;

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

unsafe fn c_string(ptr: *const i8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    CStr::from_ptr(ptr).to_str().ok().map(ToOwned::to_owned)
}

unsafe fn wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    from_wide_ptr(ptr).ok()
}

pub extern "win64" fn RegisterClassA(lpWndClass: *const WndClassA) -> u16 {
    if lpWndClass.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let class = unsafe { &*lpWndClass };
    let Some(class_name) = (unsafe { c_string(class.lpszClassName) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let atom = register_class(&class_name, class.lpfnWndProc);
    set_last_error(ERROR_SUCCESS);
    atom
}

pub extern "win64" fn RegisterClassW(lpWndClass: *const WndClassW) -> u16 {
    if lpWndClass.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let class = unsafe { &*lpWndClass };
    let Some(class_name) = (unsafe { wide_string(class.lpszClassName) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let atom = register_class(&class_name, class.lpfnWndProc);
    set_last_error(ERROR_SUCCESS);
    atom
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn CreateWindowExA(
    _dwExStyle: u32,
    lpClassName: *const i8,
    lpWindowName: *const i8,
    _dwStyle: u32,
    x: i32,
    y: i32,
    nWidth: i32,
    nHeight: i32,
    _hWndParent: usize,
    _hMenu: usize,
    _hInstance: usize,
    lpParam: *const c_void,
) -> usize {
    let Some(class_name) = (unsafe { c_string(lpClassName) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let Some(registered_class) = find_class(&class_name) else {
        set_last_error(ERROR_CANNOT_FIND_WND_CLASS);
        return 0;
    };

    let title = unsafe { c_string(lpWindowName) }.unwrap_or_default();

    let hwnd = create_window(registered_class.wnd_proc, title, x, y, nWidth, nHeight);
    enqueue_message(Msg {
        hwnd,
        message: WM_CREATE,
        wParam: 0,
        lParam: lpParam as isize,
        time: 0,
        ..Default::default()
    });

    set_last_error(ERROR_SUCCESS);
    hwnd
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn CreateWindowExW(
    dwExStyle: u32,
    lpClassName: *const u16,
    lpWindowName: *const u16,
    dwStyle: u32,
    x: i32,
    y: i32,
    nWidth: i32,
    nHeight: i32,
    hWndParent: usize,
    hMenu: usize,
    hInstance: usize,
    lpParam: *const c_void,
) -> usize {
    let Some(class_name) = (unsafe { wide_string(lpClassName) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let class_c = std::ffi::CString::new(class_name).ok();
    let title = unsafe { wide_string(lpWindowName) }.unwrap_or_default();
    let title_c = std::ffi::CString::new(title).ok();

    let Some(class_c) = class_c else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    CreateWindowExA(
        dwExStyle,
        class_c.as_ptr(),
        title_c.as_ref().map_or(std::ptr::null(), |t| t.as_ptr()),
        dwStyle,
        x,
        y,
        nWidth,
        nHeight,
        hWndParent,
        hMenu,
        hInstance,
        lpParam,
    )
}

pub extern "win64" fn ShowWindow(hWnd: usize, nCmdShow: i32) -> i32 {
    let visible = nCmdShow != 0;
    if !set_window_visibility(hWnd, visible) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    enqueue_message(Msg {
        hwnd: hWnd,
        message: WM_SHOWWINDOW,
        wParam: usize::from(visible),
        lParam: nCmdShow as isize,
        time: 0,
        ..Default::default()
    });

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn MoveWindow(
    hWnd: usize,
    X: i32,
    Y: i32,
    nWidth: i32,
    nHeight: i32,
    bRepaint: i32,
) -> i32 {
    if !update_window_rect(hWnd, X, Y, nWidth, nHeight) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    if bRepaint != 0 {
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_PAINT,
            wParam: 0,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SetWindowPos(
    hWnd: usize,
    _hWndInsertAfter: usize,
    X: i32,
    Y: i32,
    cx: i32,
    cy: i32,
    _uFlags: u32,
) -> i32 {
    if !update_window_rect(hWnd, X, Y, cx, cy) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DestroyWindow(hWnd: usize) -> i32 {
    if !remove_window(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    enqueue_message(Msg {
        hwnd: hWnd,
        message: WM_DESTROY,
        wParam: 0,
        lParam: 0,
        time: 0,
        ..Default::default()
    });

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DefWindowProcA(
    _hWnd: usize,
    _uMsg: u32,
    _wParam: usize,
    _lParam: isize,
) -> isize {
    0
}

pub extern "win64" fn DefWindowProcW(
    _hWnd: usize,
    _uMsg: u32,
    _wParam: usize,
    _lParam: isize,
) -> isize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use crate::win32::user32::{message, Msg};

    unsafe extern "win64" fn test_proc(
        _hwnd: usize,
        _msg: u32,
        _wparam: usize,
        _lparam: isize,
    ) -> isize {
        0
    }

    #[test]
    fn window_lifecycle_operations_queue_expected_messages() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("WindowLifecycleClass").expect("class");
        let wnd_class = WndClassA {
            style: 0,
            lpfnWndProc: Some(test_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: 0,
            hIcon: 0,
            hCursor: 0,
            hbrBackground: 0,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        assert_ne!(RegisterClassA(&raw const wnd_class), 0);

        let title = std::ffi::CString::new("Lifecycle").expect("title");
        let hwnd = CreateWindowExA(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            10,
            20,
            300,
            200,
            0,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(hwnd, 0);

        let mut msg = Msg::default();
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, 0, 0), 1);
        assert_eq!(msg.message, WM_CREATE);

        assert_eq!(ShowWindow(hwnd, 1), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_SHOWWINDOW, WM_SHOWWINDOW), 1);
        assert_eq!(msg.message, WM_SHOWWINDOW);

        assert_eq!(MoveWindow(hwnd, 30, 40, 500, 300, 1), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_PAINT, WM_PAINT), 1);
        assert_eq!(msg.message, WM_PAINT);

        assert_eq!(SetWindowPos(hwnd, 0, 50, 60, 640, 480, 0), 1);
        assert_eq!(DestroyWindow(hwnd), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_DESTROY, WM_DESTROY), 1);
        assert_eq!(msg.message, WM_DESTROY);
    }
}
