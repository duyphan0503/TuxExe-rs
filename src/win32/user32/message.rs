#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use super::{
    enqueue_message, message_matches_filter, message_queue, window_exists, window_proc_for, Msg,
    WM_CHAR, WM_KEYDOWN, WM_QUIT,
};

const PM_REMOVE: u32 = 0x0001;
const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

fn peek_or_pop_filtered(
    hwnd_filter: usize,
    min_filter: u32,
    max_filter: u32,
    remove: bool,
) -> Option<Msg> {
    let (queue, _) = message_queue();
    let mut guard = queue.lock().expect("message queue poisoned");
    let idx = guard
        .iter()
        .position(|msg| message_matches_filter(msg, hwnd_filter, min_filter, max_filter))?;

    if remove {
        guard.remove(idx)
    } else {
        guard.get(idx).copied()
    }
}

fn get_message_blocking(hwnd_filter: usize, min_filter: u32, max_filter: u32) -> Msg {
    let (queue, condvar) = message_queue();
    let mut guard = queue.lock().expect("message queue poisoned");

    loop {
        if let Some(index) = guard
            .iter()
            .position(|msg| message_matches_filter(msg, hwnd_filter, min_filter, max_filter))
        {
            return guard.remove(index).expect("index must exist for a filtered message removal");
        }

        guard = condvar.wait(guard).expect("message queue poisoned");
    }
}

pub extern "win64" fn GetMessageA(
    lpMsg: *mut Msg,
    hWnd: usize,
    wMsgFilterMin: u32,
    wMsgFilterMax: u32,
) -> i32 {
    if lpMsg.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return -1;
    }

    let message = get_message_blocking(hWnd, wMsgFilterMin, wMsgFilterMax);
    unsafe {
        *lpMsg = message;
    }

    set_last_error(ERROR_SUCCESS);
    if message.message == WM_QUIT {
        0
    } else {
        1
    }
}

pub extern "win64" fn GetMessageW(
    lpMsg: *mut Msg,
    hWnd: usize,
    wMsgFilterMin: u32,
    wMsgFilterMax: u32,
) -> i32 {
    GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)
}

pub extern "win64" fn PeekMessageA(
    lpMsg: *mut Msg,
    hWnd: usize,
    wMsgFilterMin: u32,
    wMsgFilterMax: u32,
    wRemoveMsg: u32,
) -> i32 {
    if lpMsg.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let remove = wRemoveMsg & PM_REMOVE != 0;
    let Some(message) = peek_or_pop_filtered(hWnd, wMsgFilterMin, wMsgFilterMax, remove) else {
        set_last_error(ERROR_SUCCESS);
        return 0;
    };

    unsafe {
        *lpMsg = message;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn PeekMessageW(
    lpMsg: *mut Msg,
    hWnd: usize,
    wMsgFilterMin: u32,
    wMsgFilterMax: u32,
    wRemoveMsg: u32,
) -> i32 {
    PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg)
}

pub extern "win64" fn TranslateMessage(lpMsg: *const Msg) -> i32 {
    if lpMsg.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let message = unsafe { *lpMsg };
    if message.message == WM_KEYDOWN {
        if let Some(ch) = super::input::vk_to_char(message.wParam as u32) {
            enqueue_message(super::Msg {
                hwnd: message.hwnd,
                message: WM_CHAR,
                wParam: ch as usize,
                lParam: message.lParam,
                time: 0,
                ..Default::default()
            });
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DispatchMessageA(lpMsg: *const Msg) -> isize {
    if lpMsg.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let message = unsafe { *lpMsg };
    if message.message == WM_QUIT {
        set_last_error(ERROR_SUCCESS);
        return message.wParam as isize;
    }

    let result = if let Some(wnd_proc) = window_proc_for(message.hwnd) {
        unsafe { wnd_proc(message.hwnd, message.message, message.wParam, message.lParam) }
    } else {
        super::window::DefWindowProcA(message.hwnd, message.message, message.wParam, message.lParam)
    };

    set_last_error(ERROR_SUCCESS);
    result
}

pub extern "win64" fn DispatchMessageW(lpMsg: *const Msg) -> isize {
    DispatchMessageA(lpMsg)
}

pub extern "win64" fn PostQuitMessage(nExitCode: i32) {
    enqueue_message(Msg {
        hwnd: 0,
        message: WM_QUIT,
        wParam: nExitCode as usize,
        lParam: 0,
        time: 0,
        ..Default::default()
    });
}

pub extern "win64" fn PostMessageA(hWnd: usize, Msg: u32, wParam: usize, lParam: isize) -> i32 {
    if hWnd != 0 && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    enqueue_message(super::Msg {
        hwnd: hWnd,
        message: Msg,
        wParam,
        lParam,
        time: 0,
        ..Default::default()
    });

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn PostMessageW(hWnd: usize, Msg: u32, wParam: usize, lParam: isize) -> i32 {
    PostMessageA(hWnd, Msg, wParam, lParam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use crate::win32::user32::{window, WndClassA, WM_CHAR, WM_CREATE, WM_KEYDOWN};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DISPATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "win64" fn test_proc(
        _hwnd: usize,
        _msg: u32,
        _wparam: usize,
        _lparam: isize,
    ) -> isize {
        DISPATCH_COUNT.fetch_add(1, Ordering::SeqCst);
        123
    }

    #[test]
    fn post_and_get_message_round_trip() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("TestWindowClass").expect("class name");
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

        assert_ne!(window::RegisterClassA(&raw const wnd_class), 0);

        let title = std::ffi::CString::new("Test Window").expect("title");
        let hwnd = window::CreateWindowExA(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            100,
            100,
            640,
            480,
            0,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(hwnd, 0);

        let mut msg = Msg::default();
        assert_eq!(GetMessageA(&raw mut msg, hwnd, 0, 0), 1);
        assert_eq!(msg.message, WM_CREATE);

        assert_eq!(PostMessageA(hwnd, 0x0400, 42, 24), 1);
        assert_eq!(GetMessageA(&raw mut msg, hwnd, 0x0400, 0x0400), 1);
        assert_eq!(msg.message, 0x0400);
        assert_eq!(msg.wParam, 42);
        assert_eq!(msg.lParam, 24);

        let dispatch_result = DispatchMessageA(&raw const msg);
        assert_eq!(dispatch_result, 123);
        assert_eq!(DISPATCH_COUNT.load(Ordering::SeqCst), 1);

        assert_eq!(window::DestroyWindow(hwnd), 1);
    }

    #[test]
    fn translate_message_posts_wm_char_for_keydown() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("TranslateWindowClass").expect("class name");
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
        assert_ne!(window::RegisterClassA(&raw const wnd_class), 0);

        let title = std::ffi::CString::new("Translate Window").expect("title");
        let hwnd = window::CreateWindowExA(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            320,
            240,
            0,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(hwnd, 0);

        let mut msg = Msg::default();
        assert_eq!(GetMessageA(&raw mut msg, hwnd, 0, 0), 1);
        assert_eq!(msg.message, WM_CREATE);

        assert_eq!(PostMessageA(hwnd, WM_KEYDOWN, 'A' as usize, 0), 1);
        assert_eq!(GetMessageA(&raw mut msg, hwnd, WM_KEYDOWN, WM_KEYDOWN), 1);
        assert_eq!(msg.message, WM_KEYDOWN);

        assert_eq!(TranslateMessage(&raw const msg), 1);
        assert_eq!(GetMessageA(&raw mut msg, hwnd, WM_CHAR, WM_CHAR), 1);
        assert_eq!(msg.message, WM_CHAR);
        assert_eq!(msg.wParam, 'A' as usize);

        assert_eq!(window::DestroyWindow(hwnd), 1);
    }
}
