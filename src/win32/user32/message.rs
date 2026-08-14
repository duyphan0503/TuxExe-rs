#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use super::{
    enqueue_message, message_matches_filter, message_queue, window_exists, window_proc_for, Msg,
    WM_CHAR, WM_KEYDOWN, WM_QUIT,
};
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::{Mutex, OnceLock};

const PM_REMOVE: u32 = 0x0001;
const WM_SETTEXT: u32 = 0x000C;
const REGISTERED_MESSAGE_BASE: u32 = 0xC000;
const REGISTERED_MESSAGE_MAX: u32 = 0xFFFF;
const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

fn message_extra_info() -> &'static Mutex<isize> {
    static EXTRA_INFO: OnceLock<Mutex<isize>> = OnceLock::new();
    EXTRA_INFO.get_or_init(|| Mutex::new(0))
}

fn registered_messages() -> &'static Mutex<HashMap<String, u32>> {
    static REGISTERED: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
    REGISTERED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_registered_message() -> &'static Mutex<u32> {
    static NEXT: OnceLock<Mutex<u32>> = OnceLock::new();
    NEXT.get_or_init(|| Mutex::new(REGISTERED_MESSAGE_BASE))
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
    crate::platform::x11::pump_x11_events();
    let (queue, condvar) = message_queue();
    let mut guard = queue.lock().expect("message queue poisoned");

    loop {
        if let Some(index) = guard
            .iter()
            .position(|msg| message_matches_filter(msg, hwnd_filter, min_filter, max_filter))
        {
            return guard.remove(index).expect("index must exist for a filtered message removal");
        }

        crate::platform::x11::pump_x11_events();
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

    crate::platform::x11::pump_x11_events();
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

pub extern "win64" fn SendMessageA(hWnd: usize, Msg: u32, wParam: usize, lParam: isize) -> isize {
    if hWnd != 0 && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let result = if let Some(wnd_proc) = window_proc_for(hWnd) {
        unsafe { wnd_proc(hWnd, Msg, wParam, lParam) }
    } else {
        super::window::DefWindowProcA(hWnd, Msg, wParam, lParam)
    };

    set_last_error(ERROR_SUCCESS);
    result
}

pub extern "win64" fn SendMessageW(hWnd: usize, Msg: u32, wParam: usize, lParam: isize) -> isize {
    SendMessageA(hWnd, Msg, wParam, lParam)
}

pub extern "win64" fn GetDlgItem(hDlg: usize, _nIDDlgItem: i32) -> usize {
    if hDlg != 0 && !window_exists(hDlg) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    0
}

pub extern "win64" fn SendDlgItemMessageA(
    hDlg: usize,
    nIDDlgItem: i32,
    Msg: u32,
    wParam: usize,
    lParam: isize,
) -> isize {
    let target = GetDlgItem(hDlg, nIDDlgItem);
    if target != 0 {
        SendMessageA(target, Msg, wParam, lParam)
    } else {
        SendMessageA(hDlg, Msg, wParam, lParam)
    }
}

pub extern "win64" fn SendDlgItemMessageW(
    hDlg: usize,
    nIDDlgItem: i32,
    Msg: u32,
    wParam: usize,
    lParam: isize,
) -> isize {
    SendDlgItemMessageA(hDlg, nIDDlgItem, Msg, wParam, lParam)
}

pub extern "win64" fn SetDlgItemTextA(hDlg: usize, nIDDlgItem: i32, lpString: *const i8) -> i32 {
    if hDlg != 0 && !window_exists(hDlg) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let _ = SendDlgItemMessageA(hDlg, nIDDlgItem, WM_SETTEXT, 0, lpString as isize);
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SetDlgItemTextW(hDlg: usize, nIDDlgItem: i32, lpString: *const u16) -> i32 {
    if hDlg != 0 && !window_exists(hDlg) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let _ = SendDlgItemMessageW(hDlg, nIDDlgItem, WM_SETTEXT, 0, lpString as isize);
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn SendMessageTimeoutA(
    hWnd: usize,
    Msg: u32,
    wParam: usize,
    lParam: isize,
    _fuFlags: u32,
    _uTimeout: u32,
    lpdwResult: *mut usize,
) -> isize {
    let result = SendMessageA(hWnd, Msg, wParam, lParam);
    if !lpdwResult.is_null() {
        unsafe {
            *lpdwResult = result as usize;
        }
    }
    set_last_error(ERROR_SUCCESS);
    result
}

pub extern "win64" fn SendMessageTimeoutW(
    hWnd: usize,
    Msg: u32,
    wParam: usize,
    lParam: isize,
    fuFlags: u32,
    uTimeout: u32,
    lpdwResult: *mut usize,
) -> isize {
    SendMessageTimeoutA(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult)
}

pub extern "win64" fn RegisterWindowMessageA(lpString: *const i8) -> u32 {
    if lpString.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let key = unsafe { CStr::from_ptr(lpString) }.to_string_lossy().to_string();
    if key.is_empty() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut map = registered_messages().lock().expect("registered message map poisoned");
    if let Some(existing) = map.get(&key) {
        set_last_error(ERROR_SUCCESS);
        return *existing;
    }

    let mut next = next_registered_message().lock().expect("registered message counter poisoned");
    let message = *next;
    if message > REGISTERED_MESSAGE_MAX {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    map.insert(key, message);
    *next = message.saturating_add(1);
    set_last_error(ERROR_SUCCESS);
    message
}

pub extern "win64" fn RegisterWindowMessageW(lpString: *const u16) -> u32 {
    if lpString.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let Ok(key) = (unsafe { crate::utils::wide_string::from_wide_ptr(lpString) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    let mut utf8 = key.into_bytes();
    utf8.push(0);
    RegisterWindowMessageA(utf8.as_ptr().cast())
}

pub extern "win64" fn GetMessageExtraInfo() -> isize {
    set_last_error(ERROR_SUCCESS);
    *message_extra_info().lock().expect("message extra info poisoned")
}

pub extern "win64" fn SetMessageExtraInfo(l_param: isize) -> isize {
    let mut extra = message_extra_info().lock().expect("message extra info poisoned");
    let previous = *extra;
    *extra = l_param;
    set_last_error(ERROR_SUCCESS);
    previous
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
        DISPATCH_COUNT.store(0, Ordering::SeqCst);

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
        DISPATCH_COUNT.store(0, Ordering::SeqCst);

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

    #[test]
    fn message_extra_info_roundtrip() {
        let _guard = serial_guard();
        let previous = SetMessageExtraInfo(0x1234);
        assert_eq!(GetMessageExtraInfo(), 0x1234);
        let _ = SetMessageExtraInfo(previous);
    }

    #[test]
    fn send_message_calls_window_proc() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("SendMessageClass").expect("class name");
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

        let title = std::ffi::CString::new("SendMessage Window").expect("title");
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

        let mut create_msg = Msg::default();
        assert_eq!(GetMessageA(&raw mut create_msg, hwnd, 0, 0), 1);
        assert_eq!(create_msg.message, WM_CREATE);

        DISPATCH_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(SendMessageW(hwnd, 0x0400, 7, 8), 123);
        assert_eq!(DISPATCH_COUNT.load(Ordering::SeqCst), 1);

        assert_eq!(SendDlgItemMessageW(hwnd, 100, 0x0400, 9, 10), 123);
        assert_eq!(DISPATCH_COUNT.load(Ordering::SeqCst), 2);

        assert_eq!(SetDlgItemTextW(hwnd, 100, std::ptr::null()), 1);
        assert_eq!(DISPATCH_COUNT.load(Ordering::SeqCst), 3);

        let mut timeout_result = 0usize;
        assert_eq!(
            SendMessageTimeoutA(hwnd, 0x0400, 1, 2, 0, 100, &mut timeout_result as *mut usize),
            123
        );
        assert_eq!(timeout_result, 123);
        assert_eq!(DISPATCH_COUNT.load(Ordering::SeqCst), 4);

        assert_eq!(window::DestroyWindow(hwnd), 1);
    }

    #[test]
    fn register_window_message_is_stable_for_same_name() {
        let _guard = serial_guard();

        let name = std::ffi::CString::new("TuxExe.Custom.Message").expect("message name");
        let id1 = RegisterWindowMessageA(name.as_ptr());
        let id2 = RegisterWindowMessageA(name.as_ptr());
        assert!(id1 >= REGISTERED_MESSAGE_BASE);
        assert_eq!(id1, id2);
    }
}
