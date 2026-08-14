#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_void, CStr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::utils::wide_string::from_wide_ptr;

use super::{
    create_window_with_parent, create_window_with_parent_and_handle, enqueue_message, find_class,
    is_window_visible, message_queue, register_class, remove_window, set_window_visibility,
    update_window_rect, window_exists, window_origin, window_parent, window_rect, Msg, WndClassA,
    WndClassW, HTCLIENT, WA_ACTIVE, WM_ACTIVATE, WM_ACTIVATEAPP, WM_CREATE, WM_DESTROY,
    WM_ERASEBKGND, WM_KILLFOCUS, WM_NCHITTEST, WM_PAINT, WM_SETCURSOR, WM_SETFOCUS, WM_SHOWWINDOW,
};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_CANNOT_FIND_WND_CLASS: u32 = 1407;
const SW_SHOWNORMAL: u32 = 1;
const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const USER_OBJECT_HANDLE: usize = 0x50_0000;
const UOI_FLAGS: i32 = 1;
const UOI_NAME: i32 = 2;
const UOI_TYPE: i32 = 3;
const SPI_GETBEEP: u32 = 0x0001;
const SPI_GETMOUSE: u32 = 0x0003;
const SPI_GETKEYBOARDSPEED: u32 = 0x000A;
const SPI_GETSCREENSAVEACTIVE: u32 = 0x0010;
const SPI_GETKEYBOARDDELAY: u32 = 0x0016;
const SPI_GETDRAGFULLWINDOWS: u32 = 0x0026;
const SPI_GETWORKAREA: u32 = 0x0030;
const SPI_GETMOUSESPEED: u32 = 0x0070;
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const SM_CYCAPTION: i32 = 4;
const SM_CXBORDER: i32 = 5;
const SM_CYBORDER: i32 = 6;
const SM_CXDLGFRAME: i32 = 7;
const SM_CYDLGFRAME: i32 = 8;
const SM_CXCURSOR: i32 = 13;
const SM_CYCURSOR: i32 = 14;
const SM_CXFULLSCREEN: i32 = 16;
const SM_CYFULLSCREEN: i32 = 17;
const SM_MOUSEPRESENT: i32 = 19;
const SM_SWAPBUTTON: i32 = 23;
const SM_CXFRAME: i32 = 32;
const SM_CYFRAME: i32 = 33;
const SM_CXMAXIMIZED: i32 = 61;
const SM_CYMAXIMIZED: i32 = 62;
const SM_XVIRTUALSCREEN: i32 = 76;
const SM_YVIRTUALSCREEN: i32 = 77;
const SM_CXVIRTUALSCREEN: i32 = 78;
const SM_CYVIRTUALSCREEN: i32 = 79;
const SM_CMONITORS: i32 = 80;
const SM_REMOTESESSION: i32 = 0x1000;
const DESKTOP_WINDOW_HANDLE: usize = 0x30_0000;
const PRIMARY_MONITOR_HANDLE: usize = 0x31_0000;
const CF_TEXT: u32 = 1;
const CF_UNICODETEXT: u32 = 13;
const CLIPBOARD_CUSTOM_FORMAT_BASE: u32 = 0xC000;
const TME_HOVER: u32 = 0x0000_0001;
const TME_LEAVE: u32 = 0x0000_0002;
const TME_QUERY: u32 = 0x4000_0000;
const TME_CANCEL: u32 = 0x8000_0000;
const MONITORINFOF_PRIMARY: u32 = 1;
const MONITOR_DEFAULTTONULL: u32 = 0;
const MONITOR_DEFAULTTOPRIMARY: u32 = 1;
const MONITOR_DEFAULTTONEAREST: u32 = 2;
const DISPLAY_DEVICE_PRIMARY_DEVICE: u32 = 0x0000_0004;
const DISPLAY_DEVICE_ACTIVE: u32 = 0x0000_0001;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowPlacement {
    pub length: u32,
    pub flags: u32,
    pub show_cmd: u32,
    pub pt_min_position: super::Point,
    pub pt_max_position: super::Point,
    pub rc_normal_position: Rect,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrackMouseEventInfo {
    pub cb_size: u32,
    pub dw_flags: u32,
    pub hwnd_track: usize,
    pub dw_hover_time: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DisplayConfigDeviceInfoHeader {
    pub r#type: u32,
    pub size: u32,
    pub adapter_id: i64,
    pub id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MonitorInfo {
    pub cb_size: u32,
    pub rc_monitor: Rect,
    pub rc_work: Rect,
    pub dw_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MonitorInfoExW {
    pub monitor_info: MonitorInfo,
    pub sz_device: [u16; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MonitorInfoExA {
    pub monitor_info: MonitorInfo,
    pub sz_device: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DisplayDeviceA {
    pub cb: u32,
    pub device_name: [u8; 32],
    pub device_string: [u8; 128],
    pub state_flags: u32,
    pub device_id: [u8; 128],
    pub device_key: [u8; 128],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DisplayDeviceW {
    pub cb: u32,
    pub device_name: [u16; 32],
    pub device_string: [u16; 128],
    pub state_flags: u32,
    pub device_id: [u16; 128],
    pub device_key: [u16; 128],
}

impl Default for MonitorInfoExW {
    fn default() -> Self {
        Self { monitor_info: MonitorInfo::default(), sz_device: [0; 32] }
    }
}

impl Default for MonitorInfoExA {
    fn default() -> Self {
        Self { monitor_info: MonitorInfo::default(), sz_device: [0; 32] }
    }
}

impl Default for DisplayDeviceA {
    fn default() -> Self {
        Self {
            cb: std::mem::size_of::<DisplayDeviceA>() as u32,
            device_name: [0; 32],
            device_string: [0; 128],
            state_flags: 0,
            device_id: [0; 128],
            device_key: [0; 128],
        }
    }
}

impl Default for DisplayDeviceW {
    fn default() -> Self {
        Self {
            cb: std::mem::size_of::<DisplayDeviceW>() as u32,
            device_name: [0; 32],
            device_string: [0; 128],
            state_flags: 0,
            device_id: [0; 128],
            device_key: [0; 128],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WndClassExA {
    pub cbSize: u32,
    pub style: u32,
    pub lpfnWndProc: Option<super::WindowProc>,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: usize,
    pub hIcon: usize,
    pub hCursor: usize,
    pub hbrBackground: usize,
    pub lpszMenuName: *const i8,
    pub lpszClassName: *const i8,
    pub hIconSm: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WndClassExW {
    pub cbSize: u32,
    pub style: u32,
    pub lpfnWndProc: Option<super::WindowProc>,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: usize,
    pub hIcon: usize,
    pub hCursor: usize,
    pub hbrBackground: usize,
    pub lpszMenuName: *const u16,
    pub lpszClassName: *const u16,
    pub hIconSm: usize,
}

pub type WndEnumProc = unsafe extern "win64" fn(usize, isize) -> i32;
pub type MonitorEnumProc = unsafe extern "win64" fn(usize, usize, *const Rect, isize) -> i32;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserObjectFlags {
    pub f_inherit: i32,
    pub f_reserved: i32,
    pub dw_flags: u32,
}

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

fn window_longs() -> &'static Mutex<std::collections::HashMap<(usize, i32), isize>> {
    static WINDOW_LONGS: OnceLock<Mutex<std::collections::HashMap<(usize, i32), isize>>> =
        OnceLock::new();
    WINDOW_LONGS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn cursor_position() -> &'static Mutex<super::Point> {
    static CURSOR_POS: OnceLock<Mutex<super::Point>> = OnceLock::new();
    CURSOR_POS.get_or_init(|| Mutex::new(super::Point { x: 0, y: 0 }))
}

fn capture_window() -> &'static Mutex<usize> {
    static CAPTURED_HWND: OnceLock<Mutex<usize>> = OnceLock::new();
    CAPTURED_HWND.get_or_init(|| Mutex::new(0))
}

fn active_cursor() -> &'static Mutex<usize> {
    static ACTIVE_CURSOR: OnceLock<Mutex<usize>> = OnceLock::new();
    ACTIVE_CURSOR.get_or_init(|| Mutex::new(0))
}

fn foreground_window() -> &'static AtomicUsize {
    static FOREGROUND_HWND: AtomicUsize = AtomicUsize::new(0);
    &FOREGROUND_HWND
}

fn is_desktop_window(hwnd: usize) -> bool {
    hwnd == DESKTOP_WINDOW_HANDLE
}

fn next_image_handle() -> usize {
    static NEXT_IMAGE: AtomicUsize = AtomicUsize::new(0x52_0000);
    NEXT_IMAGE.fetch_add(1, Ordering::Relaxed)
}

fn clipboard_data() -> &'static Mutex<std::collections::HashMap<u32, usize>> {
    static CLIPBOARD_DATA: OnceLock<Mutex<std::collections::HashMap<u32, usize>>> = OnceLock::new();
    CLIPBOARD_DATA.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn clipboard_format_registry() -> &'static Mutex<std::collections::HashMap<String, u32>> {
    static CLIPBOARD_FORMATS: OnceLock<Mutex<std::collections::HashMap<String, u32>>> =
        OnceLock::new();
    CLIPBOARD_FORMATS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn next_clipboard_custom_format() -> &'static AtomicUsize {
    static NEXT_FORMAT: AtomicUsize = AtomicUsize::new(CLIPBOARD_CUSTOM_FORMAT_BASE as usize);
    &NEXT_FORMAT
}

fn tracked_mouse_events() -> &'static Mutex<std::collections::HashMap<usize, (u32, u32)>> {
    static TRACKED_MOUSE_EVENTS: OnceLock<Mutex<std::collections::HashMap<usize, (u32, u32)>>> =
        OnceLock::new();
    TRACKED_MOUSE_EVENTS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
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

pub extern "win64" fn RegisterClassExA(lpWndClassEx: *const WndClassExA) -> u16 {
    if lpWndClassEx.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let class_ex = unsafe { &*lpWndClassEx };
    if class_ex.cbSize < std::mem::size_of::<WndClassExA>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let class = WndClassA {
        style: class_ex.style,
        lpfnWndProc: class_ex.lpfnWndProc,
        cbClsExtra: class_ex.cbClsExtra,
        cbWndExtra: class_ex.cbWndExtra,
        hInstance: class_ex.hInstance,
        hIcon: class_ex.hIcon,
        hCursor: class_ex.hCursor,
        hbrBackground: class_ex.hbrBackground,
        lpszMenuName: class_ex.lpszMenuName,
        lpszClassName: class_ex.lpszClassName,
    };

    RegisterClassA(&class as *const _)
}

pub extern "win64" fn RegisterClassExW(lpWndClassEx: *const WndClassExW) -> u16 {
    if lpWndClassEx.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let class_ex = unsafe { &*lpWndClassEx };
    if class_ex.cbSize < std::mem::size_of::<WndClassExW>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let class = WndClassW {
        style: class_ex.style,
        lpfnWndProc: class_ex.lpfnWndProc,
        cbClsExtra: class_ex.cbClsExtra,
        cbWndExtra: class_ex.cbWndExtra,
        hInstance: class_ex.hInstance,
        hIcon: class_ex.hIcon,
        hCursor: class_ex.hCursor,
        hbrBackground: class_ex.hbrBackground,
        lpszMenuName: class_ex.lpszMenuName,
        lpszClassName: class_ex.lpszClassName,
    };

    RegisterClassW(&class as *const _)
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
    hWndParent: usize,
    _hMenu: usize,
    _hInstance: usize,
    lpParam: *const c_void,
) -> usize {
    let class_name =
        unsafe { c_string(lpClassName) }.unwrap_or_else(|| "UnityWndClass".to_string());
    let wnd_proc = find_class(&class_name).and_then(|c| c.wnd_proc).or(Some(DefWindowProcA));
    let title = unsafe { c_string(lpWindowName) }.unwrap_or_default();

    tracing::info!(%class_name, %title, x, y, nWidth, nHeight, "CreateWindowExA: creating window");

    let actual_x = if x == i32::MIN || x < 0 { 100 } else { x };
    let actual_y = if y == i32::MIN || y < 0 { 100 } else { y };
    let actual_w = if nWidth <= 0 || nWidth == i32::MIN { 1280 } else { nWidth };
    let actual_h = if nHeight <= 0 || nHeight == i32::MIN { 720 } else { nHeight };

    // Try to create a REAL X11 window first
    if let Some(hwnd) = crate::platform::x11::create_x11_window(&title, x, y, nWidth, nHeight) {
        tracing::info!(hwnd = format_args!("0x{:x}", hwnd), "X11 window created successfully");
        let native_window_id = crate::platform::x11::hwnd_to_x11_window(hwnd).unwrap_or(0);
        create_window_with_parent_and_handle(
            hwnd,
            wnd_proc,
            title,
            actual_x,
            actual_y,
            actual_w,
            actual_h,
            hWndParent,
            native_window_id,
        );

        enqueue_message(Msg {
            hwnd,
            message: WM_CREATE,
            wParam: 0,
            lParam: lpParam as isize,
            time: 0,
            ..Default::default()
        });

        set_last_error(ERROR_SUCCESS);
        return hwnd;
    }

    // Fallback to fake window if X11 unavailable
    let hwnd = create_window_with_parent(wnd_proc, title, actual_x, actual_y, actual_w, actual_h, hWndParent);
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
    // The USER32 record is not the display server. Keep the native X11
    // window in sync so Unity's ShowWindow call actually becomes visible.
    let _ = crate::platform::x11::set_x11_window_visible(hWnd, visible);

    enqueue_message(Msg {
        hwnd: hWnd,
        message: WM_SHOWWINDOW,
        wParam: usize::from(visible),
        lParam: nCmdShow as isize,
        time: 0,
        ..Default::default()
    });

    if visible {
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_ACTIVATEAPP,
            wParam: 1,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_ACTIVATE,
            wParam: WA_ACTIVE,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_SETFOCUS,
            wParam: 0,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
    }

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
    let _ = crate::platform::x11::configure_x11_window(hWnd, X, Y, nWidth, nHeight);

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
    let _ = crate::platform::x11::configure_x11_window(hWnd, X, Y, cx, cy);

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SetForegroundWindow(hWnd: usize) -> i32 {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    foreground_window().store(hWnd, Ordering::Relaxed);
    if hWnd != 0 {
        if is_window_visible(hWnd) {
            let _ = crate::platform::x11::raise_x11_window(hWnd);
        }
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_ACTIVATEAPP,
            wParam: 1,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_ACTIVATE,
            wParam: WA_ACTIVE,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_SETFOCUS,
            wParam: 0,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetForegroundWindow() -> usize {
    set_last_error(ERROR_SUCCESS);
    foreground_window().load(Ordering::Relaxed)
}

pub extern "win64" fn GetDesktopWindow() -> usize {
    set_last_error(ERROR_SUCCESS);
    DESKTOP_WINDOW_HANDLE
}

pub extern "win64" fn AllowSetForegroundWindow(_dwProcessId: u32) -> i32 {
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

pub extern "win64" fn EnumWindows(_lp_enum_func: Option<WndEnumProc>, _l_param: isize) -> i32 {
    // Compatibility stub: report success even when no top-level windows are tracked.
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn EnumDisplayMonitors(
    hdc: usize,
    _lprc_clip: *const Rect,
    lpfn_enum: Option<MonitorEnumProc>,
    dw_data: isize,
) -> i32 {
    let monitor_rect = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };

    if let Some(callback) = lpfn_enum {
        tracing::info!(callback = callback as usize, hdc, data = dw_data, "EnumDisplayMonitors invoking guest callback");
        let callback_result =
            unsafe { callback(PRIMARY_MONITOR_HANDLE, hdc, &monitor_rect as *const Rect, dw_data) };
        tracing::info!(callback_result, "EnumDisplayMonitors guest callback returned");
        if callback_result == 0 {
            set_last_error(ERROR_SUCCESS);
            return 1;
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn MonitorFromPoint(_pt: crate::win32::user32::Point, _flags: u32) -> usize {
    PRIMARY_MONITOR_HANDLE
}

pub extern "win64" fn SetRect(
    lprc: *mut Rect,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> i32 {
    if !lprc.is_null() {
        unsafe {
            *lprc = Rect { left, top, right, bottom };
        }
    }
    1
}

pub extern "win64" fn ChangeDisplaySettingsExW(
    _lpszDeviceName: *const u16,
    _lpDevMode: *const c_void,
    _hwnd: usize,
    _dwflags: u32,
    _lparam: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn ChangeDisplaySettingsW(_lpDevMode: *const c_void, _dwflags: u32) -> i32 {
    0
}

pub extern "win64" fn ChangeDisplaySettingsA(_lpDevMode: *const c_void, _dwflags: u32) -> i32 {
    0
}

pub extern "win64" fn ChangeDisplaySettingsExA(
    _lpszDeviceName: *const std::ffi::c_char,
    _lpDevMode: *const c_void,
    _hwnd: usize,
    _dwflags: u32,
    _lparam: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn GetMonitorInfoW(_hMonitor: usize, lpmi: *mut c_void) -> i32 {
    if lpmi.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let cb_size = unsafe { *(lpmi.cast::<u32>()) };
    if cb_size < std::mem::size_of::<MonitorInfo>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let monitor_info = lpmi.cast::<MonitorInfo>();
    unsafe {
        (*monitor_info).rc_monitor = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };
        (*monitor_info).rc_work = Rect { left: 0, top: 0, right: 1920, bottom: 1040 };
        (*monitor_info).dw_flags = MONITORINFOF_PRIMARY;
    }

    if cb_size >= std::mem::size_of::<MonitorInfoExW>() as u32 {
        let info_ex = lpmi.cast::<MonitorInfoExW>();
        let device_name: Vec<u16> =
            "\\\\.\\DISPLAY1".encode_utf16().chain(std::iter::once(0)).collect();
        for (idx, code_unit) in device_name.iter().copied().enumerate().take(32) {
            unsafe {
                (*info_ex).sz_device[idx] = code_unit;
            }
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetMonitorInfoA(_hMonitor: usize, lpmi: *mut c_void) -> i32 {
    if lpmi.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let cb_size = unsafe { *(lpmi.cast::<u32>()) };
    if cb_size < std::mem::size_of::<MonitorInfo>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let monitor_info = lpmi.cast::<MonitorInfo>();
    unsafe {
        (*monitor_info).rc_monitor = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };
        (*monitor_info).rc_work = Rect { left: 0, top: 0, right: 1920, bottom: 1040 };
        (*monitor_info).dw_flags = MONITORINFOF_PRIMARY;
    }

    if cb_size >= std::mem::size_of::<MonitorInfoExA>() as u32 {
        let info_ex = lpmi.cast::<MonitorInfoExA>();
        let device_name = b"\\\\.\\DISPLAY1\0";
        for (idx, byte) in device_name.iter().copied().enumerate().take(32) {
            unsafe {
                (*info_ex).sz_device[idx] = byte;
            }
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn MonitorFromWindow(hwnd: usize, dwFlags: u32) -> usize {
    if hwnd == 0 {
        return match dwFlags {
            MONITOR_DEFAULTTONULL => 0,
            MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST => PRIMARY_MONITOR_HANDLE,
            _ => 0,
        };
    }

    if is_desktop_window(hwnd) || window_exists(hwnd) {
        return PRIMARY_MONITOR_HANDLE;
    }

    match dwFlags {
        MONITOR_DEFAULTTONULL => 0,
        MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST => PRIMARY_MONITOR_HANDLE,
        _ => 0,
    }
}

pub extern "win64" fn MonitorFromRect(lprc: *const Rect, dwFlags: u32) -> usize {
    if lprc.is_null() {
        return match dwFlags {
            MONITOR_DEFAULTTONULL => 0,
            MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST => PRIMARY_MONITOR_HANDLE,
            _ => 0,
        };
    }

    let rect = unsafe { *lprc };
    let intersects_primary =
        rect.right > 0 && rect.bottom > 0 && rect.left < 1920 && rect.top < 1080;
    if intersects_primary {
        return PRIMARY_MONITOR_HANDLE;
    }

    match dwFlags {
        MONITOR_DEFAULTTONULL => 0,
        MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST => PRIMARY_MONITOR_HANDLE,
        _ => 0,
    }
}

pub extern "win64" fn GetDC(hWnd: usize) -> usize {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    // Return a deterministic, non-zero pseudo HDC for compatibility.
    let hdc = 0x40_0000usize.wrapping_add(hWnd & 0xFFFF);
    set_last_error(ERROR_SUCCESS);
    hdc
}

pub extern "win64" fn GetWindowDC(hWnd: usize) -> usize {
    GetDC(hWnd)
}

pub extern "win64" fn GetDCEx(hWnd: usize, _hrgn_clip: usize, _flags: u32) -> usize {
    GetDC(hWnd)
}

pub extern "win64" fn ReleaseDC(hWnd: usize, hDC: usize) -> i32 {
    if hDC == 0 || (hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd)) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetWindowPlacement(hWnd: usize, lpwndpl: *mut WindowPlacement) -> i32 {
    if lpwndpl.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let placement_size = std::mem::size_of::<WindowPlacement>() as u32;
    unsafe {
        if (*lpwndpl).length != placement_size {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        (*lpwndpl).flags = 0;
        (*lpwndpl).show_cmd = SW_SHOWNORMAL;
        (*lpwndpl).pt_min_position = super::Point { x: -1, y: -1 };
        (*lpwndpl).pt_max_position = super::Point { x: -1, y: -1 };
        (*lpwndpl).rc_normal_position = Rect { left: 0, top: 0, right: 1280, bottom: 720 };
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn SetWindowPlacement(hWnd: usize, lpwndpl: *const WindowPlacement) -> i32 {
    if lpwndpl.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let placement_size = std::mem::size_of::<WindowPlacement>() as u32;
    unsafe {
        if (*lpwndpl).length != placement_size {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn UpdateWindow(hWnd: usize) -> i32 {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    if hWnd != 0 {
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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn AdjustWindowRect(lp_rect: *mut Rect, _dw_style: u32, b_menu: i32) -> i32 {
    AdjustWindowRectEx(lp_rect, 0, b_menu, 0)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn AdjustWindowRectEx(
    lp_rect: *mut Rect,
    _dw_style: u32,
    b_menu: i32,
    _dw_ex_style: u32,
) -> i32 {
    if lp_rect.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Minimal non-client inflation for compatibility with window sizing logic.
    let border = 8;
    let caption = 31;
    let menu_height = if b_menu != 0 { 20 } else { 0 };

    unsafe {
        (*lp_rect).left -= border;
        (*lp_rect).right += border;
        (*lp_rect).top -= caption;
        (*lp_rect).bottom += border + menu_height;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn AdjustWindowRectExForDpi(
    lp_rect: *mut Rect,
    dw_style: u32,
    b_menu: i32,
    dw_ex_style: u32,
    _dpi: u32,
) -> i32 {
    AdjustWindowRectEx(lp_rect, dw_style, b_menu, dw_ex_style)
}

pub extern "win64" fn EnableNonClientDpiScaling(h_wnd: usize) -> i32 {
    if !window_exists(h_wnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetDpiForWindow(h_wnd: usize) -> u32 {
    if h_wnd != 0 && !window_exists(h_wnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    set_last_error(ERROR_SUCCESS);
    96
}

pub extern "win64" fn SetWindowLongA(hWnd: usize, nIndex: i32, dwNewLong: i32) -> i32 {
    if !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let mut map = window_longs().lock().expect("window long map poisoned");
    let key = (hWnd, nIndex);
    let prev = map.insert(key, dwNewLong as isize).unwrap_or(0);
    set_last_error(ERROR_SUCCESS);
    prev as i32
}

pub extern "win64" fn SetWindowLongW(hWnd: usize, nIndex: i32, dwNewLong: i32) -> i32 {
    SetWindowLongA(hWnd, nIndex, dwNewLong)
}

pub extern "win64" fn GetWindowLongA(hWnd: usize, nIndex: i32) -> i32 {
    if !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    let map = window_longs().lock().expect("window long map poisoned");
    let value = *map.get(&(hWnd, nIndex)).unwrap_or(&0);
    set_last_error(ERROR_SUCCESS);
    value as i32
}

pub extern "win64" fn GetWindowLongW(hWnd: usize, nIndex: i32) -> i32 {
    GetWindowLongA(hWnd, nIndex)
}

pub extern "win64" fn SetWindowLongPtrA(hWnd: usize, nIndex: i32, dwNewLong: isize) -> isize {
    if !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    if nIndex == -4 {
        let prev = {
            let mut reg = super::window_registry().write().expect("window registry poisoned");
            if let Some(w) = reg.get_mut(&hWnd) {
                let prev_proc = w.wnd_proc.map(|p| p as usize as isize).unwrap_or(0);
                w.wnd_proc = if dwNewLong != 0 {
                    Some(unsafe { std::mem::transmute(dwNewLong) })
                } else {
                    None
                };
                prev_proc
            } else {
                0
            }
        };
        let mut map = window_longs().lock().expect("window long map poisoned");
        map.insert((hWnd, nIndex), dwNewLong);
        set_last_error(ERROR_SUCCESS);
        return prev;
    }

    let mut map = window_longs().lock().expect("window long map poisoned");
    let key = (hWnd, nIndex);
    let prev = map.insert(key, dwNewLong).unwrap_or(0);
    set_last_error(ERROR_SUCCESS);
    prev
}

pub extern "win64" fn SetWindowLongPtrW(hWnd: usize, nIndex: i32, dwNewLong: isize) -> isize {
    SetWindowLongPtrA(hWnd, nIndex, dwNewLong)
}

pub extern "win64" fn GetWindowLongPtrA(hWnd: usize, nIndex: i32) -> isize {
    if !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    if nIndex == -4 {
        if let Some(proc) = super::window_proc_for(hWnd) {
            set_last_error(ERROR_SUCCESS);
            return proc as usize as isize;
        }
    }

    let map = window_longs().lock().expect("window long map poisoned");
    let value = *map.get(&(hWnd, nIndex)).unwrap_or(&0);
    set_last_error(ERROR_SUCCESS);
    value
}

pub extern "win64" fn GetWindowLongPtrW(hWnd: usize, nIndex: i32) -> isize {
    GetWindowLongPtrA(hWnd, nIndex)
}

pub extern "win64" fn LoadIconA(_hInstance: usize, lpIconName: *const i8) -> usize {
    if lpIconName.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Compatibility handle for stock/custom icon lookup.
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn LoadIconW(_hInstance: usize, lpIconName: *const u16) -> usize {
    if lpIconName.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DestroyIcon(hIcon: usize) -> i32 {
    if hIcon == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Compatibility shim: icon handles are synthetic and require no teardown.
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn LoadCursorA(_hInstance: usize, lpCursorName: *const i8) -> usize {
    if lpCursorName.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn LoadCursorW(_hInstance: usize, lpCursorName: *const u16) -> usize {
    if lpCursorName.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DestroyCursor(hCursor: usize) -> i32 {
    if hCursor == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Compatibility shim: cursor handles are synthetic and require no teardown.
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SetCursor(hCursor: usize) -> usize {
    let mut cursor = active_cursor().lock().expect("active cursor poisoned");
    let previous = *cursor;
    *cursor = hCursor;
    set_last_error(ERROR_SUCCESS);
    previous
}

pub extern "win64" fn OpenClipboard(_hWndNewOwner: usize) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CloseClipboard() -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn EmptyClipboard() -> i32 {
    clipboard_data().lock().expect("clipboard data poisoned").clear();
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn IsClipboardFormatAvailable(format: u32) -> i32 {
    if format == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let available = clipboard_data().lock().expect("clipboard data poisoned").contains_key(&format);
    set_last_error(ERROR_SUCCESS);
    available as i32
}

pub extern "win64" fn GetClipboardData(format: u32) -> usize {
    let value = clipboard_data()
        .lock()
        .expect("clipboard data poisoned")
        .get(&format)
        .copied()
        .unwrap_or(0);
    set_last_error(ERROR_SUCCESS);
    value
}

pub extern "win64" fn SetClipboardData(format: u32, hMem: usize) -> usize {
    if format == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    clipboard_data().lock().expect("clipboard data poisoned").insert(format, hMem);
    set_last_error(ERROR_SUCCESS);
    hMem
}

pub extern "win64" fn CountClipboardFormats() -> i32 {
    let count = clipboard_data().lock().expect("clipboard data poisoned").len();
    set_last_error(ERROR_SUCCESS);
    count.min(i32::MAX as usize) as i32
}

pub extern "win64" fn EnumClipboardFormats(format: u32) -> u32 {
    let data = clipboard_data().lock().expect("clipboard data poisoned");
    let mut keys: Vec<u32> = data.keys().copied().collect();
    keys.sort_unstable();

    let next = if format == 0 {
        keys.first().copied().unwrap_or(0)
    } else {
        keys.into_iter().find(|value| *value > format).unwrap_or(0)
    };

    set_last_error(ERROR_SUCCESS);
    next
}

pub extern "win64" fn RegisterClipboardFormatA(lpszFormat: *const i8) -> u32 {
    let Some(name) = (unsafe { c_string(lpszFormat) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    if name.is_empty() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut map = clipboard_format_registry().lock().expect("clipboard format registry poisoned");
    if let Some(existing) = map.get(&name) {
        set_last_error(ERROR_SUCCESS);
        return *existing;
    }

    let next = next_clipboard_custom_format().fetch_add(1, Ordering::Relaxed) as u32;
    map.insert(name, next);
    set_last_error(ERROR_SUCCESS);
    next
}

pub extern "win64" fn RegisterClipboardFormatW(lpszFormat: *const u16) -> u32 {
    let Some(name) = (unsafe { wide_string(lpszFormat) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };

    if name.is_empty() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let mut utf8 = name.into_bytes();
    utf8.push(0);
    RegisterClipboardFormatA(utf8.as_ptr().cast())
}

pub extern "win64" fn TrackMouseEvent(lpEventTrack: *mut TrackMouseEventInfo) -> i32 {
    if lpEventTrack.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let event = unsafe { &mut *lpEventTrack };
    if event.cb_size < std::mem::size_of::<TrackMouseEventInfo>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if event.dw_flags & TME_QUERY != 0 {
        if event.hwnd_track == 0 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        let tracked = tracked_mouse_events()
            .lock()
            .expect("tracked mouse events poisoned")
            .get(&event.hwnd_track)
            .copied();
        if let Some((flags, hover_time)) = tracked {
            event.dw_flags = flags;
            event.dw_hover_time = hover_time;
        } else {
            event.dw_flags = 0;
            event.dw_hover_time = 0;
        }
        set_last_error(ERROR_SUCCESS);
        return 1;
    }

    if event.hwnd_track == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let tracked_flags = event.dw_flags & (TME_HOVER | TME_LEAVE);
    let mut tracked = tracked_mouse_events().lock().expect("tracked mouse events poisoned");

    if event.dw_flags & TME_CANCEL != 0 {
        tracked.remove(&event.hwnd_track);
    } else {
        tracked.insert(event.hwnd_track, (tracked_flags, event.dw_hover_time));
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn LoadImageA(
    _hInst: usize,
    _name: *const i8,
    _type: u32,
    _cx: i32,
    _cy: i32,
    _fuLoad: u32,
) -> usize {
    let handle = next_image_handle();
    set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn LoadImageW(
    _hInst: usize,
    _name: *const u16,
    _type: u32,
    _cx: i32,
    _cy: i32,
    _fuLoad: u32,
) -> usize {
    let handle = next_image_handle();
    set_last_error(ERROR_SUCCESS);
    handle
}

unsafe fn populate_dev_mode_blob(blob: *mut u8, dm_size: u16, is_wide: bool, width: u32, height: u32) {
    let (fields_offset, bits_offset, width_offset, height_offset, freq_offset) = if is_wide {
        (72usize, 168usize, 172usize, 176usize, 184usize)
    } else {
        (40usize, 104usize, 108usize, 112usize, 120usize)
    };

    let dm_size = dm_size as usize;
    let dm_fields = 0x0004_0000u32 | 0x0008_0000u32 | 0x0010_0000u32 | 0x0040_0000u32;

    if dm_size >= fields_offset + 4 {
        *(blob.add(fields_offset).cast::<u32>()) = dm_fields;
    }
    if dm_size >= bits_offset + 4 {
        *(blob.add(bits_offset).cast::<u32>()) = 32;
    }
    if dm_size >= width_offset + 4 {
        *(blob.add(width_offset).cast::<u32>()) = width;
    }
    if dm_size >= height_offset + 4 {
        *(blob.add(height_offset).cast::<u32>()) = height;
    }
    if dm_size >= freq_offset + 4 {
        *(blob.add(freq_offset).cast::<u32>()) = 60;
    }
}

const SUPPORTED_DISPLAY_MODES: &[(u32, u32)] = &[
    (1920, 1080),
    (1600, 900),
    (1366, 768),
    (1280, 720),
];

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn EnumDisplaySettingsW(
    _lpsz_device_name: *const u16,
    i_mode_num: u32,
    lp_dev_mode: *mut std::ffi::c_void,
) -> i32 {
    if lp_dev_mode.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let (width, height) = match i_mode_num {
        ENUM_CURRENT_SETTINGS | 0xFFFF_FFFE /* ENUM_REGISTRY_SETTINGS */ => (1920, 1080),
        idx if (idx as usize) < SUPPORTED_DISPLAY_MODES.len() => SUPPORTED_DISPLAY_MODES[idx as usize],
        _ => {
            set_last_error(ERROR_SUCCESS);
            return 0;
        }
    };

    unsafe {
        // DEVMODEW.dmSize at offset 68.
        let dm_size = *(lp_dev_mode.cast::<u8>().add(68).cast::<u16>());
        populate_dev_mode_blob(lp_dev_mode.cast::<u8>(), dm_size, true, width, height);
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn EnumDisplaySettingsA(
    _lpsz_device_name: *const i8,
    i_mode_num: u32,
    lp_dev_mode: *mut std::ffi::c_void,
) -> i32 {
    if lp_dev_mode.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let (width, height) = match i_mode_num {
        ENUM_CURRENT_SETTINGS | 0xFFFF_FFFE => (1920, 1080),
        idx if (idx as usize) < SUPPORTED_DISPLAY_MODES.len() => SUPPORTED_DISPLAY_MODES[idx as usize],
        _ => {
            set_last_error(ERROR_SUCCESS);
            return 0;
        }
    };

    unsafe {
        // DEVMODEA.dmSize at offset 36.
        let dm_size = *(lp_dev_mode.cast::<u8>().add(36).cast::<u16>());
        populate_dev_mode_blob(lp_dev_mode.cast::<u8>(), dm_size, false, width, height);
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn EnumDisplaySettingsExW(
    lpsz_device_name: *const u16,
    i_mode_num: u32,
    lp_dev_mode: *mut std::ffi::c_void,
    _dw_flags: u32,
) -> i32 {
    EnumDisplaySettingsW(lpsz_device_name, i_mode_num, lp_dev_mode)
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn EnumDisplaySettingsExA(
    lpsz_device_name: *const i8,
    i_mode_num: u32,
    lp_dev_mode: *mut std::ffi::c_void,
    _dw_flags: u32,
) -> i32 {
    EnumDisplaySettingsA(lpsz_device_name, i_mode_num, lp_dev_mode)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn EnumDisplayDevicesA(
    _lp_device: *const i8,
    i_dev_num: u32,
    lp_display_device: *mut DisplayDeviceA,
    _dw_flags: u32,
) -> i32 {
    if lp_display_device.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let device = unsafe { &mut *lp_display_device };
    if device.cb < std::mem::size_of::<DisplayDeviceA>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if i_dev_num != 0 {
        set_last_error(ERROR_SUCCESS);
        return 0;
    }

    *device = DisplayDeviceA::default();
    device.state_flags = DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_PRIMARY_DEVICE;

    let name = b"\\\\.\\DISPLAY1\0";
    let description = b"TuxExe Virtual Display\0";
    let id = b"DISPLAY\\TUXEXE1\0";
    let key = b"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\TuxExe\0";

    for (idx, byte) in name.iter().copied().enumerate().take(device.device_name.len()) {
        device.device_name[idx] = byte;
    }
    for (idx, byte) in description.iter().copied().enumerate().take(device.device_string.len()) {
        device.device_string[idx] = byte;
    }
    for (idx, byte) in id.iter().copied().enumerate().take(device.device_id.len()) {
        device.device_id[idx] = byte;
    }
    for (idx, byte) in key.iter().copied().enumerate().take(device.device_key.len()) {
        device.device_key[idx] = byte;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn EnumDisplayDevicesW(
    _lp_device: *const u16,
    i_dev_num: u32,
    lp_display_device: *mut DisplayDeviceW,
    _dw_flags: u32,
) -> i32 {
    if lp_display_device.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let device = unsafe { &mut *lp_display_device };
    if device.cb < std::mem::size_of::<DisplayDeviceW>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if i_dev_num != 0 {
        set_last_error(ERROR_SUCCESS);
        return 0;
    }

    *device = DisplayDeviceW::default();
    device.state_flags = DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_PRIMARY_DEVICE;

    let name: Vec<u16> = "\\\\.\\DISPLAY1".encode_utf16().chain(std::iter::once(0)).collect();
    let description: Vec<u16> =
        "TuxExe Virtual Display".encode_utf16().chain(std::iter::once(0)).collect();
    let id: Vec<u16> = "DISPLAY\\TUXEXE1".encode_utf16().chain(std::iter::once(0)).collect();
    let key: Vec<u16> = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\TuxExe"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    for (idx, ch) in name.iter().copied().enumerate().take(device.device_name.len()) {
        device.device_name[idx] = ch;
    }
    for (idx, ch) in description.iter().copied().enumerate().take(device.device_string.len()) {
        device.device_string[idx] = ch;
    }
    for (idx, ch) in id.iter().copied().enumerate().take(device.device_id.len()) {
        device.device_id[idx] = ch;
    }
    for (idx, ch) in key.iter().copied().enumerate().take(device.device_key.len()) {
        device.device_key[idx] = ch;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DisplayConfigGetDeviceInfo(
    request_packet: *mut DisplayConfigDeviceInfoHeader,
) -> i32 {
    if request_packet.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER as i32;
    }

    let header = unsafe { &*request_packet };
    if header.size < std::mem::size_of::<DisplayConfigDeviceInfoHeader>() as u32 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER as i32;
    }

    // Compatibility stub: report success without mutating the caller-provided payload.
    set_last_error(ERROR_SUCCESS);
    ERROR_SUCCESS as i32
}

pub extern "win64" fn GetDisplayConfigBufferSizes(
    _flags: u32,
    num_path_array_elements: *mut u32,
    num_mode_info_array_elements: *mut u32,
) -> i32 {
    if num_path_array_elements.is_null() || num_mode_info_array_elements.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER as i32;
    }

    unsafe {
        *num_path_array_elements = 0;
        *num_mode_info_array_elements = 0;
    }
    set_last_error(ERROR_SUCCESS);
    ERROR_SUCCESS as i32
}

pub extern "win64" fn QueryDisplayConfig(
    _flags: u32,
    num_path_array_elements: *mut u32,
    path_array: *mut c_void,
    num_mode_info_array_elements: *mut u32,
    mode_info_array: *mut c_void,
    current_topology_id: *mut u32,
) -> i32 {
    if num_path_array_elements.is_null() || num_mode_info_array_elements.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER as i32;
    }

    let requested_path_count = unsafe { *num_path_array_elements };
    let requested_mode_count = unsafe { *num_mode_info_array_elements };

    if requested_path_count > 0 && path_array.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER as i32;
    }
    if requested_mode_count > 0 && mode_info_array.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER as i32;
    }

    unsafe {
        *num_path_array_elements = 0;
        *num_mode_info_array_elements = 0;
        if !current_topology_id.is_null() {
            *current_topology_id = 0;
        }
    }

    set_last_error(ERROR_SUCCESS);
    ERROR_SUCCESS as i32
}

pub extern "win64" fn GetProcessWindowStation() -> usize {
    set_last_error(ERROR_SUCCESS);
    USER_OBJECT_HANDLE
}

pub extern "win64" fn GetThreadDesktop(_dw_thread_id: u32) -> usize {
    set_last_error(ERROR_SUCCESS);
    USER_OBJECT_HANDLE
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetUserObjectInformationW(
    h_obj: usize,
    n_index: i32,
    pv_info: *mut std::ffi::c_void,
    n_length: u32,
    lpn_length_needed: *mut u32,
) -> i32 {
    if h_obj == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    match n_index {
        UOI_FLAGS => {
            let required = std::mem::size_of::<UserObjectFlags>() as u32;
            if !lpn_length_needed.is_null() {
                unsafe {
                    *lpn_length_needed = required;
                }
            }
            if pv_info.is_null() || n_length < required {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            unsafe {
                *pv_info.cast::<UserObjectFlags>() = UserObjectFlags::default();
            }
        }
        UOI_NAME | UOI_TYPE => {
            let value = if n_index == UOI_NAME { "WinSta0" } else { "WindowStation" };
            let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
            let required = (wide.len() * std::mem::size_of::<u16>()) as u32;

            if !lpn_length_needed.is_null() {
                unsafe {
                    *lpn_length_needed = required;
                }
            }
            if pv_info.is_null() || n_length < required {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), pv_info.cast::<u16>(), wide.len());
            }
        }
        _ => {
            if !lpn_length_needed.is_null() {
                unsafe {
                    *lpn_length_needed = 0;
                }
            }
            set_last_error(ERROR_SUCCESS);
            return 1;
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn GetUserObjectInformationA(
    h_obj: usize,
    n_index: i32,
    pv_info: *mut std::ffi::c_void,
    n_length: u32,
    lpn_length_needed: *mut u32,
) -> i32 {
    if h_obj == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    match n_index {
        UOI_FLAGS => {
            let required = std::mem::size_of::<UserObjectFlags>() as u32;
            if !lpn_length_needed.is_null() {
                unsafe {
                    *lpn_length_needed = required;
                }
            }
            if pv_info.is_null() || n_length < required {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            unsafe {
                *pv_info.cast::<UserObjectFlags>() = UserObjectFlags::default();
            }
        }
        UOI_NAME | UOI_TYPE => {
            let mut bytes =
                if n_index == UOI_NAME { b"WinSta0".to_vec() } else { b"WindowStation".to_vec() };
            bytes.push(0);
            let required = bytes.len() as u32;

            if !lpn_length_needed.is_null() {
                unsafe {
                    *lpn_length_needed = required;
                }
            }
            if pv_info.is_null() || n_length < required {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), pv_info.cast::<u8>(), bytes.len());
            }
        }
        _ => {
            if !lpn_length_needed.is_null() {
                unsafe {
                    *lpn_length_needed = 0;
                }
            }
            set_last_error(ERROR_SUCCESS);
            return 1;
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "win64" fn SystemParametersInfoW(
    ui_action: u32,
    _ui_param: u32,
    pv_param: *mut std::ffi::c_void,
    _f_win_ini: u32,
) -> i32 {
    match ui_action {
        SPI_GETWORKAREA => {
            if pv_param.is_null() {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            unsafe {
                *pv_param.cast::<Rect>() = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };
            }
        }
        SPI_GETMOUSE => {
            if pv_param.is_null() {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            unsafe {
                *pv_param.cast::<[i32; 3]>() = [6, 10, 1];
            }
        }
        SPI_GETMOUSESPEED => {
            if pv_param.is_null() {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            unsafe {
                *pv_param.cast::<u32>() = 10;
            }
        }
        SPI_GETBEEP
        | SPI_GETSCREENSAVEACTIVE
        | SPI_GETDRAGFULLWINDOWS
        | SPI_GETKEYBOARDDELAY
        | SPI_GETKEYBOARDSPEED => {
            if pv_param.is_null() {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            unsafe {
                *pv_param.cast::<u32>() = 1;
            }
        }
        _ => {
            // Unknown actions are treated as accepted no-ops for compatibility.
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SystemParametersInfoA(
    ui_action: u32,
    ui_param: u32,
    pv_param: *mut std::ffi::c_void,
    f_win_ini: u32,
) -> i32 {
    SystemParametersInfoW(ui_action, ui_param, pv_param, f_win_ini)
}

pub extern "win64" fn PtInRect(lprc: *const Rect, pt: super::Point) -> i32 {
    if lprc.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let rect = unsafe { &*lprc };
    let inside = pt.x >= rect.left && pt.x < rect.right && pt.y >= rect.top && pt.y < rect.bottom;
    set_last_error(ERROR_SUCCESS);
    inside as i32
}

pub extern "win64" fn OffsetRect(lprc: *mut Rect, dx: i32, dy: i32) -> i32 {
    if lprc.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        (*lprc).left += dx;
        (*lprc).right += dx;
        (*lprc).top += dy;
        (*lprc).bottom += dy;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CopyRect(lprc_dst: *mut Rect, lprc_src: *const Rect) -> i32 {
    if lprc_dst.is_null() || lprc_src.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    unsafe {
        *lprc_dst = *lprc_src;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn ScreenToClient(h_wnd: usize, lp_point: *mut super::Point) -> i32 {
    if lp_point.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if h_wnd != 0 {
        if let Some((origin_x, origin_y)) = window_origin(h_wnd) {
            unsafe {
                (*lp_point).x -= origin_x;
                (*lp_point).y -= origin_y;
            }
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn ClientToScreen(h_wnd: usize, lp_point: *mut super::Point) -> i32 {
    if lp_point.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if h_wnd != 0 {
        if let Some((origin_x, origin_y)) = window_origin(h_wnd) {
            unsafe {
                (*lp_point).x += origin_x;
                (*lp_point).y += origin_y;
            }
        }
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetCursorPos(lp_point: *mut super::Point) -> i32 {
    if lp_point.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let has_visible_window = super::window_registry()
        .read()
        .map(|reg| reg.values().any(|w| w.visible))
        .unwrap_or(false);

    if has_visible_window {
        if let Some((root_x, root_y)) = crate::platform::x11::query_pointer_root() {
            let mut pos = cursor_position().lock().expect("cursor position poisoned");
            pos.x = root_x;
            pos.y = root_y;
        }
    }

    let pos = *cursor_position().lock().expect("cursor position poisoned");
    unsafe {
        *lp_point = pos;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SetCursorPos(x: i32, y: i32) -> i32 {
    let mut pos = cursor_position().lock().expect("cursor position poisoned");
    pos.x = x;
    pos.y = y;

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetSystemMetrics(n_index: i32) -> i32 {
    let value = match n_index {
        SM_CXSCREEN | SM_CXFULLSCREEN | SM_CXVIRTUALSCREEN | SM_CXMAXIMIZED => 1920,
        SM_CYSCREEN | SM_CYFULLSCREEN | SM_CYVIRTUALSCREEN | SM_CYMAXIMIZED => 1080,
        SM_XVIRTUALSCREEN | SM_YVIRTUALSCREEN => 0,
        SM_CYCAPTION => 23,
        SM_CXCURSOR | SM_CYCURSOR => 32,
        SM_CXBORDER | SM_CYBORDER => 1,
        SM_CXFRAME | SM_CYFRAME => 4,
        SM_CXDLGFRAME | SM_CYDLGFRAME => 3,
        SM_MOUSEPRESENT => 1,
        SM_SWAPBUTTON => 0,
        SM_CMONITORS => 1,
        SM_REMOTESESSION => 0,
        _ => 0,
    };

    set_last_error(ERROR_SUCCESS);
    value
}

pub extern "win64" fn GetSystemMetricsForDpi(n_index: i32, _dpi: u32) -> i32 {
    GetSystemMetrics(n_index)
}

pub extern "win64" fn SystemParametersInfoForDpi(
    ui_action: u32,
    ui_param: u32,
    pv_param: *mut c_void,
    f_win_ini: u32,
    _dpi: u32,
) -> i32 {
    SystemParametersInfoA(ui_action, ui_param, pv_param, f_win_ini)
}

pub extern "win64" fn SetCapture(h_wnd: usize) -> usize {
    let mut capture = capture_window().lock().expect("capture window poisoned");
    let previous = *capture;
    *capture = h_wnd;
    set_last_error(ERROR_SUCCESS);
    previous
}

pub extern "win64" fn GetCapture() -> usize {
    set_last_error(ERROR_SUCCESS);
    *capture_window().lock().expect("capture window poisoned")
}

pub extern "win64" fn ReleaseCapture() -> i32 {
    let mut capture = capture_window().lock().expect("capture window poisoned");
    *capture = 0;
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn RegisterDeviceNotificationW(
    _h_recipient: usize,
    _notification_filter: *const c_void,
    _flags: u32,
) -> usize {
    static NEXT_NOTIFICATION_HANDLE: AtomicUsize = AtomicUsize::new(0x90_0000);
    let handle = NEXT_NOTIFICATION_HANDLE.fetch_add(1, Ordering::Relaxed);
    set_last_error(ERROR_SUCCESS);
    handle
}

pub extern "win64" fn RegisterDeviceNotificationA(
    h_recipient: usize,
    notification_filter: *const c_void,
    flags: u32,
) -> usize {
    RegisterDeviceNotificationW(h_recipient, notification_filter, flags)
}

pub extern "win64" fn UnregisterDeviceNotification(h_dev_notify: usize) -> i32 {
    if h_dev_notify == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DefWindowProcA(
    _hWnd: usize,
    uMsg: u32,
    _wParam: usize,
    _lParam: isize,
) -> isize {
    match uMsg {
        WM_ERASEBKGND => 1,
        WM_NCHITTEST => HTCLIENT,
        WM_SETCURSOR => 1,
        _ => 0,
    }
}

pub extern "win64" fn DefWindowProcW(
    _hWnd: usize,
    uMsg: u32,
    _wParam: usize,
    _lParam: isize,
) -> isize {
    match uMsg {
        WM_ERASEBKGND => 1,
        WM_NCHITTEST => HTCLIENT,
        WM_SETCURSOR => 1,
        _ => 0,
    }
}

// ── New USER32 stubs required by UnityPlayer.dll ────────────────────────────

/// Return the parent or owner window. Returns 0 for top-level windows or on
/// invalid HWND, matching the real API.
pub extern "win64" fn GetParent(hWnd: usize) -> usize {
    if hWnd == 0 {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    if is_desktop_window(hWnd) {
        set_last_error(ERROR_SUCCESS);
        return 0;
    }
    match window_parent(hWnd) {
        Some(parent) => {
            set_last_error(ERROR_SUCCESS);
            parent
        }
        None => {
            set_last_error(ERROR_INVALID_WINDOW_HANDLE);
            0
        }
    }
}

/// Fill *lpRect with the bounding rectangle of the window in screen coords.
pub extern "win64" fn GetWindowRect(hWnd: usize, lpRect: *mut Rect) -> i32 {
    if lpRect.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if hWnd == 0 || is_desktop_window(hWnd) {
        unsafe {
            *lpRect = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };
        }
        set_last_error(ERROR_SUCCESS);
        return 1;
    }
    match window_rect(hWnd) {
        Some((left, top, right, bottom)) => {
            unsafe {
                *lpRect = Rect { left, top, right, bottom };
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        None => {
            set_last_error(ERROR_INVALID_WINDOW_HANDLE);
            0
        }
    }
}

/// Fill *lpRect with the client-area rectangle (always origin 0,0).
pub extern "win64" fn GetClientRect(hWnd: usize, lpRect: *mut Rect) -> i32 {
    if lpRect.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if hWnd == 0 || is_desktop_window(hWnd) {
        unsafe {
            *lpRect = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };
        }
        set_last_error(ERROR_SUCCESS);
        return 1;
    }
    match window_rect(hWnd) {
        Some((_, _, right, bottom)) => {
            // Client rect is always origin (0,0); width/height from stored size.
            let (left, top) = window_origin(hWnd).unwrap_or((0, 0));
            unsafe {
                *lpRect = Rect { left: 0, top: 0, right: right - left, bottom: bottom - top };
            }
            set_last_error(ERROR_SUCCESS);
            1
        }
        None => {
            set_last_error(ERROR_INVALID_WINDOW_HANDLE);
            0
        }
    }
}

/// Set the window title (Unicode). Compatibility stub — title is not rendered.
pub extern "win64" fn SetWindowTextW(hWnd: usize, lpString: *const u16) -> i32 {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    let _ = lpString; // title tracking not needed for headless compat
    set_last_error(ERROR_SUCCESS);
    1
}

/// Set the window title (ANSI). Delegates to W variant.
pub extern "win64" fn SetWindowTextA(hWnd: usize, lpString: *const i8) -> i32 {
    let _ = lpString;
    SetWindowTextW(hWnd, std::ptr::null())
}

/// Get the window title into a UTF-16 buffer. Returns character count.
pub extern "win64" fn GetWindowTextW(hWnd: usize, lpString: *mut u16, nMaxCount: i32) -> i32 {
    if lpString.is_null() || nMaxCount <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    // Write an empty string
    unsafe {
        *lpString = 0;
    }
    set_last_error(ERROR_SUCCESS);
    0
}

/// Get the window title into an ANSI buffer. Returns character count.
pub extern "win64" fn GetWindowTextA(hWnd: usize, lpString: *mut i8, nMaxCount: i32) -> i32 {
    if lpString.is_null() || nMaxCount <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    unsafe {
        *lpString = 0;
    }
    set_last_error(ERROR_SUCCESS);
    0
}

/// Validate a rectangle in a window, removing it from the update region.
/// Compatibility stub that always succeeds.
pub extern "win64" fn ValidateRect(hWnd: usize, _lpRect: *const Rect) -> i32 {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    set_last_error(ERROR_SUCCESS);
    1
}

/// Confine the cursor to a rectangle. Stub — no native cursor confinement in
/// our headless environment.
pub extern "win64" fn ClipCursor(_lpRect: *const Rect) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

/// Show or hide the cursor. Returns a pseudo display-counter (always 0).
pub extern "win64" fn ShowCursor(_bShow: i32) -> i32 {
    set_last_error(ERROR_SUCCESS);
    0
}

/// Detect whether the user started dragging from a point. Stub returns FALSE
/// (no drag) so callers fall through to normal click handling.
pub extern "win64" fn DragDetect(_hWnd: usize, _pt_x: i32, _pt_y: i32) -> i32 {
    set_last_error(ERROR_SUCCESS);
    0
}

fn focused_window() -> &'static std::sync::atomic::AtomicUsize {
    static FOCUS_HWND: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    &FOCUS_HWND
}

/// Return the window that currently has keyboard focus.
pub extern "win64" fn GetFocus() -> usize {
    set_last_error(ERROR_SUCCESS);
    focused_window().load(Ordering::Relaxed)
}

pub extern "win64" fn SetFocus(hWnd: usize) -> usize {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    let prev = focused_window().swap(hWnd, Ordering::Relaxed);
    if prev != 0 && prev != hWnd {
        enqueue_message(Msg {
            hwnd: prev,
            message: WM_KILLFOCUS,
            wParam: hWnd,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
    }
    if hWnd != 0 {
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_SETFOCUS,
            wParam: prev,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
    }
    set_last_error(ERROR_SUCCESS);
    prev
}

/// Return the active (foreground) window. Aliases GetForegroundWindow.
pub extern "win64" fn GetActiveWindow() -> usize {
    set_last_error(ERROR_SUCCESS);
    foreground_window().load(Ordering::Relaxed)
}

/// Set the active window. Returns the previously active HWND.
pub extern "win64" fn SetActiveWindow(hWnd: usize) -> usize {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    let prev = foreground_window().swap(hWnd, Ordering::Relaxed);
    if hWnd != 0 {
        if is_window_visible(hWnd) {
            let _ = crate::platform::x11::raise_x11_window(hWnd);
        }
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_ACTIVATEAPP,
            wParam: 1,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_ACTIVATE,
            wParam: WA_ACTIVE,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
        enqueue_message(Msg {
            hwnd: hWnd,
            message: WM_SETFOCUS,
            wParam: 0,
            lParam: 0,
            time: 0,
            ..Default::default()
        });
    }
    set_last_error(ERROR_SUCCESS);
    prev
}

/// Return TRUE if the window is minimised (iconic). We never minimise windows,
/// so this always returns FALSE.
pub extern "win64" fn IsIconic(_hWnd: usize) -> i32 {
    set_last_error(ERROR_SUCCESS);
    0
}

/// Return TRUE if the window and all its ancestors are visible.
pub extern "win64" fn IsWindowVisible(hWnd: usize) -> i32 {
    if hWnd == 0 || is_desktop_window(hWnd) {
        set_last_error(ERROR_SUCCESS);
        return 1; // desktop is always "visible"
    }
    if !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    let visible = is_window_visible(hWnd);
    set_last_error(ERROR_SUCCESS);
    i32::from(visible)
}

/// Return TRUE if the HWND identifies an existing window.
pub extern "win64" fn IsWindow(hWnd: usize) -> i32 {
    if hWnd == 0 {
        return 0;
    }
    if is_desktop_window(hWnd) || window_exists(hWnd) {
        1
    } else {
        0
    }
}

/// Unregister a previously registered window class (ANSI).
pub extern "win64" fn UnregisterClassA(lpClassName: *const i8, _hInstance: usize) -> i32 {
    let Some(name) = (unsafe { c_string(lpClassName) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    use super::class_registry;
    let mut reg = class_registry().write().expect("class registry poisoned");
    if reg.remove(&name).is_some() {
        set_last_error(ERROR_SUCCESS);
        1
    } else {
        // Class not found — Unity checks this after cleanup; returning success
        // avoids spurious failure paths.
        set_last_error(ERROR_SUCCESS);
        1
    }
}

/// Unregister a previously registered window class (Unicode).
pub extern "win64" fn UnregisterClassW(lpClassName: *const u16, hInstance: usize) -> i32 {
    let Some(name) = (unsafe { wide_string(lpClassName) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let name_c = match std::ffi::CString::new(name) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    };
    UnregisterClassA(name_c.as_ptr(), hInstance)
}

fn timer_registry() -> &'static Mutex<std::collections::HashMap<(usize, usize), u32>> {
    static TIMERS: OnceLock<Mutex<std::collections::HashMap<(usize, usize), u32>>> =
        OnceLock::new();
    TIMERS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn next_timer_id() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0x6000_0000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Set a timer. Returns the timer identifier on success, 0 on failure.
/// Timers are tracked but not actually fired in this compatibility layer.
pub extern "win64" fn SetTimer(
    hWnd: usize,
    nIDEvent: usize,
    uElapse: u32,
    _lpTimerFunc: usize,
) -> usize {
    if hWnd != 0 && !is_desktop_window(hWnd) && !window_exists(hWnd) {
        set_last_error(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    let id = if nIDEvent != 0 { nIDEvent } else { next_timer_id() };
    timer_registry().lock().expect("timer registry poisoned").insert((hWnd, id), uElapse);
    set_last_error(ERROR_SUCCESS);
    id
}

/// Destroy a timer previously set with SetTimer.
pub extern "win64" fn KillTimer(hWnd: usize, uIDEvent: usize) -> i32 {
    let removed = timer_registry()
        .lock()
        .expect("timer registry poisoned")
        .remove(&(hWnd, uIDEvent))
        .is_some();
    set_last_error(ERROR_SUCCESS);
    // Return 1 even if the timer wasn't found — Unity ignores the return value.
    let _ = removed;
    1
}

/// Wait for multiple object handles OR a message. Returns WAIT_TIMEOUT (0x102)
/// immediately in our stub so that callers loop back to PeekMessage.
pub extern "win64" fn MsgWaitForMultipleObjects(
    n_count: u32,
    handles: *const usize,
    wait_all: i32,
    milliseconds: u32,
    wake_mask: u32,
) -> u32 {
    const MWMO_WAITALL: u32 = 0x0001;
    MsgWaitForMultipleObjectsEx(
        n_count,
        handles,
        milliseconds,
        wake_mask,
        if wait_all != 0 { MWMO_WAITALL } else { 0 },
    )
}

pub extern "win64" fn MsgWaitForMultipleObjectsEx(
    n_count: u32,
    handles: *const usize,
    milliseconds: u32,
    _wake_mask: u32,
    flags: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x102;
    const WAIT_FAILED: u32 = 0xffff_ffff;
    const WAIT_IO_COMPLETION: u32 = 0x00c0;
    const MWMO_WAITALL: u32 = 0x0001;
    const MWMO_ALERTABLE: u32 = 0x0002;

    if n_count > 0 && handles.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return WAIT_FAILED;
    }
    let guest_handles = if n_count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(handles, n_count as usize) }
            .iter()
            .map(|handle| *handle as usize)
            .collect()
    };

    let wait_all = (flags & MWMO_WAITALL) != 0;
    let alertable = (flags & MWMO_ALERTABLE) != 0;
    let current_tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };

    let deadline = (milliseconds != u32::MAX)
        .then(|| Instant::now() + Duration::from_millis(milliseconds as u64));

    loop {
        if alertable && crate::win32::kernel32::process::execute_queued_apc(current_tid) {
            set_last_error(ERROR_SUCCESS);
            return WAIT_IO_COMPLETION;
        }

        crate::platform::x11::pump_x11_events();

        if !message_queue().0.lock().expect("message queue poisoned").is_empty() {
            set_last_error(ERROR_SUCCESS);
            return WAIT_OBJECT_0 + n_count;
        }
        if !guest_handles.is_empty() {
            let wait = crate::nt_kernel::sync::wait_for_multiple_objects(&guest_handles, wait_all, 0);
            if wait != WAIT_TIMEOUT && wait != WAIT_FAILED {
                set_last_error(ERROR_SUCCESS);
                return wait;
            }
            if wait == WAIT_FAILED {
                set_last_error(ERROR_INVALID_PARAMETER);
                return WAIT_FAILED;
            }
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            set_last_error(ERROR_SUCCESS);
            return WAIT_TIMEOUT;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Return the cursor blink interval in milliseconds.
pub extern "win64" fn GetCaretBlinkTime() -> u32 {
    530 // Typical Windows default
}

/// Return the double-click interval in milliseconds.
pub extern "win64" fn GetDoubleClickTime() -> u32 {
    500 // Typical Windows default
}

pub extern "win64" fn RegisterTouchWindow(_hWnd: usize, _ulFlags: u32) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn UnregisterTouchWindow(_hWnd: usize) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn IsTouchWindow(_hWnd: usize, _pulFlags: *mut u32) -> i32 {
    0
}

pub extern "win64" fn GetPointerType(_pointerId: u32, pointerType: *mut u32) -> i32 {
    if !pointerType.is_null() {
        unsafe { *pointerType = 1; /* PT_POINTER */ }
    }
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetPointerTouchInfo(_pointerId: u32, _touchInfo: *mut c_void) -> i32 {
    set_last_error(ERROR_INVALID_PARAMETER);
    0
}

pub extern "win64" fn GetPointerTouchInfoHistory(
    _pointerId: u32,
    entriesCount: *mut u32,
    _touchInfo: *mut c_void,
) -> i32 {
    if !entriesCount.is_null() {
        unsafe { *entriesCount = 0; }
    }
    set_last_error(ERROR_INVALID_PARAMETER);
    0
}

// ── end of new USER32 stubs ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use crate::win32::user32::{message, Msg};
    use std::sync::atomic::{AtomicI32, AtomicIsize, Ordering};

    unsafe extern "win64" fn test_proc(
        _hwnd: usize,
        _msg: u32,
        _wparam: usize,
        _lparam: isize,
    ) -> isize {
        0
    }

    unsafe extern "win64" fn monitor_enum_proc(
        _hmonitor: usize,
        _hdc: usize,
        _lprc_monitor: *const Rect,
        dw_data: isize,
    ) -> i32 {
        MONITOR_ENUM_CALLS.fetch_add(1, Ordering::SeqCst);
        MONITOR_ENUM_LAST_DATA.store(dw_data, Ordering::SeqCst);
        1
    }

    static MONITOR_ENUM_CALLS: AtomicI32 = AtomicI32::new(0);
    static MONITOR_ENUM_LAST_DATA: AtomicIsize = AtomicIsize::new(0);

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

        // This must work for both fallback and native X11 windows.  A native
        // HWND not registered in USER32 is rejected here, which prevents GL
        // and Vulkan backends from binding the window as a render target.
        let hdc = GetDC(hwnd);
        assert_ne!(hdc, 0);
        assert_eq!(ReleaseDC(hwnd, hdc), 1);

        assert_eq!(ShowWindow(hwnd, 1), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_SHOWWINDOW, WM_SHOWWINDOW), 1);
        assert_eq!(msg.message, WM_SHOWWINDOW);

        assert_eq!(MoveWindow(hwnd, 30, 40, 500, 300, 1), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_PAINT, WM_PAINT), 1);
        assert_eq!(msg.message, WM_PAINT);

        assert_eq!(SetWindowPos(hwnd, 0, 50, 60, 640, 480, 0), 1);
        assert_eq!(UpdateWindow(hwnd), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_PAINT, WM_PAINT), 1);
        assert_eq!(msg.message, WM_PAINT);

        assert_eq!(DestroyWindow(hwnd), 1);
        assert_eq!(message::GetMessageA(&raw mut msg, hwnd, WM_DESTROY, WM_DESTROY), 1);
        assert_eq!(msg.message, WM_DESTROY);
    }

    #[test]
    fn get_dc_and_release_dc_support_desktop_dc() {
        let _guard = serial_guard();
        let hdc = GetDC(0);
        assert_ne!(hdc, 0);
        assert_eq!(ReleaseDC(0, hdc), 1);
    }

    #[test]
    fn enum_display_monitors_invokes_callback_once() {
        let _guard = serial_guard();
        MONITOR_ENUM_CALLS.store(0, Ordering::SeqCst);
        MONITOR_ENUM_LAST_DATA.store(0, Ordering::SeqCst);

        assert_eq!(EnumDisplayMonitors(0, std::ptr::null(), Some(monitor_enum_proc), 0x55AA), 1);
        assert_eq!(MONITOR_ENUM_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(MONITOR_ENUM_LAST_DATA.load(Ordering::SeqCst), 0x55AA);
    }

    #[test]
    fn get_monitor_info_w_populates_primary_display_fields() {
        let _guard = serial_guard();

        let mut info = MonitorInfoExW {
            monitor_info: MonitorInfo {
                cb_size: std::mem::size_of::<MonitorInfoExW>() as u32,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(GetMonitorInfoW(PRIMARY_MONITOR_HANDLE, (&raw mut info).cast::<c_void>()), 1);
        assert_eq!(info.monitor_info.dw_flags, MONITORINFOF_PRIMARY);
        assert!(info.monitor_info.rc_monitor.right > info.monitor_info.rc_monitor.left);

        let device_name = unsafe { from_wide_ptr(info.sz_device.as_ptr()) }.expect("device name");
        assert_eq!(device_name, "\\\\.\\DISPLAY1");
    }

    #[test]
    fn get_monitor_info_a_populates_primary_display_fields() {
        let _guard = serial_guard();

        let mut info = MonitorInfoExA {
            monitor_info: MonitorInfo {
                cb_size: std::mem::size_of::<MonitorInfoExA>() as u32,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(GetMonitorInfoA(PRIMARY_MONITOR_HANDLE, (&raw mut info).cast::<c_void>()), 1);
        assert_eq!(info.monitor_info.dw_flags, MONITORINFOF_PRIMARY);
        assert!(info.monitor_info.rc_monitor.right > info.monitor_info.rc_monitor.left);

        let device_name = unsafe { CStr::from_ptr(info.sz_device.as_ptr().cast()) }
            .to_str()
            .expect("monitor device name");
        assert_eq!(device_name, "\\\\.\\DISPLAY1");
    }

    #[test]
    fn monitor_from_window_respects_default_flags() {
        let _guard = serial_guard();

        assert_eq!(MonitorFromWindow(0, MONITOR_DEFAULTTONULL), 0);
        assert_eq!(MonitorFromWindow(0, MONITOR_DEFAULTTOPRIMARY), PRIMARY_MONITOR_HANDLE);
        assert_eq!(MonitorFromWindow(0, MONITOR_DEFAULTTONEAREST), PRIMARY_MONITOR_HANDLE);

        assert_eq!(
            MonitorFromWindow(GetDesktopWindow(), MONITOR_DEFAULTTONULL),
            PRIMARY_MONITOR_HANDLE
        );
    }

    #[test]
    fn monitor_from_rect_respects_default_flags() {
        let _guard = serial_guard();

        let inside = Rect { left: 100, top: 100, right: 200, bottom: 200 };
        let outside = Rect { left: 3000, top: 3000, right: 3200, bottom: 3200 };

        assert_eq!(
            MonitorFromRect(&inside as *const Rect, MONITOR_DEFAULTTONULL),
            PRIMARY_MONITOR_HANDLE
        );
        assert_eq!(MonitorFromRect(&outside as *const Rect, MONITOR_DEFAULTTONULL), 0);
        assert_eq!(
            MonitorFromRect(&outside as *const Rect, MONITOR_DEFAULTTOPRIMARY),
            PRIMARY_MONITOR_HANDLE
        );
        assert_eq!(
            MonitorFromRect(std::ptr::null(), MONITOR_DEFAULTTOPRIMARY),
            PRIMARY_MONITOR_HANDLE
        );
    }

    #[test]
    fn enum_display_devices_a_reports_primary_display_once() {
        let _guard = serial_guard();

        let mut device = DisplayDeviceA::default();
        device.cb = std::mem::size_of::<DisplayDeviceA>() as u32;

        assert_eq!(EnumDisplayDevicesA(std::ptr::null(), 0, &raw mut device, 0), 1);
        assert_eq!(device.state_flags, DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_PRIMARY_DEVICE);

        let name = unsafe { CStr::from_ptr(device.device_name.as_ptr().cast()) }
            .to_str()
            .expect("device name");
        assert_eq!(name, "\\\\.\\DISPLAY1");

        assert_eq!(EnumDisplayDevicesA(std::ptr::null(), 1, &raw mut device, 0), 0);
    }

    #[test]
    fn enum_display_devices_w_validates_size_and_reports_primary() {
        let _guard = serial_guard();

        let mut too_small = DisplayDeviceW::default();
        too_small.cb = 4;
        assert_eq!(EnumDisplayDevicesW(std::ptr::null(), 0, &raw mut too_small, 0), 0);

        let mut device = DisplayDeviceW::default();
        device.cb = std::mem::size_of::<DisplayDeviceW>() as u32;
        assert_eq!(EnumDisplayDevicesW(std::ptr::null(), 0, &raw mut device, 0), 1);

        let name = unsafe { from_wide_ptr(device.device_name.as_ptr()) }.expect("device name");
        assert_eq!(name, "\\\\.\\DISPLAY1");
        assert_eq!(EnumDisplayDevicesW(std::ptr::null(), 1, &raw mut device, 0), 0);
    }

    #[test]
    fn get_window_placement_fills_structure() {
        let _guard = serial_guard();
        let mut placement = WindowPlacement {
            length: std::mem::size_of::<WindowPlacement>() as u32,
            ..WindowPlacement::default()
        };

        assert_eq!(GetWindowPlacement(0, &mut placement as *mut WindowPlacement), 1);
        assert_eq!(placement.show_cmd, SW_SHOWNORMAL);
        assert!(placement.rc_normal_position.right > placement.rc_normal_position.left);
    }

    #[test]
    fn adjust_window_rect_ex_inflates_non_client_area() {
        let _guard = serial_guard();
        let mut rect = Rect { left: 0, top: 0, right: 640, bottom: 480 };

        assert_eq!(AdjustWindowRectEx(&mut rect as *mut Rect, 0, 1, 0), 1);
        assert!(rect.left < 0);
        assert!(rect.top < 0);
        assert!(rect.right > 640);
        assert!(rect.bottom > 480);
    }

    #[test]
    fn set_and_get_window_long_roundtrip() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("WindowLongClass").expect("class");
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

        let hwnd = CreateWindowExA(
            0,
            class_name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            100,
            100,
            0,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(hwnd, 0);

        assert_eq!(SetWindowLongA(hwnd, 0, 123), 0);
        assert_eq!(GetWindowLongA(hwnd, 0), 123);
        assert_eq!(SetWindowLongPtrA(hwnd, 1, 0x1234), 0);
        assert_eq!(GetWindowLongPtrA(hwnd, 1), 0x1234);

        assert_eq!(DestroyWindow(hwnd), 1);
    }

    #[test]
    fn load_icon_and_cursor_return_stub_handles() {
        let _guard = serial_guard();
        let icon_a = std::ffi::CString::new("IDI_APPLICATION").expect("icon a");
        let cursor_a = std::ffi::CString::new("IDC_ARROW").expect("cursor a");
        let icon_w: Vec<u16> = "IDI_APPLICATION".encode_utf16().chain(std::iter::once(0)).collect();
        let cursor_w: Vec<u16> = "IDC_ARROW".encode_utf16().chain(std::iter::once(0)).collect();

        assert_eq!(LoadIconA(0, icon_a.as_ptr()), 1);
        assert_eq!(LoadIconW(0, icon_w.as_ptr()), 1);
        assert_eq!(LoadCursorA(0, cursor_a.as_ptr()), 1);
        assert_eq!(LoadCursorW(0, cursor_w.as_ptr()), 1);
        assert_eq!(DestroyIcon(1), 1);
        assert_eq!(DestroyIcon(0), 0);
        assert_eq!(DestroyCursor(1), 1);
        assert_eq!(DestroyCursor(0), 0);
        assert_eq!(SetCursor(1), 0);
        assert_eq!(SetCursor(2), 1);
    }

    #[test]
    fn clipboard_format_and_data_roundtrip() {
        let _guard = serial_guard();
        let _ = EmptyClipboard();

        assert_eq!(OpenClipboard(0), 1);
        assert_eq!(IsClipboardFormatAvailable(CF_UNICODETEXT), 0);
        assert_eq!(SetClipboardData(CF_UNICODETEXT, 0xCAFE_BABE), 0xCAFE_BABE);
        assert_eq!(IsClipboardFormatAvailable(CF_UNICODETEXT), 1);
        assert_eq!(GetClipboardData(CF_UNICODETEXT), 0xCAFE_BABE);
        assert!(CountClipboardFormats() >= 1);
        assert_ne!(EnumClipboardFormats(0), 0);
        assert_eq!(CloseClipboard(), 1);

        let fmt_a = std::ffi::CString::new("TuxExe.Custom.Format").expect("clipboard format");
        let id1 = RegisterClipboardFormatA(fmt_a.as_ptr());
        let id2 = RegisterClipboardFormatA(fmt_a.as_ptr());
        assert!(id1 >= CLIPBOARD_CUSTOM_FORMAT_BASE);
        assert_eq!(id1, id2);

        let fmt_w: Vec<u16> =
            "TuxExe.Custom.Format.W".encode_utf16().chain(std::iter::once(0)).collect();
        let idw = RegisterClipboardFormatW(fmt_w.as_ptr());
        assert!(idw >= CLIPBOARD_CUSTOM_FORMAT_BASE);
        assert_ne!(idw, 0);

        assert_eq!(CF_TEXT, 1);
    }

    #[test]
    fn track_mouse_event_supports_query_and_cancel() {
        let _guard = serial_guard();
        tracked_mouse_events().lock().expect("tracked mouse events poisoned").clear();

        let mut track = TrackMouseEventInfo {
            cb_size: std::mem::size_of::<TrackMouseEventInfo>() as u32,
            dw_flags: TME_HOVER | TME_LEAVE,
            hwnd_track: 0x44,
            dw_hover_time: 120,
        };
        assert_eq!(TrackMouseEvent(&mut track), 1);

        let mut query = TrackMouseEventInfo {
            cb_size: std::mem::size_of::<TrackMouseEventInfo>() as u32,
            dw_flags: TME_QUERY,
            hwnd_track: 0x44,
            dw_hover_time: 0,
        };
        assert_eq!(TrackMouseEvent(&mut query), 1);
        assert_eq!(query.dw_flags, TME_HOVER | TME_LEAVE);
        assert_eq!(query.dw_hover_time, 120);

        let mut cancel = TrackMouseEventInfo {
            cb_size: std::mem::size_of::<TrackMouseEventInfo>() as u32,
            dw_flags: TME_CANCEL | TME_HOVER | TME_LEAVE,
            hwnd_track: 0x44,
            dw_hover_time: 0,
        };
        assert_eq!(TrackMouseEvent(&mut cancel), 1);

        let mut query_after_cancel = TrackMouseEventInfo {
            cb_size: std::mem::size_of::<TrackMouseEventInfo>() as u32,
            dw_flags: TME_QUERY,
            hwnd_track: 0x44,
            dw_hover_time: 99,
        };
        assert_eq!(TrackMouseEvent(&mut query_after_cancel), 1);
        assert_eq!(query_after_cancel.dw_flags, 0);
        assert_eq!(query_after_cancel.dw_hover_time, 0);
    }

    #[test]
    fn enum_display_settings_w_populates_basic_display_metrics() {
        let _guard = serial_guard();

        let mut blob = vec![0u8; 256];
        // DEVMODEW.dmSize offset.
        blob[68..70].copy_from_slice(&(220u16).to_ne_bytes());

        assert_eq!(
            EnumDisplaySettingsW(std::ptr::null(), ENUM_CURRENT_SETTINGS, blob.as_mut_ptr().cast()),
            1
        );

        let width = u32::from_ne_bytes(blob[172..176].try_into().expect("width bytes"));
        let height = u32::from_ne_bytes(blob[176..180].try_into().expect("height bytes"));
        assert_eq!(width, 1920);
        assert_eq!(height, 1080);
    }

    #[test]
    fn display_config_get_device_info_validates_header() {
        let _guard = serial_guard();

        assert_eq!(
            DisplayConfigGetDeviceInfo(std::ptr::null_mut()),
            ERROR_INVALID_PARAMETER as i32
        );

        let mut too_small = DisplayConfigDeviceInfoHeader {
            size: (std::mem::size_of::<DisplayConfigDeviceInfoHeader>() as u32) - 1,
            ..Default::default()
        };
        assert_eq!(DisplayConfigGetDeviceInfo(&mut too_small), ERROR_INVALID_PARAMETER as i32);

        let mut valid = DisplayConfigDeviceInfoHeader {
            size: std::mem::size_of::<DisplayConfigDeviceInfoHeader>() as u32,
            ..Default::default()
        };
        assert_eq!(DisplayConfigGetDeviceInfo(&mut valid), ERROR_SUCCESS as i32);
    }

    #[test]
    fn display_config_buffer_size_and_query_stubs_return_success() {
        let _guard = serial_guard();

        let mut paths = 3u32;
        let mut modes = 4u32;
        assert_eq!(
            GetDisplayConfigBufferSizes(0, &mut paths as *mut u32, &mut modes as *mut u32),
            ERROR_SUCCESS as i32
        );
        assert_eq!(paths, 0);
        assert_eq!(modes, 0);

        let mut query_paths = 2u32;
        let mut query_modes = 2u32;
        let mut topology = u32::MAX;
        let mut path_buf = [0u8; 16];
        let mut mode_buf = [0u8; 16];
        assert_eq!(
            QueryDisplayConfig(
                0,
                &mut query_paths as *mut u32,
                path_buf.as_mut_ptr().cast(),
                &mut query_modes as *mut u32,
                mode_buf.as_mut_ptr().cast(),
                &mut topology as *mut u32,
            ),
            ERROR_SUCCESS as i32
        );
        assert_eq!(query_paths, 0);
        assert_eq!(query_modes, 0);
        assert_eq!(topology, 0);
    }

    #[test]
    fn user_object_information_w_reports_window_station_name() {
        let _guard = serial_guard();
        let mut needed = 0u32;
        assert_eq!(
            GetUserObjectInformationW(
                GetProcessWindowStation(),
                UOI_NAME,
                std::ptr::null_mut(),
                0,
                &mut needed as *mut u32,
            ),
            0
        );
        assert!(needed >= 2);

        let mut buf = vec![0u16; (needed as usize + 1) / 2];
        assert_eq!(
            GetUserObjectInformationW(
                GetProcessWindowStation(),
                UOI_NAME,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed as *mut u32,
            ),
            1
        );

        let value =
            unsafe { crate::utils::wide_string::from_wide_ptr(buf.as_ptr()) }.expect("name");
        assert_eq!(value, "WinSta0");
    }

    #[test]
    fn register_class_ex_w_delegates_to_register_class_w() {
        let _guard = serial_guard();
        let class_name: Vec<u16> = "ExClass".encode_utf16().chain(std::iter::once(0)).collect();
        let cls = WndClassExW {
            cbSize: std::mem::size_of::<WndClassExW>() as u32,
            style: 0,
            lpfnWndProc: None,
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: 0,
            hIcon: 0,
            hCursor: 0,
            hbrBackground: 0,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: 0,
        };

        assert_ne!(RegisterClassExW(&cls as *const _), 0);
    }

    #[test]
    fn enum_windows_succeeds_with_null_callback() {
        let _guard = serial_guard();
        assert_eq!(EnumWindows(None, 0), 1);
    }

    #[test]
    fn system_parameters_info_w_get_workarea_populates_rect() {
        let _guard = serial_guard();
        let mut rect = Rect::default();
        assert_eq!(
            SystemParametersInfoW(SPI_GETWORKAREA, 0, (&mut rect as *mut Rect).cast(), 0,),
            1
        );
        assert!(rect.right > rect.left);
        assert!(rect.bottom > rect.top);
    }

    #[test]
    fn pt_in_rect_respects_half_open_edges() {
        let _guard = serial_guard();
        let rect = Rect { left: 10, top: 20, right: 30, bottom: 40 };

        assert_eq!(PtInRect(&rect as *const Rect, super::super::Point { x: 10, y: 20 }), 1);
        assert_eq!(PtInRect(&rect as *const Rect, super::super::Point { x: 29, y: 39 }), 1);
        assert_eq!(PtInRect(&rect as *const Rect, super::super::Point { x: 30, y: 39 }), 0);
        assert_eq!(PtInRect(&rect as *const Rect, super::super::Point { x: 9, y: 20 }), 0);
    }

    #[test]
    fn offset_rect_translates_rectangle_coordinates() {
        let _guard = serial_guard();
        let mut rect = Rect { left: 1, top: 2, right: 3, bottom: 4 };
        assert_eq!(OffsetRect(&mut rect as *mut _, 10, -5), 1);
        assert_eq!(rect.left, 11);
        assert_eq!(rect.top, -3);
        assert_eq!(rect.right, 13);
        assert_eq!(rect.bottom, -1);
    }

    #[test]
    fn copy_rect_copies_source_to_destination() {
        let _guard = serial_guard();
        let src = Rect { left: 5, top: 6, right: 7, bottom: 8 };
        let mut dst = Rect::default();

        assert_eq!(CopyRect(&mut dst as *mut _, &src as *const _), 1);
        assert_eq!(dst.left, src.left);
        assert_eq!(dst.top, src.top);
        assert_eq!(dst.right, src.right);
        assert_eq!(dst.bottom, src.bottom);
    }

    #[test]
    fn screen_client_roundtrip_with_desktop_hwnd_is_noop() {
        let _guard = serial_guard();
        let mut p = super::super::Point { x: 123, y: 456 };
        assert_eq!(ScreenToClient(0, &mut p as *mut _), 1);
        assert_eq!(ClientToScreen(0, &mut p as *mut _), 1);
        assert_eq!(p.x, 123);
        assert_eq!(p.y, 456);
    }

    #[test]
    fn cursor_position_roundtrip() {
        let _guard = serial_guard();
        assert_eq!(SetCursorPos(321, 654), 1);

        let mut p = super::super::Point::default();
        assert_eq!(GetCursorPos(&mut p as *mut _), 1);
        assert_eq!(p.x, 321);
        assert_eq!(p.y, 654);
    }

    #[test]
    fn foreground_window_roundtrip() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("ForegroundWindowClass").expect("class name");
        let wnd_class = WndClassA {
            style: 0,
            lpfnWndProc: None,
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

        let title = std::ffi::CString::new("Foreground Window").expect("title");
        let hwnd = CreateWindowExA(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            100,
            100,
            0,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(hwnd, 0);

        assert_eq!(SetForegroundWindow(hwnd), 1);
        assert_eq!(GetForegroundWindow(), hwnd);

        assert_eq!(DestroyWindow(hwnd), 1);
    }

    #[test]
    fn allow_set_foreground_window_returns_success() {
        let _guard = serial_guard();
        assert_eq!(AllowSetForegroundWindow(u32::MAX), 1);
    }

    #[test]
    fn desktop_window_handle_is_accepted_by_dc_apis() {
        let _guard = serial_guard();
        let desktop = GetDesktopWindow();
        assert_ne!(desktop, 0);

        let hdc = GetDC(desktop);
        assert_ne!(hdc, 0);
        assert_eq!(ReleaseDC(desktop, hdc), 1);
    }

    #[test]
    fn load_image_returns_nonzero_handle() {
        let _guard = serial_guard();
        assert_ne!(LoadImageW(0, std::ptr::null(), 0, 0, 0, 0), 0);
        assert_ne!(LoadImageA(0, std::ptr::null(), 0, 0, 0, 0), 0);
    }

    #[test]
    fn get_system_metrics_reports_expected_basics() {
        let _guard = serial_guard();
        assert!(GetSystemMetrics(SM_CXSCREEN) > 0);
        assert!(GetSystemMetrics(SM_CYSCREEN) > 0);
        assert_eq!(GetSystemMetrics(SM_MOUSEPRESENT), 1);
        assert_eq!(GetSystemMetrics(0x7fff), 0);
    }

    #[test]
    fn capture_state_roundtrip() {
        let _guard = serial_guard();
        assert_eq!(SetCapture(0x1234), 0);
        assert_eq!(GetCapture(), 0x1234);
        assert_eq!(ReleaseCapture(), 1);
        assert_eq!(GetCapture(), 0);
    }

    #[test]
    fn device_notification_handles_register_and_unregister() {
        let _guard = serial_guard();
        let h = RegisterDeviceNotificationW(0, std::ptr::null(), 0);
        assert!(h != 0);
        assert_eq!(UnregisterDeviceNotification(h), 1);
        assert_eq!(UnregisterDeviceNotification(0), 0);
    }

    #[test]
    fn def_window_proc_returns_expected_default_codes() {
        let _guard = serial_guard();
        assert_eq!(DefWindowProcA(0, WM_ERASEBKGND, 0, 0), 1);
        assert_eq!(DefWindowProcA(0, WM_NCHITTEST, 0, 0), HTCLIENT);
        assert_eq!(DefWindowProcA(0, WM_SETCURSOR, 0, 0), 1);
        assert_eq!(DefWindowProcA(0, 0x1234, 0, 0), 0);

        assert_eq!(DefWindowProcW(0, WM_ERASEBKGND, 0, 0), 1);
        assert_eq!(DefWindowProcW(0, WM_NCHITTEST, 0, 0), HTCLIENT);
        assert_eq!(DefWindowProcW(0, WM_SETCURSOR, 0, 0), 1);
        assert_eq!(DefWindowProcW(0, 0x1234, 0, 0), 0);
    }

    #[test]
    fn msg_wait_for_multiple_objects_ex_alertable_executes_apc() {
        let _guard = serial_guard();
        const WAIT_IO_COMPLETION: u32 = 0x00c0;
        const MWMO_ALERTABLE: u32 = 0x0002;

        static APC_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        APC_DONE.store(false, std::sync::atomic::Ordering::SeqCst);

        extern "win64" fn apc_cb(_param: usize) {
            APC_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
        let ev = crate::nt_kernel::sync::create_event(false, false);

        // Queue APC for current thread
        crate::win32::kernel32::process::queue_user_apc(
            apc_cb as usize,
            crate::win32::kernel32::process::CURRENT_THREAD_PSEUDO_HANDLE as *mut c_void,
            0,
        );

        let res = MsgWaitForMultipleObjectsEx(1, &raw const ev, 1000, 0, MWMO_ALERTABLE);
        assert_eq!(res, WAIT_IO_COMPLETION);
        assert!(APC_DONE.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn set_focus_and_set_active_window_enqueue_activation_messages() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("ActivationTestClass").expect("class");
        let wnd_class = WndClassA {
            style: 0,
            lpfnWndProc: None,
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

        let title = std::ffi::CString::new("Activation Test").expect("title");
        let hwnd1 = CreateWindowExA(0, class_name.as_ptr(), title.as_ptr(), 0, 0, 0, 100, 100, 0, 0, 0, std::ptr::null());
        let hwnd2 = CreateWindowExA(0, class_name.as_ptr(), title.as_ptr(), 0, 0, 0, 100, 100, 0, 0, 0, std::ptr::null());
        assert_ne!(hwnd1, 0);
        assert_ne!(hwnd2, 0);

        // SetFocus on hwnd1
        SetFocus(hwnd1);
        let mut msg = Msg::default();
        assert_eq!(crate::win32::user32::message::PeekMessageA(&mut msg as *mut _, hwnd1, WM_SETFOCUS, WM_SETFOCUS, 1), 1);
        assert_eq!(msg.message, WM_SETFOCUS);

        // Switch focus to hwnd2 -> should generate WM_KILLFOCUS for hwnd1 and WM_SETFOCUS for hwnd2
        SetFocus(hwnd2);
        assert_eq!(crate::win32::user32::message::PeekMessageA(&mut msg as *mut _, hwnd1, WM_KILLFOCUS, WM_KILLFOCUS, 1), 1);
        assert_eq!(msg.message, WM_KILLFOCUS);
        assert_eq!(crate::win32::user32::message::PeekMessageA(&mut msg as *mut _, hwnd2, WM_SETFOCUS, WM_SETFOCUS, 1), 1);
        assert_eq!(msg.message, WM_SETFOCUS);

        // SetActiveWindow on hwnd1
        SetActiveWindow(hwnd1);
        assert_eq!(crate::win32::user32::message::PeekMessageA(&mut msg as *mut _, hwnd1, WM_ACTIVATEAPP, WM_ACTIVATEAPP, 1), 1);
        assert_eq!(msg.message, WM_ACTIVATEAPP);
        assert_eq!(crate::win32::user32::message::PeekMessageA(&mut msg as *mut _, hwnd1, WM_ACTIVATE, WM_ACTIVATE, 1), 1);
        assert_eq!(msg.message, WM_ACTIVATE);

        DestroyWindow(hwnd1);
        DestroyWindow(hwnd2);
    }
}
