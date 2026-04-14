#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod dialogs;
pub mod input;
pub mod message;
pub mod window;

use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicU16, AtomicUsize, Ordering},
    Condvar, Mutex, OnceLock, RwLock,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Msg {
    pub hwnd: usize,
    pub message: u32,
    pub wParam: usize,
    pub lParam: isize,
    pub time: u32,
    pub pt: Point,
}

pub type WindowProc = unsafe extern "win64" fn(usize, u32, usize, isize) -> isize;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WndClassA {
    pub style: u32,
    pub lpfnWndProc: Option<WindowProc>,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: usize,
    pub hIcon: usize,
    pub hCursor: usize,
    pub hbrBackground: usize,
    pub lpszMenuName: *const i8,
    pub lpszClassName: *const i8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WndClassW {
    pub style: u32,
    pub lpfnWndProc: Option<WindowProc>,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: usize,
    pub hIcon: usize,
    pub hCursor: usize,
    pub hbrBackground: usize,
    pub lpszMenuName: *const u16,
    pub lpszClassName: *const u16,
}

#[derive(Clone, Debug)]
pub(crate) struct RegisteredClass {
    pub atom: u16,
    pub wnd_proc: Option<WindowProc>,
}

#[derive(Clone, Debug)]
pub(crate) struct WindowRecord {
    pub wnd_proc: Option<WindowProc>,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub visible: bool,
    pub native_window_id: u64,
    /// Win32 HWND of the parent window, 0 = top-level / no parent.
    pub parent_hwnd: usize,
}

pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;

fn class_registry() -> &'static RwLock<HashMap<String, RegisteredClass>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, RegisteredClass>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

fn window_registry() -> &'static RwLock<HashMap<usize, WindowRecord>> {
    static WINDOWS: OnceLock<RwLock<HashMap<usize, WindowRecord>>> = OnceLock::new();
    WINDOWS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn message_queue_state() -> &'static (Mutex<VecDeque<Msg>>, Condvar) {
    static QUEUE: OnceLock<(Mutex<VecDeque<Msg>>, Condvar)> = OnceLock::new();
    QUEUE.get_or_init(|| (Mutex::new(VecDeque::new()), Condvar::new()))
}

fn next_atom() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn next_hwnd() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0x10_000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn register_class(name: &str, wnd_proc: Option<WindowProc>) -> u16 {
    let mut classes = class_registry().write().expect("class registry poisoned");
    if let Some(existing) = classes.get(name) {
        return existing.atom;
    }

    let atom = next_atom();
    classes.insert(name.to_string(), RegisteredClass { atom, wnd_proc });
    atom
}

pub(crate) fn find_class(name: &str) -> Option<RegisteredClass> {
    class_registry().read().expect("class registry poisoned").get(name).cloned()
}

pub(crate) fn create_window(
    wnd_proc: Option<WindowProc>,
    _title: String,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> usize {
    create_window_with_parent(wnd_proc, _title, x, y, width, height, 0)
}

pub(crate) fn create_window_with_parent(
    wnd_proc: Option<WindowProc>,
    _title: String,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent_hwnd: usize,
) -> usize {
    let hwnd = next_hwnd();
    let record = WindowRecord {
        wnd_proc,
        x,
        y,
        width,
        height,
        visible: false,
        native_window_id: 0,
        parent_hwnd,
    };

    window_registry().write().expect("window registry poisoned").insert(hwnd, record);
    hwnd
}

pub(crate) fn window_parent(hwnd: usize) -> Option<usize> {
    window_registry().read().expect("window registry poisoned").get(&hwnd).map(|w| w.parent_hwnd)
}

pub(crate) fn window_rect(hwnd: usize) -> Option<(i32, i32, i32, i32)> {
    window_registry()
        .read()
        .expect("window registry poisoned")
        .get(&hwnd)
        .map(|w| (w.x, w.y, w.x + w.width, w.y + w.height))
}

pub(crate) fn is_window_visible(hwnd: usize) -> bool {
    window_registry()
        .read()
        .expect("window registry poisoned")
        .get(&hwnd)
        .map(|w| w.visible)
        .unwrap_or(false)
}

pub(crate) fn update_window_rect(hwnd: usize, x: i32, y: i32, width: i32, height: i32) -> bool {
    let mut windows = window_registry().write().expect("window registry poisoned");
    let Some(window) = windows.get_mut(&hwnd) else {
        return false;
    };

    window.x = x;
    window.y = y;
    window.width = width;
    window.height = height;
    true
}

pub(crate) fn set_window_visibility(hwnd: usize, visible: bool) -> bool {
    let mut windows = window_registry().write().expect("window registry poisoned");
    let Some(window) = windows.get_mut(&hwnd) else {
        return false;
    };

    window.visible = visible;
    true
}

pub(crate) fn remove_window(hwnd: usize) -> bool {
    window_registry().write().expect("window registry poisoned").remove(&hwnd).is_some()
}

pub(crate) fn window_exists(hwnd: usize) -> bool {
    window_registry().read().expect("window registry poisoned").contains_key(&hwnd)
}

pub(crate) fn window_proc_for(hwnd: usize) -> Option<WindowProc> {
    window_registry()
        .read()
        .expect("window registry poisoned")
        .get(&hwnd)
        .and_then(|window| window.wnd_proc)
}

pub(crate) fn window_origin(hwnd: usize) -> Option<(i32, i32)> {
    window_registry()
        .read()
        .expect("window registry poisoned")
        .get(&hwnd)
        .map(|window| (window.x, window.y))
}

pub(crate) fn ensure_native_window_id(hwnd: usize) -> Option<u64> {
    let mut windows = window_registry().write().expect("window registry poisoned");
    let window = windows.get_mut(&hwnd)?;

    if window.native_window_id == 0 {
        // Keep IDs deterministic to simplify test assertions and event replay.
        window.native_window_id = 0x20_0000_u64 + hwnd as u64;
    }

    Some(window.native_window_id)
}
pub(crate) fn enqueue_message(mut msg: Msg) {
    if msg.time == 0 {
        msg.time = now_ms();
    }

    let (queue, condvar) = message_queue_state();
    let mut guard = queue.lock().expect("message queue poisoned");
    guard.push_back(msg);
    condvar.notify_all();
}

pub(crate) fn message_queue() -> &'static (Mutex<VecDeque<Msg>>, Condvar) {
    message_queue_state()
}

pub(crate) fn message_matches_filter(
    message: &Msg,
    hwnd_filter: usize,
    min_filter: u32,
    max_filter: u32,
) -> bool {
    if hwnd_filter != 0 && message.hwnd != hwnd_filter {
        return false;
    }

    if min_filter == 0 && max_filter == 0 {
        return true;
    }

    message.message >= min_filter && message.message <= max_filter
}

pub(crate) fn now_ms() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };

    duration.as_millis().min(u32::MAX as u128) as u32
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    exports.insert("RegisterClassA", window::RegisterClassA as usize);
    exports.insert("RegisterClassW", window::RegisterClassW as usize);
    exports.insert("RegisterClassExA", window::RegisterClassExA as usize);
    exports.insert("RegisterClassExW", window::RegisterClassExW as usize);
    exports.insert("CreateWindowExA", window::CreateWindowExA as usize);
    exports.insert("CreateWindowExW", window::CreateWindowExW as usize);
    exports.insert("ShowWindow", window::ShowWindow as usize);
    exports.insert("UpdateWindow", window::UpdateWindow as usize);
    exports.insert("MoveWindow", window::MoveWindow as usize);
    exports.insert("SetWindowPos", window::SetWindowPos as usize);
    exports.insert("SetForegroundWindow", window::SetForegroundWindow as usize);
    exports.insert("GetForegroundWindow", window::GetForegroundWindow as usize);
    exports.insert("GetDesktopWindow", window::GetDesktopWindow as usize);
    exports.insert("AllowSetForegroundWindow", window::AllowSetForegroundWindow as usize);
    exports.insert("GetDC", window::GetDC as usize);
    exports.insert("GetWindowDC", window::GetWindowDC as usize);
    exports.insert("GetDCEx", window::GetDCEx as usize);
    exports.insert("ReleaseDC", window::ReleaseDC as usize);
    exports.insert("GetWindowPlacement", window::GetWindowPlacement as usize);
    exports.insert("SetWindowPlacement", window::SetWindowPlacement as usize);
    exports.insert("AdjustWindowRect", window::AdjustWindowRect as usize);
    exports.insert("AdjustWindowRectEx", window::AdjustWindowRectEx as usize);
    exports.insert("SetWindowLongA", window::SetWindowLongA as usize);
    exports.insert("SetWindowLongW", window::SetWindowLongW as usize);
    exports.insert("GetWindowLongA", window::GetWindowLongA as usize);
    exports.insert("GetWindowLongW", window::GetWindowLongW as usize);
    exports.insert("SetWindowLongPtrA", window::SetWindowLongPtrA as usize);
    exports.insert("SetWindowLongPtrW", window::SetWindowLongPtrW as usize);
    exports.insert("GetWindowLongPtrA", window::GetWindowLongPtrA as usize);
    exports.insert("GetWindowLongPtrW", window::GetWindowLongPtrW as usize);
    exports.insert("LoadIconA", window::LoadIconA as usize);
    exports.insert("LoadIconW", window::LoadIconW as usize);
    exports.insert("DestroyIcon", window::DestroyIcon as usize);
    exports.insert("LoadCursorA", window::LoadCursorA as usize);
    exports.insert("LoadCursorW", window::LoadCursorW as usize);
    exports.insert("DestroyCursor", window::DestroyCursor as usize);
    exports.insert("SetCursor", window::SetCursor as usize);
    exports.insert("OpenClipboard", window::OpenClipboard as usize);
    exports.insert("CloseClipboard", window::CloseClipboard as usize);
    exports.insert("EmptyClipboard", window::EmptyClipboard as usize);
    exports.insert("IsClipboardFormatAvailable", window::IsClipboardFormatAvailable as usize);
    exports.insert("GetClipboardData", window::GetClipboardData as usize);
    exports.insert("SetClipboardData", window::SetClipboardData as usize);
    exports.insert("CountClipboardFormats", window::CountClipboardFormats as usize);
    exports.insert("EnumClipboardFormats", window::EnumClipboardFormats as usize);
    exports.insert("RegisterClipboardFormatA", window::RegisterClipboardFormatA as usize);
    exports.insert("RegisterClipboardFormatW", window::RegisterClipboardFormatW as usize);
    exports.insert("TrackMouseEvent", window::TrackMouseEvent as usize);
    exports.insert("LoadImageA", window::LoadImageA as usize);
    exports.insert("LoadImageW", window::LoadImageW as usize);
    exports.insert("EnumDisplaySettingsA", window::EnumDisplaySettingsA as usize);
    exports.insert("EnumDisplaySettingsW", window::EnumDisplaySettingsW as usize);
    exports.insert("EnumDisplaySettingsExA", window::EnumDisplaySettingsExA as usize);
    exports.insert("EnumDisplaySettingsExW", window::EnumDisplaySettingsExW as usize);
    exports.insert("EnumDisplayDevicesA", window::EnumDisplayDevicesA as usize);
    exports.insert("EnumDisplayDevicesW", window::EnumDisplayDevicesW as usize);
    exports.insert("DisplayConfigGetDeviceInfo", window::DisplayConfigGetDeviceInfo as usize);
    exports.insert("GetDisplayConfigBufferSizes", window::GetDisplayConfigBufferSizes as usize);
    exports.insert("QueryDisplayConfig", window::QueryDisplayConfig as usize);
    exports.insert("GetProcessWindowStation", window::GetProcessWindowStation as usize);
    exports.insert("GetThreadDesktop", window::GetThreadDesktop as usize);
    exports.insert("GetUserObjectInformationA", window::GetUserObjectInformationA as usize);
    exports.insert("GetUserObjectInformationW", window::GetUserObjectInformationW as usize);
    exports.insert("SystemParametersInfoA", window::SystemParametersInfoA as usize);
    exports.insert("SystemParametersInfoW", window::SystemParametersInfoW as usize);
    exports.insert("PtInRect", window::PtInRect as usize);
    exports.insert("OffsetRect", window::OffsetRect as usize);
    exports.insert("CopyRect", window::CopyRect as usize);
    exports.insert("ScreenToClient", window::ScreenToClient as usize);
    exports.insert("ClientToScreen", window::ClientToScreen as usize);
    exports.insert("GetCursorPos", window::GetCursorPos as usize);
    exports.insert("SetCursorPos", window::SetCursorPos as usize);
    exports.insert("GetSystemMetrics", window::GetSystemMetrics as usize);
    exports.insert("SetCapture", window::SetCapture as usize);
    exports.insert("GetCapture", window::GetCapture as usize);
    exports.insert("ReleaseCapture", window::ReleaseCapture as usize);
    exports.insert("RegisterDeviceNotificationA", window::RegisterDeviceNotificationA as usize);
    exports.insert("RegisterDeviceNotificationW", window::RegisterDeviceNotificationW as usize);
    exports.insert("UnregisterDeviceNotification", window::UnregisterDeviceNotification as usize);
    exports.insert("DestroyWindow", window::DestroyWindow as usize);
    exports.insert("EnumWindows", window::EnumWindows as usize);
    exports.insert("EnumDisplayMonitors", window::EnumDisplayMonitors as usize);
    exports.insert("GetMonitorInfoA", window::GetMonitorInfoA as usize);
    exports.insert("GetMonitorInfoW", window::GetMonitorInfoW as usize);
    exports.insert("MonitorFromRect", window::MonitorFromRect as usize);
    exports.insert("MonitorFromWindow", window::MonitorFromWindow as usize);
    exports.insert("DefWindowProcA", window::DefWindowProcA as usize);
    exports.insert("DefWindowProcW", window::DefWindowProcW as usize);
    exports.insert("GetParent", window::GetParent as usize);
    exports.insert("GetWindowRect", window::GetWindowRect as usize);
    exports.insert("GetClientRect", window::GetClientRect as usize);
    exports.insert("SetWindowTextW", window::SetWindowTextW as usize);
    exports.insert("SetWindowTextA", window::SetWindowTextA as usize);
    exports.insert("ValidateRect", window::ValidateRect as usize);
    exports.insert("ClipCursor", window::ClipCursor as usize);
    exports.insert("ShowCursor", window::ShowCursor as usize);
    exports.insert("DragDetect", window::DragDetect as usize);
    exports.insert("GetFocus", window::GetFocus as usize);
    exports.insert("SetFocus", window::SetFocus as usize);
    exports.insert("GetActiveWindow", window::GetActiveWindow as usize);
    exports.insert("IsIconic", window::IsIconic as usize);
    exports.insert("IsWindowVisible", window::IsWindowVisible as usize);
    exports.insert("UnregisterClassA", window::UnregisterClassA as usize);
    exports.insert("UnregisterClassW", window::UnregisterClassW as usize);
    exports.insert("KillTimer", window::KillTimer as usize);
    exports.insert("SetTimer", window::SetTimer as usize);
    exports.insert("MsgWaitForMultipleObjects", window::MsgWaitForMultipleObjects as usize);
    exports.insert("GetCaretBlinkTime", window::GetCaretBlinkTime as usize);
    exports.insert("GetDoubleClickTime", window::GetDoubleClickTime as usize);
    exports.insert("IsWindow", window::IsWindow as usize);
    exports.insert("GetWindowTextW", window::GetWindowTextW as usize);
    exports.insert("GetWindowTextA", window::GetWindowTextA as usize);
    exports.insert("MapVirtualKeyA", input::MapVirtualKeyA as usize);
    exports.insert("MapVirtualKeyW", input::MapVirtualKeyW as usize);
    exports.insert("MapVirtualKeyExA", input::MapVirtualKeyExA as usize);
    exports.insert("MapVirtualKeyExW", input::MapVirtualKeyExW as usize);
    exports.insert("ToUnicode", input::ToUnicode as usize);
    exports.insert("ToUnicodeEx", input::ToUnicodeEx as usize);
    exports.insert("GetKeyNameTextA", input::GetKeyNameTextA as usize);
    exports.insert("GetKeyNameTextW", input::GetKeyNameTextW as usize);
    exports.insert("GetAsyncKeyState", input::GetAsyncKeyState as usize);
    exports.insert("GetKeyState", input::GetKeyState as usize);
    exports.insert("GetKeyboardState", input::GetKeyboardState as usize);
    exports.insert("GetKeyboardLayout", input::GetKeyboardLayout as usize);
    exports.insert("GetKeyboardLayoutList", input::GetKeyboardLayoutList as usize);
    exports.insert("ActivateKeyboardLayout", input::ActivateKeyboardLayout as usize);
    exports.insert("GetKeyboardLayoutNameW", input::GetKeyboardLayoutNameW as usize);
    exports.insert("GetRawInputBuffer", input::GetRawInputBuffer as usize);
    exports.insert("GetRawInputData", input::GetRawInputData as usize);
    exports.insert("GetRawInputDeviceInfoA", input::GetRawInputDeviceInfoA as usize);
    exports.insert("GetRawInputDeviceInfoW", input::GetRawInputDeviceInfoW as usize);
    exports.insert("GetRawInputDeviceList", input::GetRawInputDeviceList as usize);
    exports.insert("RegisterRawInputDevices", input::RegisterRawInputDevices as usize);

    exports.insert("GetMessageA", message::GetMessageA as usize);
    exports.insert("GetMessageW", message::GetMessageW as usize);
    exports.insert("PeekMessageA", message::PeekMessageA as usize);
    exports.insert("PeekMessageW", message::PeekMessageW as usize);
    exports.insert("TranslateMessage", message::TranslateMessage as usize);
    exports.insert("DispatchMessageA", message::DispatchMessageA as usize);
    exports.insert("DispatchMessageW", message::DispatchMessageW as usize);
    exports.insert("PostQuitMessage", message::PostQuitMessage as usize);
    exports.insert("PostMessageA", message::PostMessageA as usize);
    exports.insert("PostMessageW", message::PostMessageW as usize);
    exports.insert("SendMessageA", message::SendMessageA as usize);
    exports.insert("SendMessageW", message::SendMessageW as usize);
    exports.insert("SendMessageTimeoutA", message::SendMessageTimeoutA as usize);
    exports.insert("SendMessageTimeoutW", message::SendMessageTimeoutW as usize);
    exports.insert("GetDlgItem", message::GetDlgItem as usize);
    exports.insert("SendDlgItemMessageA", message::SendDlgItemMessageA as usize);
    exports.insert("SendDlgItemMessageW", message::SendDlgItemMessageW as usize);
    exports.insert("SetDlgItemTextA", message::SetDlgItemTextA as usize);
    exports.insert("SetDlgItemTextW", message::SetDlgItemTextW as usize);
    exports.insert("RegisterWindowMessageA", message::RegisterWindowMessageA as usize);
    exports.insert("RegisterWindowMessageW", message::RegisterWindowMessageW as usize);
    exports.insert("GetMessageExtraInfo", message::GetMessageExtraInfo as usize);
    exports.insert("SetMessageExtraInfo", message::SetMessageExtraInfo as usize);

    // Dialogs
    exports.insert("MessageBoxA", dialogs::MessageBoxA as usize);
    exports.insert("MessageBoxW", dialogs::MessageBoxW as usize);
    exports.insert("EndDialog", dialogs::EndDialog as usize);
    exports.insert("DialogBoxParamA", dialogs::DialogBoxParamA as usize);
    exports.insert("DialogBoxParamW", dialogs::DialogBoxParamW as usize);

    exports
}
