//! X11 integration for window creation and GL context.
//!
//! This module creates REAL X11 windows and GLX contexts that Unity can use.

use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use x11::glx::*;
use x11::xlib::*;

use tracing::trace;

// ─── Global X11 State ───

pub struct X11State {
    pub display: *mut Display,
    pub screen: i32,
    pub root_window: Window,
    pub visual: *mut Visual,
    pub depth: i32,
    pub colormap: Colormap,
    pub glx_context: *mut __GLXcontextRec,
}

unsafe impl Send for X11State {}
unsafe impl Sync for X11State {}

fn x11_state() -> &'static Mutex<Option<X11State>> {
    static STATE: OnceLock<Mutex<Option<X11State>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

unsafe extern "C" fn x11_error_handler(
    _display: *mut Display,
    error_event: *mut XErrorEvent,
) -> std::os::raw::c_int {
    if !error_event.is_null() {
        let ev = unsafe { *error_event };
        tracing::debug!(
            resource_id = ev.resourceid,
            serial = ev.serial,
            error_code = ev.error_code,
            request_code = ev.request_code,
            minor_code = ev.minor_code,
            "Suppressed non-fatal X11 error"
        );
    }
    0
}

fn init_x11() -> bool {
    let mut state = x11_state().lock().expect("x11 state poisoned");
    if state.is_some() {
        return true;
    }

    eprintln!("[TuxExe] Initializing X11...");

    unsafe {
        let display = XOpenDisplay(std::ptr::null());
        if display.is_null() {
            eprintln!("[TuxExe] XOpenDisplay failed");
            return false;
        }

        XSetErrorHandler(Some(x11_error_handler));

        eprintln!("[TuxExe] X11 display opened successfully");

        let screen = XDefaultScreen(display);
        let root_window = XRootWindow(display, screen);
        let visual = XDefaultVisual(display, screen);
        let depth = XDefaultDepth(display, screen);
        let colormap = XDefaultColormap(display, screen);

        // Initialize GLX
        let mut error_base = 0i32;
        let mut event_base = 0i32;
        if glXQueryExtension(display, &mut error_base, &mut event_base) == 0 {
            trace!("GLX extension not found");
            XCloseDisplay(display);
            return false;
        }

        *state = Some(X11State {
            display,
            screen,
            root_window,
            visual,
            depth,
            colormap,
            glx_context: std::ptr::null_mut(),
        });

        trace!("X11 display opened successfully");
    }

    true
}

// ─── Window Records ───

#[derive(Debug)]
pub struct X11Window {
    pub hwnd: usize,
    pub x11_window: Window,
    pub width: i32,
    pub height: i32,
    pub visible: bool,
    pub title: String,
}

fn window_registry() -> &'static Mutex<Vec<X11Window>> {
    static REG: OnceLock<Mutex<Vec<X11Window>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn create_x11_window(title: &str, x: i32, y: i32, width: i32, height: i32) -> Option<usize> {
    if !init_x11() {
        return None;
    }

    let state = x11_state().lock().expect("x11 state poisoned");
    let state = state.as_ref()?;

    let title_c = CString::new(title).ok()?;

    let win_x = if x == i32::MIN || x < 0 { 100 } else { x };
    let win_y = if y == i32::MIN || y < 0 { 100 } else { y };
    let win_width = if width <= 0 || width == i32::MIN { 1280 } else { width };
    let win_height = if height <= 0 || height == i32::MIN { 720 } else { height };

    unsafe {
        let mut attributes = XSetWindowAttributes {
            background_pixel: 0,
            background_pixmap: 0,
            border_pixel: 0,
            border_pixmap: 0,
            bit_gravity: 0,
            win_gravity: 0,
            backing_store: 0,
            backing_planes: 0,
            backing_pixel: 0,
            save_under: 0,
            event_mask: ExposureMask
                | KeyPressMask
                | KeyReleaseMask
                | ButtonPressMask
                | ButtonReleaseMask
                | PointerMotionMask
                | StructureNotifyMask,
            do_not_propagate_mask: 0,
            override_redirect: 0,
            colormap: state.colormap,
            cursor: 0,
        };

        let x11_win = XCreateWindow(
            state.display,
            state.root_window,
            win_x,
            win_y,
            win_width as u32,
            win_height as u32,
            0,
            state.depth as i32,
            InputOutput as u32,
            state.visual,
            CWBackPixel | CWBorderPixel | CWEventMask | CWColormap,
            &mut attributes,
        );

        if x11_win == 0 {
            trace!("XCreateWindow failed");
            return None;
        }

        XStoreName(state.display, x11_win, title_c.as_ptr());
        XMapWindow(state.display, x11_win);
        XFlush(state.display);

        // DXVK's TuxExe WSI backend receives HWND directly, so preserve the
        // Xlib Window ID rather than manufacturing an unrelated handle.
        let hwnd = x11_win as usize;

        window_registry().lock().expect("window reg poisoned").push(X11Window {
            hwnd,
            x11_window: x11_win,
            width,
            height,
            visible: true,
            title: title.to_string(),
        });

        trace!("Created X11 window: hwnd=0x{:x} x11=0x{:x}", hwnd, x11_win);
        Some(hwnd)
    }
}

pub fn hwnd_to_x11_window(hwnd: usize) -> Option<Window> {
    let reg = window_registry().lock().expect("window reg poisoned");
    reg.iter().find(|w| w.hwnd == hwnd).map(|w| w.x11_window)
}

pub fn get_first_x11_window() -> Option<Window> {
    let reg = window_registry().lock().expect("window reg poisoned");
    reg.first().map(|w| w.x11_window)
}

/// Mirrors USER32 visibility changes to the native X11 window. Returns false
/// only when `hwnd` is a synthetic (non-X11) window.
pub fn set_x11_window_visible(hwnd: usize, visible: bool) -> bool {
    let display = {
        let state = x11_state().lock().expect("x11 state poisoned");
        let Some(state) = state.as_ref() else {
            return false;
        };
        state.display
    };
    let Some(window) = hwnd_to_x11_window(hwnd) else {
        return false;
    };

    unsafe {
        if visible {
            XMapRaised(display, window);
        } else {
            XUnmapWindow(display, window);
        }
        XFlush(display);
    }
    if let Some(record) = window_registry()
        .lock()
        .expect("window reg poisoned")
        .iter_mut()
        .find(|record| record.hwnd == hwnd)
    {
        record.visible = visible;
    }
    true
}

/// Raises a mapped native window to match `SetForegroundWindow` semantics.
pub fn raise_x11_window(hwnd: usize) -> bool {
    let display = {
        let state = x11_state().lock().expect("x11 state poisoned");
        let Some(state) = state.as_ref() else {
            return false;
        };
        state.display
    };
    let Some(window) = hwnd_to_x11_window(hwnd) else {
        return false;
    };
    unsafe {
        XMapRaised(display, window);
        XSetInputFocus(display, window, RevertToParent, CurrentTime);
        XFlush(display);
    }
    true
}

/// Applies USER32 geometry changes to the mapped X11 window.
pub fn configure_x11_window(hwnd: usize, x: i32, y: i32, width: i32, height: i32) -> bool {
    let display = {
        let state = x11_state().lock().expect("x11 state poisoned");
        let Some(state) = state.as_ref() else {
            return false;
        };
        state.display
    };
    let Some(window) = hwnd_to_x11_window(hwnd) else {
        return false;
    };
    unsafe {
        XMoveResizeWindow(
            display,
            window,
            x,
            y,
            width.max(1) as u32,
            height.max(1) as u32,
        );
        XFlush(display);
    }
    if let Some(record) = window_registry()
        .lock()
        .expect("window reg poisoned")
        .iter_mut()
        .find(|record| record.hwnd == hwnd)
    {
        record.width = width.max(1);
        record.height = height.max(1);
    }
    true
}

pub fn x11_display() -> Option<*mut Display> {
    let state = x11_state().lock().expect("x11 state poisoned");
    state.as_ref().map(|s| s.display)
}

// ─── GLX Context ───

#[derive(Debug)]
pub struct GLContext {
    pub hglrc: usize,
    pub glx_context: usize, // Store as usize for Send safety
    pub x11_window: Window,
}

fn gl_context_registry() -> &'static Mutex<Vec<GLContext>> {
    static REG: OnceLock<Mutex<Vec<GLContext>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Vec::new()))
}

static NEXT_HGLRC: AtomicUsize = AtomicUsize::new(0x20_000);

pub fn create_gl_context() -> Option<usize> {
    if !init_x11() {
        return None;
    }

    let state = x11_state().lock().expect("x11 state poisoned");
    let state = state.as_ref()?;

    // Get default X11 window for context creation
    let x11_win = window_registry()
        .lock()
        .expect("window reg poisoned")
        .first()
        .map(|w| w.x11_window)
        .unwrap_or(state.root_window);

    unsafe {
        // Get framebuffer configs
        let mut attribs = [
            GLX_RGBA,
            GLX_DOUBLEBUFFER,
            GLX_RED_SIZE,
            8,
            GLX_GREEN_SIZE,
            8,
            GLX_BLUE_SIZE,
            8,
            GLX_ALPHA_SIZE,
            8,
            GLX_DEPTH_SIZE,
            24,
            GLX_STENCIL_SIZE,
            8,
            0,
        ];

        let vi = glXChooseVisual(state.display, state.screen, attribs.as_mut_ptr());
        if vi.is_null() {
            // Try simpler config
            let mut simple_attribs = [GLX_RGBA, GLX_DOUBLEBUFFER, 0];
            let vi = glXChooseVisual(state.display, state.screen, simple_attribs.as_mut_ptr());
            if vi.is_null() {
                trace!("glXChooseVisual failed");
                return None;
            }
        }

        let ctx = glXCreateContext(state.display, vi, std::ptr::null_mut(), 1);
        if ctx.is_null() {
            trace!("glXCreateContext failed");
            return None;
        }

        let hglrc = NEXT_HGLRC.fetch_add(1, Ordering::Relaxed);

        gl_context_registry().lock().expect("gl context reg poisoned").push(GLContext {
            hglrc,
            glx_context: ctx as usize,
            x11_window: x11_win,
        });

        trace!("Created GLX context: hglrc=0x{:x}", hglrc);
        Some(hglrc)
    }
}

pub fn make_gl_context_current(hglrc: usize) -> bool {
    if !init_x11() {
        return false;
    }

    if hglrc == 0 {
        // Unmake current
        unsafe {
            let state = x11_state().lock().expect("x11 state poisoned");
            if let Some(s) = state.as_ref() {
                glXMakeCurrent(s.display, 0, std::ptr::null_mut());
            }
        }
        return true;
    }

    let reg = gl_context_registry().lock().expect("gl context reg poisoned");
    let ctx = match reg.iter().find(|c| c.hglrc == hglrc) {
        Some(c) => c,
        None => return false,
    };
    let glx_ctx = ctx.glx_context as *mut __GLXcontextRec;
    let x11_win = ctx.x11_window;

    unsafe {
        let state = x11_state().lock().expect("x11 state poisoned");
        if let Some(s) = state.as_ref() {
            let result = glXMakeCurrent(s.display, x11_win, glx_ctx);
            result != 0
        } else {
            false
        }
    }
}

pub fn swap_buffers(hwnd: usize) {
    if let Some(x11_win) = hwnd_to_x11_window(hwnd) {
        if let Some(display) = x11_display() {
            unsafe {
                glXSwapBuffers(display, x11_win);
            }
        }
    }
}

fn xkeysym_to_vk(keysym: u64) -> u32 {
    match keysym {
        0x0020 => 0x20, // VK_SPACE
        0x0030..=0x0039 => keysym as u32, // '0'..'9'
        0x0041..=0x005a => keysym as u32, // 'A'..'Z'
        0x0061..=0x007a => (keysym - 0x20) as u32, // 'a'..'z' -> 'A'..'Z'
        0xff08 => 0x08, // VK_BACK
        0xff09 => 0x09, // VK_TAB
        0xff0d => 0x0D, // VK_RETURN
        0xff1b => 0x1B, // VK_ESCAPE
        0xff50 => 0x24, // VK_HOME
        0xff51 => 0x25, // VK_LEFT
        0xff52 => 0x26, // VK_UP
        0xff53 => 0x27, // VK_RIGHT
        0xff54 => 0x28, // VK_DOWN
        0xff55 => 0x21, // VK_PRIOR (PageUp)
        0xff56 => 0x22, // VK_NEXT (PageDown)
        0xff57 => 0x23, // VK_END
        0xffff => 0x2E, // VK_DELETE
        0xffe1 | 0xffe2 => 0x10, // VK_SHIFT (Shift_L / Shift_R)
        0xffe3 | 0xffe4 => 0x11, // VK_CONTROL (Control_L / Control_R)
        0xffe9 | 0xffea => 0x12, // VK_MENU (Alt_L / Alt_R)
        0xffbe..=0xffcb => (keysym - 0xffbe + 0x70) as u32, // VK_F1..VK_F12
        _ => 0,
    }
}

pub fn query_pointer_root() -> Option<(i32, i32)> {
    let state = x11_state().lock().expect("x11 state poisoned");
    let state = state.as_ref()?;
    let display = state.display;
    if display.is_null() {
        return None;
    }

    let mut root: Window = 0;
    let mut child: Window = 0;
    let mut root_x: i32 = 0;
    let mut root_y: i32 = 0;
    let mut win_x: i32 = 0;
    let mut win_y: i32 = 0;
    let mut mask: u32 = 0;

    let res = unsafe {
        XQueryPointer(
            display,
            state.root_window,
            &mut root,
            &mut child,
            &mut root_x,
            &mut root_y,
            &mut win_x,
            &mut win_y,
            &mut mask,
        )
    };

    if res != 0 {
        if (mask & (1 << 8)) != 0 {
            crate::win32::user32::input::set_key_down(0x01); // VK_LBUTTON
        } else {
            crate::win32::user32::input::set_key_up(0x01);
        }
        if (mask & (1 << 10)) != 0 {
            crate::win32::user32::input::set_key_down(0x02); // VK_RBUTTON
        } else {
            crate::win32::user32::input::set_key_up(0x02);
        }
        if (mask & (1 << 9)) != 0 {
            crate::win32::user32::input::set_key_down(0x04); // VK_MBUTTON
        } else {
            crate::win32::user32::input::set_key_up(0x04);
        }

        Some((root_x, root_y))
    } else {
        None
    }
}

#[allow(non_upper_case_globals)]
pub fn pump_x11_events() {
    let state_guard = x11_state().lock().expect("x11 state poisoned");
    let Some(state) = state_guard.as_ref() else {
        return;
    };

    let display = state.display;
    if display.is_null() {
        return;
    }

    let reg = window_registry().lock().expect("window reg poisoned");
    if reg.is_empty() {
        return;
    }

    unsafe {
        while XPending(display) > 0 {
            let mut event: XEvent = std::mem::zeroed();
            XNextEvent(display, &mut event);

            let event_type = event.type_;
            let x11_win = event.any.window;
            let hwnd = reg.iter().find(|w| w.x11_window == x11_win).map(|w| w.hwnd).unwrap_or(0);

            if hwnd == 0 {
                continue;
            }

            match event_type {
                Expose => {
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x000F, // WM_PAINT
                        wParam: 0,
                        lParam: 0,
                        time: 0,
                        ..Default::default()
                    });
                }
                ConfigureNotify => {
                    let cfg = event.configure;
                    let lparam = (cfg.width & 0xFFFF) as isize | (((cfg.height & 0xFFFF) as isize) << 16);
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0005, // WM_SIZE
                        wParam: 0,
                        lParam: lparam,
                        time: 0,
                        ..Default::default()
                    });
                }
                KeyPress => {
                    let key = event.key;
                    let keysym = XKeycodeToKeysym(display, key.keycode as u8, 0);
                    let vk = xkeysym_to_vk(keysym as u64);
                    if vk != 0 {
                        crate::win32::user32::input::set_key_down(vk);
                    }
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0100, // WM_KEYDOWN
                        wParam: vk as usize,
                        lParam: 1,
                        time: key.time as u32,
                        pt: crate::win32::user32::Point { x: key.x_root, y: key.y_root },
                    });
                    if keysym >= 0x20 && keysym <= 0x7E {
                        crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                            hwnd,
                            message: 0x0102, // WM_CHAR
                            wParam: keysym as usize,
                            lParam: 1,
                            time: key.time as u32,
                            pt: crate::win32::user32::Point { x: key.x_root, y: key.y_root },
                        });
                    }
                }
                KeyRelease => {
                    let key = event.key;
                    let keysym = XKeycodeToKeysym(display, key.keycode as u8, 0);
                    let vk = xkeysym_to_vk(keysym as u64);
                    if vk != 0 {
                        crate::win32::user32::input::set_key_up(vk);
                    }
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0101, // WM_KEYUP
                        wParam: vk as usize,
                        lParam: 1,
                        time: key.time as u32,
                        pt: crate::win32::user32::Point { x: key.x_root, y: key.y_root },
                    });
                }
                ButtonPress => {
                    let btn = event.button;
                    crate::win32::user32::window::SetCursorPos(btn.x_root, btn.y_root);
                    let (msg_id, vk, wparam) = match btn.button {
                        1 => (0x0201, 0x01, 0x0001), // WM_LBUTTONDOWN, VK_LBUTTON, MK_LBUTTON
                        2 => (0x0207, 0x04, 0x0010), // WM_MBUTTONDOWN, VK_MBUTTON, MK_MBUTTON
                        3 => (0x0204, 0x02, 0x0002), // WM_RBUTTONDOWN, VK_RBUTTON, MK_RBUTTON
                        4 => (0x020A, 0, (120 << 16)), // WM_MOUSEWHEEL (scroll up)
                        5 => (0x020A, 0, ((-120i32 as u32) << 16) as usize), // WM_MOUSEWHEEL (scroll down)
                        _ => (0x0201, 0x01, 0x0001),
                    };
                    if vk != 0 {
                        crate::win32::user32::input::set_key_down(vk);
                    }
                    let lparam = (btn.x & 0xFFFF) as isize | (((btn.y & 0xFFFF) as isize) << 16);
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: msg_id,
                        wParam: wparam,
                        lParam: lparam,
                        time: btn.time as u32,
                        pt: crate::win32::user32::Point { x: btn.x_root, y: btn.y_root },
                    });
                }
                ButtonRelease => {
                    let btn = event.button;
                    crate::win32::user32::window::SetCursorPos(btn.x_root, btn.y_root);
                    let (msg_id, vk) = match btn.button {
                        1 => (0x0202, 0x01), // WM_LBUTTONUP, VK_LBUTTON
                        2 => (0x0208, 0x04), // WM_MBUTTONUP, VK_MBUTTON
                        3 => (0x0205, 0x02), // WM_RBUTTONUP, VK_RBUTTON
                        _ => (0x0202, 0x01),
                    };
                    if vk != 0 {
                        crate::win32::user32::input::set_key_up(vk);
                    }
                    let lparam = (btn.x & 0xFFFF) as isize | (((btn.y & 0xFFFF) as isize) << 16);
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: msg_id,
                        wParam: 0,
                        lParam: lparam,
                        time: btn.time as u32,
                        pt: crate::win32::user32::Point { x: btn.x_root, y: btn.y_root },
                    });
                }
                MotionNotify => {
                    let mot = event.motion;
                    crate::win32::user32::window::SetCursorPos(mot.x_root, mot.y_root);
                    let lparam = (mot.x & 0xFFFF) as isize | (((mot.y & 0xFFFF) as isize) << 16);
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0200, // WM_MOUSEMOVE
                        wParam: 0,
                        lParam: lparam,
                        time: mot.time as u32,
                        pt: crate::win32::user32::Point { x: mot.x_root, y: mot.y_root },
                    });
                }
                _ => {}
            }
        }
    }
}
