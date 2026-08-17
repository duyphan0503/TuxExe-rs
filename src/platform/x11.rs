//! X11 integration for window creation and GL context.
//!
//! This module creates REAL X11 windows and GLX contexts that Unity can use.

use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

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

unsafe extern "C" fn x11_io_error_handler(_display: *mut Display) -> std::os::raw::c_int {
    tracing::warn!("Suppressed non-fatal X11 IO error");
    0
}

fn init_x11() -> bool {
    let mut state = x11_state().lock().expect("x11 state poisoned");
    if state.is_some() {
        return true;
    }

    eprintln!("[TuxExe] Initializing X11...");

    unsafe {
        XInitThreads();
        XSetErrorHandler(Some(x11_error_handler));
        XSetIOErrorHandler(Some(x11_io_error_handler));

        let display = XOpenDisplay(std::ptr::null());
        if display.is_null() {
            eprintln!("[TuxExe] XOpenDisplay failed");
            return false;
        }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorGeometry {
    pub is_primary: bool,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

fn cached_monitors() -> &'static RwLock<Option<Vec<MonitorGeometry>>> {
    static CACHED: OnceLock<RwLock<Option<Vec<MonitorGeometry>>>> = OnceLock::new();
    CACHED.get_or_init(|| RwLock::new(None))
}

/// Query all connected monitors with their position and dimensions.
pub fn get_monitors() -> Vec<MonitorGeometry> {
    if let Ok(guard) = cached_monitors().read() {
        if let Some(ref list) = *guard {
            return list.clone();
        }
    }

    if !init_x11() {
        return vec![MonitorGeometry {
            is_primary: true,
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        }];
    }

    let state_guard = x11_state().lock().ok();
    let Some(state_guard) = state_guard else {
        return vec![MonitorGeometry {
            is_primary: true,
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        }];
    };
    let Some(state) = state_guard.as_ref() else {
        return vec![MonitorGeometry {
            is_primary: true,
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        }];
    };

    let monitors = unsafe {
        // Try XRRGetMonitors first (XRandR)
        let mut count = 0;
        let monitors_ptr = x11::xrandr::XRRGetMonitors(state.display, state.root_window, 1, &mut count);
        if !monitors_ptr.is_null() && count > 0 {
            let mut list = Vec::with_capacity(count as usize);
            let slice = std::slice::from_raw_parts(monitors_ptr, count as usize);
            for m in slice {
                list.push(MonitorGeometry {
                    is_primary: m.primary != 0,
                    x: m.x,
                    y: m.y,
                    width: m.width,
                    height: m.height,
                });
            }
            x11::xrandr::XRRFreeMonitors(monitors_ptr);
            // If none was marked primary, mark the first one as primary
            if !list.is_empty() && !list.iter().any(|m| m.is_primary) {
                list[0].is_primary = true;
            }
            list
        } else {
            // Fallback: Xinerama
            let mut xin_count = 0;
            let xin_ptr = x11::xinerama::XineramaQueryScreens(state.display, &mut xin_count);
            if !xin_ptr.is_null() && xin_count > 0 {
                let mut list = Vec::with_capacity(xin_count as usize);
                let slice = std::slice::from_raw_parts(xin_ptr, xin_count as usize);
                for (idx, s) in slice.iter().enumerate() {
                    list.push(MonitorGeometry {
                        is_primary: idx == 0,
                        x: s.x_org as i32,
                        y: s.y_org as i32,
                        width: s.width as i32,
                        height: s.height as i32,
                    });
                }
                x11::xlib::XFree(xin_ptr.cast());
                list
            } else {
                // Fallback: Default screen size
                let w = XDisplayWidth(state.display, state.screen);
                let h = XDisplayHeight(state.display, state.screen);
                vec![MonitorGeometry {
                    is_primary: true,
                    x: 0,
                    y: 0,
                    width: if w > 0 { w as i32 } else { 1920 },
                    height: if h > 0 { h as i32 } else { 1080 },
                }]
            }
        }
    };

    if let Ok(mut guard) = cached_monitors().write() {
        *guard = Some(monitors.clone());
    }

    monitors
}

/// Query the primary display monitor.
pub fn get_primary_monitor() -> MonitorGeometry {
    let monitors = get_monitors();
    monitors
        .iter()
        .find(|m| m.is_primary)
        .copied()
        .or_else(|| monitors.first().copied())
        .unwrap_or(MonitorGeometry {
            is_primary: true,
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        })
}

/// Query the primary display monitor's resolution (width, height).
pub fn get_screen_size() -> Option<(i32, i32)> {
    let primary = get_primary_monitor();
    Some((primary.width, primary.height))
}

/// Query the primary display monitor's refresh rate in Hz.
pub fn get_screen_refresh_rate() -> u32 {
    if !init_x11() {
        return 60;
    }

    let state_guard = x11_state().lock().ok();
    let Some(state_guard) = state_guard else { return 60; };
    let Some(state) = state_guard.as_ref() else { return 60; };

    unsafe {
        let screen_info = x11::xrandr::XRRGetScreenInfo(state.display, state.root_window);
        if !screen_info.is_null() {
            let rate = x11::xrandr::XRRConfigCurrentRate(screen_info);
            x11::xrandr::XRRFreeScreenConfigInfo(screen_info);
            if rate > 0 {
                return rate as u32;
            }
        }
    }

    60
}

/// Query the virtual desktop bounding box across all monitors (x, y, width, height).
pub fn get_virtual_screen_size() -> (i32, i32, i32, i32) {
    let monitors = get_monitors();
    if monitors.is_empty() {
        return (0, 0, 1920, 1080);
    }
    let min_x = monitors.iter().map(|m| m.x).min().unwrap_or(0);
    let min_y = monitors.iter().map(|m| m.y).min().unwrap_or(0);
    let max_x = monitors.iter().map(|m| m.x + m.width).max().unwrap_or(1920);
    let max_y = monitors.iter().map(|m| m.y + m.height).max().unwrap_or(1080);
    (min_x, min_y, (max_x - min_x).max(1), (max_y - min_y).max(1))
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
    create_x11_window_with_visibility(title, x, y, width, height, true)
}

pub fn create_x11_window_with_visibility(
    title: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    visible: bool,
) -> Option<usize> {
    if !init_x11() {
        return None;
    }

    let primary = get_primary_monitor();
    let state = x11_state().lock().expect("x11 state poisoned");
    let state = state.as_ref()?;

    let title_c = CString::new(title).ok()?;

    let win_width = if width <= 0 || width == i32::MIN { 1280 } else { width };
    let win_height = if height <= 0 || height == i32::MIN { 720 } else { height };
    let win_x = if x == i32::MIN || x < 0 {
        primary.x + ((primary.width - win_width) / 2).max(0)
    } else {
        x
    };
    let win_y = if y == i32::MIN || y < 0 {
        primary.y + ((primary.height - win_height) / 2).max(0)
    } else {
        y
    };

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
                | StructureNotifyMask
                | FocusChangeMask,
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
        if visible {
            XMapWindow(state.display, x11_win);
        }
        XFlush(state.display);

        // DXVK's TuxExe WSI backend receives HWND directly, so preserve the
        // Xlib Window ID rather than manufacturing an unrelated handle.
        let hwnd = x11_win as usize;

        window_registry().lock().expect("window reg poisoned").push(X11Window {
            hwnd,
            x11_window: x11_win,
            width: win_width,
            height: win_height,
            visible,
            title: title.to_string(),
        });

        trace!("Created X11 window: hwnd=0x{:x} x11=0x{:x} visible={}", hwnd, x11_win, visible);
        Some(hwnd)
    }
}

pub fn destroy_x11_window(hwnd: usize) -> bool {
    let display = {
        let state = x11_state().lock().expect("x11 state poisoned");
        let Some(state) = state.as_ref() else {
            return false;
        };
        state.display
    };

    let mut reg = window_registry().lock().expect("window reg poisoned");
    let pos = reg.iter().position(|w| w.hwnd == hwnd);
    if let Some(idx) = pos {
        let win = reg.remove(idx);
        unsafe {
            XUnmapWindow(display, win.x11_window);
            XDestroyWindow(display, win.x11_window);
            XFlush(display);
        }
        trace!("Destroyed X11 window: hwnd=0x{:x}", hwnd);
        true
    } else {
        false
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

/// Updates the title of the native X11 window.
pub fn set_x11_window_title(hwnd: usize, title: &str) -> bool {
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

    let title_c = std::ffi::CString::new(title).unwrap_or_default();
    unsafe {
        XStoreName(display, window, title_c.as_ptr());
        XFlush(display);
    }
    if let Some(record) = window_registry()
        .lock()
        .expect("window reg poisoned")
        .iter_mut()
        .find(|record| record.hwnd == hwnd)
    {
        record.title = title.to_string();
    }
    true
}

/// Raises a mapped native window to match `SetForegroundWindow` semantics.
pub fn raise_x11_window(hwnd: usize) -> bool {
    let Ok(state_guard) = x11_state().try_lock() else {
        return false;
    };
    let Some(state) = state_guard.as_ref() else {
        return false;
    };
    let display = state.display;
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
    make_gl_context_current_for_window(hglrc, None)
}

pub fn make_gl_context_current_for_window(hglrc: usize, target_hwnd: Option<usize>) -> bool {
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

    let mut reg = gl_context_registry().lock().expect("gl context reg poisoned");
    let ctx = match reg.iter_mut().find(|c| c.hglrc == hglrc) {
        Some(c) => c,
        None => return false,
    };
    let glx_ctx = ctx.glx_context as *mut __GLXcontextRec;

    let target_win = target_hwnd.and_then(hwnd_to_x11_window).or_else(|| {
        window_registry()
            .lock()
            .ok()?
            .last()
            .map(|w| w.x11_window)
    });

    let x11_win = if let Some(w) = target_win {
        ctx.x11_window = w;
        w
    } else {
        ctx.x11_window
    };

    unsafe {
        let state = x11_state().lock().expect("x11 state poisoned");
        if let Some(s) = state.as_ref() {
            let result = glXMakeCurrent(s.display, x11_win, glx_ctx);
            trace!(hglrc, x11_win, result, "glXMakeCurrent");
            result != 0
        } else {
            false
        }
    }
}

pub fn swap_buffers(hwnd: usize) {
    let x11_win = hwnd_to_x11_window(hwnd).or_else(|| {
        window_registry()
            .lock()
            .ok()?
            .last()
            .map(|w| w.x11_window)
    });

    if let Some(win) = x11_win {
        if let Some(display) = x11_display() {
            unsafe {
                glXSwapBuffers(display, win);
                XFlush(display);
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
        // Punctuation and symbols
        0x0021 => 0x31, // '!' -> VK_1 (with shift)
        0x0040 => 0x32, // '@' -> VK_2
        0x0023 => 0x33, // '#' -> VK_3
        0x0024 => 0x34, // '$' -> VK_4
        0x0025 => 0x35, // '%' -> VK_5
        0x005e => 0x36, // '^' -> VK_6
        0x0026 => 0x37, // '&' -> VK_7
        0x002a => 0x38, // '*' -> VK_8
        0x0028 => 0x39, // '(' -> VK_9
        0x0029 => 0x30, // ')' -> VK_0
        0x002d | 0x005f => 0xBD, // '-' / '_' -> VK_OEM_MINUS
        0x003d | 0x002b => 0xBB, // '=' / '+' -> VK_OEM_PLUS
        0x005b | 0x007b => 0xDB, // '[' / '{' -> VK_OEM_4
        0x005d | 0x007d => 0xDD, // ']' / '}' -> VK_OEM_6
        0x005c | 0x007c => 0xDC, // '\' / '|' -> VK_OEM_5
        0x003b | 0x003a => 0xBA, // ';' / ':' -> VK_OEM_1
        0x0027 | 0x0022 => 0xDE, // '\'' / '"' -> VK_OEM_7
        0x002c | 0x003c => 0xBC, // ',' / '<' -> VK_OEM_COMMA
        0x002e | 0x003e => 0xBE, // '.' / '>' -> VK_OEM_PERIOD
        0x002f | 0x003f => 0xBF, // '/' / '?' -> VK_OEM_2
        0x0060 | 0x007e => 0xC0, // '`' / '~' -> VK_OEM_3
        // Control and navigation keys
        0xff08 => 0x08, // VK_BACK
        0xff09 => 0x09, // VK_TAB
        0xff0d => 0x0D, // VK_RETURN
        0xff13 => 0x13, // VK_PAUSE
        0xff14 => 0x91, // VK_SCROLL
        0xff1b => 0x1B, // VK_ESCAPE
        0xff20 => 0x20, // Multi-key / Space
        0xff50 => 0x24, // VK_HOME
        0xff51 => 0x25, // VK_LEFT
        0xff52 => 0x26, // VK_UP
        0xff53 => 0x27, // VK_RIGHT
        0xff54 => 0x28, // VK_DOWN
        0xff55 => 0x21, // VK_PRIOR (PageUp)
        0xff56 => 0x22, // VK_NEXT (PageDown)
        0xff57 => 0x23, // VK_END
        0xff61 => 0x2C, // VK_SNAPSHOT (PrintScreen)
        0xff63 => 0x2D, // VK_INSERT
        0xffff => 0x2E, // VK_DELETE
        // Modifier keys (left/right and generic)
        0xffe1 => 0xA0, // Shift_L -> VK_LSHIFT
        0xffe2 => 0xA1, // Shift_R -> VK_RSHIFT
        0xffe3 => 0xA2, // Control_L -> VK_LCONTROL
        0xffe4 => 0xA3, // Control_R -> VK_RCONTROL
        0xffe5 => 0x14, // Caps_Lock -> VK_CAPITAL
        0xffe9 => 0xA4, // Alt_L -> VK_LMENU
        0xffea => 0xA5, // Alt_R -> VK_RMENU
        0xffeb => 0x5B, // Super_L -> VK_LWIN
        0xffec => 0x5C, // Super_R -> VK_RWIN
        0xff7f => 0x90, // Num_Lock -> VK_NUMLOCK
        // Keypad / Numpad keys
        0xff8d => 0x0D, // KP_Enter -> VK_RETURN
        0xffaa => 0x6A, // KP_Multiply -> VK_MULTIPLY
        0xffab => 0x6B, // KP_Add -> VK_ADD
        0xffad => 0x6D, // KP_Subtract -> VK_SUBTRACT
        0xffae => 0x6E, // KP_Decimal -> VK_DECIMAL
        0xffaf => 0x6F, // KP_Divide -> VK_DIVIDE
        0xffb0..=0xffb9 => (keysym - 0xffb0 + 0x60) as u32, // KP_0..KP_9 -> VK_NUMPAD0..VK_NUMPAD9
        // Function keys F1..F24
        0xffbe..=0xffcb => (keysym - 0xffbe + 0x70) as u32, // VK_F1..VK_F12
        0xffcc..=0xffd7 => (keysym - 0xffcc + 0x7C) as u32, // VK_F13..VK_F24
        _ => 0,
    }
}

static LAST_QUERY_POINTER_MS: AtomicUsize = AtomicUsize::new(0);

pub fn query_pointer_root() -> Option<(i32, i32)> {
    let now_ms = crate::win32::kernel32::time::get_tick_count() as usize;

    let last = LAST_QUERY_POINTER_MS.load(Ordering::Relaxed);
    if now_ms > last && now_ms - last < 16 {
        let pos = crate::win32::user32::window::cursor_position()
            .lock()
            .map(|p| (p.x, p.y))
            .ok();
        return pos;
    }
    LAST_QUERY_POINTER_MS.store(now_ms, Ordering::Relaxed);

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
                    let mut root_x = cfg.x;
                    let mut root_y = cfg.y;
                    let mut child: Window = 0;
                    let _ = XTranslateCoordinates(
                        display,
                        x11_win,
                        state.root_window,
                        0,
                        0,
                        &mut root_x,
                        &mut root_y,
                        &mut child,
                    );

                    crate::win32::user32::update_window_rect(hwnd, root_x, root_y, cfg.width, cfg.height);

                    let move_lparam = ((root_x as u16 as usize) | ((root_y as u16 as usize) << 16)) as isize;
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0003, // WM_MOVE
                        wParam: 0,
                        lParam: move_lparam,
                        time: 0,
                        ..Default::default()
                    });

                    let size_lparam = ((cfg.width as u16 as usize) | ((cfg.height as u16 as usize) << 16)) as isize;
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0005, // WM_SIZE
                        wParam: 0,
                        lParam: size_lparam,
                        time: 0,
                        ..Default::default()
                    });
                }
                KeyPress => {
                    let key = event.key;
                    let keysym = XKeycodeToKeysym(display, key.keycode as u8, 0);
                    let vk = xkeysym_to_vk(keysym as u64);
                    if vk != 0 {
                        // Check if key was already down (for bit 30 — previous key state)
                        let was_down = crate::win32::user32::input::is_key_down(vk);
                        crate::win32::user32::input::set_key_down(vk);

                        // Build proper Win32 lParam for WM_KEYDOWN:
                        //   bits  0-15: repeat count (1)
                        //   bits 16-23: OEM scan code
                        //   bit  24: extended key flag (1 for E0-prefixed keys)
                        //   bits 25-28: reserved (0)
                        //   bit  29: context code (0 for WM_KEYDOWN)
                        //   bit  30: previous key state (1 if key was already down)
                        //   bit  31: transition state (0 for key down)
                        let scan = crate::win32::user32::input::vk_to_scan_code(vk);
                        let is_ext = crate::win32::user32::input::is_extended_key(vk);
                        let lparam: isize = 1
                            | ((scan as isize) << 16)
                            | (if is_ext { 1isize << 24 } else { 0 })
                            | (if was_down { 1isize << 30 } else { 0 });
                        // bit 31 = 0 (key-down transition)

                        crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                            hwnd,
                            message: 0x0100, // WM_KEYDOWN
                            wParam: vk as usize,
                            lParam: lparam,
                            time: key.time as u32,
                            pt: crate::win32::user32::Point { x: key.x_root, y: key.y_root },
                        });
                        // NOTE: Do NOT post WM_CHAR here — TranslateMessage() in the guest
                        // message loop generates WM_CHAR from WM_KEYDOWN. Posting it here
                        // would produce duplicate characters.
                    }
                }
                KeyRelease => {
                    let key = event.key;
                    // Ignore auto-repeat: X11 fires KeyRelease+KeyPress for held keys;
                    // detect this by peeking at the next event.
                    let is_auto_repeat = XPending(display) > 0 && {
                        let mut peek: XEvent = std::mem::zeroed();
                        XPeekEvent(display, &mut peek);
                        peek.type_ == KeyPress
                            && peek.key.keycode == key.keycode
                            && peek.key.time == key.time
                    };
                    if is_auto_repeat {
                        // Drop both events: let the already-queued WM_KEYDOWN serve as repeat.
                        let mut _discard: XEvent = std::mem::zeroed();
                        XNextEvent(display, &mut _discard);
                    } else {
                        let keysym = XKeycodeToKeysym(display, key.keycode as u8, 0);
                        let vk = xkeysym_to_vk(keysym as u64);
                        if vk != 0 {
                            crate::win32::user32::input::set_key_up(vk);

                            // Build proper Win32 lParam for WM_KEYUP:
                            //   bits  0-15: repeat count (1)
                            //   bits 16-23: OEM scan code
                            //   bit  24: extended key flag
                            //   bit  30: previous key state (1 = was down)
                            //   bit  31: transition state (1 = key up)
                            let scan = crate::win32::user32::input::vk_to_scan_code(vk);
                            let is_ext = crate::win32::user32::input::is_extended_key(vk);
                            let lparam: isize = 1
                                | ((scan as isize) << 16)
                                | (if is_ext { 1isize << 24 } else { 0 })
                                | (1isize << 30) // was previously down
                                | (1isize << 31); // key-up transition

                            crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                                hwnd,
                                message: 0x0101, // WM_KEYUP
                                wParam: vk as usize,
                                lParam: lparam,
                                time: key.time as u32,
                                pt: crate::win32::user32::Point { x: key.x_root, y: key.y_root },
                            });
                        }
                    }
                }
                FocusIn => {
                    // X11 window gained keyboard focus → update Windows focus state
                    crate::win32::user32::set_focused_hwnd(hwnd);
                    crate::win32::user32::set_foreground_hwnd(hwnd);
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x001C, // WM_ACTIVATEAPP
                        wParam: 1,
                        lParam: 0,
                        time: 0,
                        ..Default::default()
                    });
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0006, // WM_ACTIVATE
                        wParam: 1, // WA_ACTIVE
                        lParam: 0,
                        time: 0,
                        ..Default::default()
                    });
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0007, // WM_SETFOCUS
                        wParam: 0,
                        lParam: 0,
                        time: 0,
                        ..Default::default()
                    });
                }
                FocusOut => {
                    // X11 window lost focus → send WM_KILLFOCUS
                    crate::win32::user32::set_focused_hwnd(0);
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0008, // WM_KILLFOCUS
                        wParam: 0,
                        lParam: 0,
                        time: 0,
                        ..Default::default()
                    });
                }
                ButtonPress => {
                    let btn = event.button;
                    crate::win32::user32::update_window_pos(hwnd, btn.x_root - btn.x, btn.y_root - btn.y);
                    crate::win32::user32::window::SetCursorPos(btn.x_root, btn.y_root);
                    crate::win32::user32::set_focused_hwnd(hwnd);
                    crate::win32::user32::set_foreground_hwnd(hwnd);
                    let (msg_id, vk, wparam) = match btn.button {
                        1 => (0x0201, 0x01, 0x0001), // WM_LBUTTONDOWN, VK_LBUTTON, MK_LBUTTON
                        2 => (0x0207, 0x04, 0x0010), // WM_MBUTTONDOWN, VK_MBUTTON, MK_MBUTTON
                        3 => (0x0204, 0x02, 0x0002), // WM_RBUTTONDOWN, VK_RBUTTON, MK_RBUTTON
                        4 => (0x020A, 0, (120 << 16)), // WM_MOUSEWHEEL (scroll up)
                        5 => (0x020A, 0, ((-120i32 as u32) << 16) as usize), // WM_MOUSEWHEEL (scroll down)
                        6 => (0x020E, 0, ((-120i32 as u32) << 16) as usize), // WM_MOUSEHWHEEL (scroll left)
                        7 => (0x020E, 0, (120 << 16)), // WM_MOUSEHWHEEL (scroll right)
                        _ => (0x0201, 0x01, 0x0001),
                    };
                    if vk != 0 {
                        crate::win32::user32::input::set_key_down(vk);
                    }
                    let (lx, ly) = if msg_id == 0x020A || msg_id == 0x020E {
                        (btn.x_root, btn.y_root)
                    } else {
                        (btn.x, btn.y)
                    };
                    let lparam = ((lx as i16 as u16 as usize) | ((ly as i16 as u16 as usize) << 16)) as isize;
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
                    crate::win32::user32::update_window_pos(hwnd, btn.x_root - btn.x, btn.y_root - btn.y);
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
                    let lparam = ((btn.x as i16 as u16 as usize) | ((btn.y as i16 as u16 as usize) << 16)) as isize;
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
                    crate::win32::user32::update_window_pos(hwnd, mot.x_root - mot.x, mot.y_root - mot.y);
                    crate::win32::user32::window::SetCursorPos(mot.x_root, mot.y_root);

                    let mut wparam = 0usize;
                    if (mot.state & (1 << 8)) != 0 {
                        wparam |= 0x0001; // MK_LBUTTON
                    }
                    if (mot.state & (1 << 10)) != 0 {
                        wparam |= 0x0002; // MK_RBUTTON
                    }
                    if (mot.state & (1 << 0)) != 0 {
                        wparam |= 0x0004; // MK_SHIFT
                    }
                    if (mot.state & (1 << 2)) != 0 {
                        wparam |= 0x0008; // MK_CONTROL
                    }
                    if (mot.state & (1 << 9)) != 0 {
                        wparam |= 0x0010; // MK_MBUTTON
                    }

                    let lparam = ((mot.x as i16 as u16 as usize) | ((mot.y as i16 as u16 as usize) << 16)) as isize;
                    crate::win32::user32::enqueue_message(crate::win32::user32::Msg {
                        hwnd,
                        message: 0x0200, // WM_MOUSEMOVE
                        wParam: wparam,
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
