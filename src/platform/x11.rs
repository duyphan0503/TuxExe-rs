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

static LAST_QUERY_POINTER_MS: AtomicUsize = AtomicUsize::new(0);

pub fn query_pointer_root() -> Option<(i32, i32)> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as usize)
        .unwrap_or(0);

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
                    crate::win32::user32::update_window_pos(hwnd, btn.x_root - btn.x, btn.y_root - btn.y);
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
                    let lparam = ((btn.x as i16 as u16 as usize) | ((btn.y as i16 as u16 as usize) << 16)) as isize;
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
