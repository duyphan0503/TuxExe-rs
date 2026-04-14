//! X11 integration for window creation and GL context.
//!
//! This module creates REAL X11 windows and GLX contexts that Unity can use.

use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use x11::xlib::*;
use x11::glx::*;

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

static NEXT_HWND: AtomicUsize = AtomicUsize::new(0x10_000);

pub fn create_x11_window(
    title: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Option<usize> {
    if !init_x11() {
        return None;
    }

    let state = x11_state().lock().expect("x11 state poisoned");
    let state = state.as_ref()?;

    let title_c = CString::new(title).ok()?;

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
            x,
            y,
            width as u32,
            height as u32,
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

        let hwnd = NEXT_HWND.fetch_add(1, Ordering::Relaxed);

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
    reg.iter()
        .find(|w| w.hwnd == hwnd)
        .map(|w| w.x11_window)
}

pub fn x11_display() -> Option<*mut Display> {
    let state = x11_state().lock().expect("x11 state poisoned");
    state.as_ref().map(|s| s.display)
}

// ─── GLX Context ───

#[derive(Debug)]
pub struct GLContext {
    pub hglrc: usize,
    pub glx_context: usize,  // Store as usize for Send safety
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
            GLX_RED_SIZE, 8,
            GLX_GREEN_SIZE, 8,
            GLX_BLUE_SIZE, 8,
            GLX_ALPHA_SIZE, 8,
            GLX_DEPTH_SIZE, 24,
            GLX_STENCIL_SIZE, 8,
            0,
        ];

        let vi = glXChooseVisual(state.display, state.screen, attribs.as_mut_ptr());
        if vi.is_null() {
            // Try simpler config
            let mut simple_attribs = [
                GLX_RGBA,
                GLX_DOUBLEBUFFER,
                0,
            ];
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
