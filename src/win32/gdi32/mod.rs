#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;

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
pub struct PaintStruct {
    pub hdc: usize,
    pub fErase: i32,
    pub rcPaint: Rect,
    pub fRestore: i32,
    pub fIncUpdate: i32,
    pub rgbReserved: [u8; 32],
}

fn set_last_error(value: u32) {
    crate::win32::kernel32::error::set_last_error(value);
}

fn next_hdc() -> usize {
    static NEXT_HDC: AtomicUsize = AtomicUsize::new(1);
    NEXT_HDC.fetch_add(1, Ordering::Relaxed)
}

pub extern "win64" fn BeginPaint(_hWnd: usize, lpPaint: *mut PaintStruct) -> usize {
    if lpPaint.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let hdc = next_hdc();
    unsafe {
        (*lpPaint).hdc = hdc;
    }
    set_last_error(ERROR_SUCCESS);
    hdc
}

pub extern "win64" fn EndPaint(_hWnd: usize, lpPaint: *const PaintStruct) -> i32 {
    if lpPaint.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn TextOutA(_hdc: usize, _x: i32, _y: i32, lpString: *const i8, c: i32) -> i32 {
    if c > 0 && lpString.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn TextOutW(_hdc: usize, _x: i32, _y: i32, lpString: *const u16, c: i32) -> i32 {
    if c > 0 && lpString.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn Rectangle(
    _hdc: usize,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn Ellipse(
    _hdc: usize,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn BitBlt(
    _hdcDest: usize,
    _xDest: i32,
    _yDest: i32,
    _width: i32,
    _height: i32,
    _hdcSrc: usize,
    _xSrc: i32,
    _ySrc: i32,
    _rop: u32,
) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CreateCompatibleDC(_hdc: usize) -> usize {
    let hdc = next_hdc();
    set_last_error(ERROR_SUCCESS);
    hdc
}

pub extern "win64" fn SelectObject(_hdc: usize, _hObject: usize) -> usize {
    set_last_error(ERROR_SUCCESS);
    0
}

/// Pixel format descriptor for OpenGL
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PixelFormatDescriptor {
    pub nSize: u16,
    pub nVersion: u16,
    pub dwFlags: u32,
    pub iPixelType: u8,
    pub cColorBits: u8,
    pub cRedBits: u8,
    pub cRedShift: u8,
    pub cGreenBits: u8,
    pub cGreenShift: u8,
    pub cBlueBits: u8,
    pub cBlueShift: u8,
    pub cAlphaBits: u8,
    pub cAlphaShift: u8,
    pub cAccumBits: u8,
    pub cAccumRedBits: u8,
    pub cAccumGreenBits: u8,
    pub cAccumBlueBits: u8,
    pub cAccumAlphaBits: u8,
    pub cDepthBits: u8,
    pub cStencilBits: u8,
    pub cAuxBuffers: u8,
    pub iLayerType: u8,
    pub bReserved: u8,
    pub dwLayerMask: u32,
    pub dwVisibleMask: u32,
    pub dwDamageMask: u32,
}

pub extern "win64" fn GetDeviceCaps(_hdc: usize, _nIndex: i32) -> i32 {
    // Return sensible defaults for common queries
    // Windows GDI device capabilities: https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-getdevicecaps
    if _nIndex == 8
    /*HORZRES*/
    {
        1920 // Width in pixels
    } else if _nIndex == 10
    /*VERTRES*/
    {
        1080 // Height in pixels
    } else if _nIndex == 12
    /*BITSPIXEL*/
    {
        32 // Bits per pixel
    } else if _nIndex == 14
    /*PLANES*/
    {
        1 // Number of color planes
    } else if _nIndex == 88
    /*LOGPIXELSX*/
    {
        96 // Horizontal DPI
    } else if _nIndex == 90
    /*LOGPIXELSY*/
    {
        96 // Vertical DPI
    } else if _nIndex == 116
    /*VREFRESH*/
    {
        60 // Vertical refresh rate
    } else if _nIndex == 38
    /*RASTERCAPS*/
    {
        0x00000001 // RC_BITBLT
    } else {
        0
    }
}

pub extern "win64" fn SetPixelFormat(
    _hdc: usize,
    _format: i32,
    _ppfd: *const PixelFormatDescriptor,
) -> i32 {
    // Always succeed — we're stubbing OpenGL anyway
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn ChoosePixelFormat(_hdc: usize, _ppfd: *const PixelFormatDescriptor) -> i32 {
    // Return format 1 — good enough for basic OpenGL
    1
}

pub extern "win64" fn SwapBuffers(_hdc: usize) -> i32 {
    // No-op — nothing to swap
    set_last_error(ERROR_SUCCESS);
    1
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    exports.insert("BeginPaint", BeginPaint as usize);
    exports.insert("EndPaint", EndPaint as usize);
    exports.insert("TextOutA", TextOutA as usize);
    exports.insert("TextOutW", TextOutW as usize);
    exports.insert("Rectangle", Rectangle as usize);
    exports.insert("Ellipse", Ellipse as usize);
    exports.insert("BitBlt", BitBlt as usize);
    exports.insert("CreateCompatibleDC", CreateCompatibleDC as usize);
    exports.insert("SelectObject", SelectObject as usize);
    exports.insert("GetDeviceCaps", GetDeviceCaps as usize);
    exports.insert("SetPixelFormat", SetPixelFormat as usize);
    exports.insert("ChoosePixelFormat", ChoosePixelFormat as usize);
    exports.insert("SwapBuffers", SwapBuffers as usize);

    exports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn begin_and_end_paint_round_trip() {
        let _guard = serial_guard();
        let mut paint = PaintStruct::default();
        let hdc = BeginPaint(1, &raw mut paint);
        assert_ne!(hdc, 0);
        assert_eq!(paint.hdc, hdc);
        assert_eq!(EndPaint(1, &raw const paint), 1);
    }

    #[test]
    fn text_out_rejects_null_buffer_when_length_positive() {
        let _guard = serial_guard();
        assert_eq!(TextOutA(1, 0, 0, std::ptr::null(), 1), 0);
        assert_eq!(TextOutW(1, 0, 0, std::ptr::null(), 1), 0);
    }
}
