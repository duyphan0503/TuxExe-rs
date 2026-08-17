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

pub extern "win64" fn SwapBuffers(hdc: usize) -> i32 {
    let hwnd = crate::win32::user32::window::hdc_to_hwnd(hdc)
        .or_else(|| {
            let active = crate::win32::user32::window::GetActiveWindow();
            if active != 0 { Some(active) } else { None }
        });
    let target = hwnd.unwrap_or(0);
    crate::platform::x11::swap_buffers(target);
    set_last_error(ERROR_SUCCESS);
    1
}

fn next_gdi_handle() -> usize {
    static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(0x20000);
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BitmapInfoHeader {
    pub biSize: u32,
    pub biWidth: i32,
    pub biHeight: i32,
    pub biPlanes: u16,
    pub biBitCount: u16,
    pub biCompression: u32,
    pub biSizeImage: u32,
    pub biXPelsPerMeter: i32,
    pub biYPelsPerMeter: i32,
    pub biClrUsed: u32,
    pub biClrImportant: u32,
}

pub extern "win64" fn CreateDIBSection(
    _hdc: usize,
    pbmi: *const BitmapInfoHeader,
    _iUsage: u32,
    ppvBits: *mut *mut std::ffi::c_void,
    _hSection: usize,
    _dwOffset: u32,
) -> usize {
    let mut image_size = 65536usize;
    if !pbmi.is_null() {
        let bmi = unsafe { &*pbmi };
        let w = bmi.biWidth.abs() as usize;
        let h = bmi.biHeight.abs() as usize;
        let bpp = if bmi.biBitCount == 0 { 32 } else { bmi.biBitCount as usize };
        let row_bytes = ((w * bpp + 31) / 32) * 4;
        let calc_size = row_bytes * h;
        if bmi.biSizeImage > 0 {
            image_size = (bmi.biSizeImage as usize).max(calc_size);
        } else if calc_size > 0 {
            image_size = calc_size;
        }
    }
    image_size = image_size.max(4096);
    if !ppvBits.is_null() {
        unsafe {
            *ppvBits = libc::calloc(1, image_size);
        }
    }
    let hbitmap = next_gdi_handle();
    tracing::info!(hbitmap, image_size, "CreateDIBSection");
    set_last_error(ERROR_SUCCESS);
    hbitmap
}

pub extern "win64" fn CreateBitmap(
    _nWidth: i32,
    _nHeight: i32,
    _nPlanes: u32,
    _nBitCount: u32,
    _lpBits: *const std::ffi::c_void,
) -> usize {
    let hbitmap = next_gdi_handle();
    set_last_error(ERROR_SUCCESS);
    hbitmap
}

pub extern "win64" fn CreateCompatibleBitmap(_hdc: usize, _cx: i32, _cy: i32) -> usize {
    let hbitmap = next_gdi_handle();
    set_last_error(ERROR_SUCCESS);
    hbitmap
}

pub extern "win64" fn CreateSolidBrush(_crColor: u32) -> usize {
    let hbrush = next_gdi_handle();
    set_last_error(ERROR_SUCCESS);
    hbrush
}

pub extern "win64" fn CreateRectRgn(_x1: i32, _y1: i32, _x2: i32, _y2: i32) -> usize {
    let hrgn = next_gdi_handle();
    set_last_error(ERROR_SUCCESS);
    hrgn
}

pub extern "win64" fn DeleteObject(_hObject: usize) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn DeleteDC(_hdc: usize) -> i32 {
    set_last_error(ERROR_SUCCESS);
    1
}

pub extern "win64" fn SetBkMode(_hdc: usize, _mode: i32) -> i32 {
    1 // TRANSPARENT
}

pub extern "win64" fn GetBkMode(_hdc: usize) -> i32 {
    1 // TRANSPARENT
}

pub extern "win64" fn SetBkColor(_hdc: usize, _color: u32) -> u32 {
    0xFFFFFF // previous color (white)
}

pub extern "win64" fn GetBkColor(_hdc: usize) -> u32 {
    0xFFFFFF
}

pub extern "win64" fn SetTextColor(_hdc: usize, _color: u32) -> u32 {
    0 // previous color
}

pub extern "win64" fn GetTextColor(_hdc: usize) -> u32 {
    0 // black
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LogFontA {
    pub lfHeight: i32,
    pub lfWidth: i32,
    pub lfEscapement: i32,
    pub lfOrientation: i32,
    pub lfWeight: i32,
    pub lfItalic: u8,
    pub lfUnderline: u8,
    pub lfStrikeOut: u8,
    pub lfCharSet: u8,
    pub lfOutPrecision: u8,
    pub lfClipPrecision: u8,
    pub lfQuality: u8,
    pub lfPitchAndFamily: u8,
    pub lfFaceName: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LogFontW {
    pub lfHeight: i32,
    pub lfWidth: i32,
    pub lfEscapement: i32,
    pub lfOrientation: i32,
    pub lfWeight: i32,
    pub lfItalic: u8,
    pub lfUnderline: u8,
    pub lfStrikeOut: u8,
    pub lfCharSet: u8,
    pub lfOutPrecision: u8,
    pub lfClipPrecision: u8,
    pub lfQuality: u8,
    pub lfPitchAndFamily: u8,
    pub lfFaceName: [u16; 32],
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn CreateFontA(
    _cHeight: i32,
    _cWidth: i32,
    _cEscapement: i32,
    _cOrientation: i32,
    _cWeight: i32,
    _bItalic: u32,
    _bUnderline: u32,
    _bStrikeOut: u32,
    _iCharSet: u32,
    _iOutPrecision: u32,
    _iClipPrecision: u32,
    _iQuality: u32,
    _iPitchAndFamily: u32,
    _pszFaceName: *const i8,
) -> usize {
    next_gdi_handle()
}

#[allow(clippy::too_many_arguments)]
pub extern "win64" fn CreateFontW(
    _cHeight: i32,
    _cWidth: i32,
    _cEscapement: i32,
    _cOrientation: i32,
    _cWeight: i32,
    _bItalic: u32,
    _bUnderline: u32,
    _bStrikeOut: u32,
    _iCharSet: u32,
    _iOutPrecision: u32,
    _iClipPrecision: u32,
    _iQuality: u32,
    _iPitchAndFamily: u32,
    _pszFaceName: *const u16,
) -> usize {
    next_gdi_handle()
}

pub extern "win64" fn CreateFontIndirectA(_lplf: *const LogFontA) -> usize {
    next_gdi_handle()
}

pub extern "win64" fn CreateFontIndirectW(_lplf: *const LogFontW) -> usize {
    next_gdi_handle()
}

pub extern "win64" fn AddFontResourceA(_lpFileName: *const i8) -> i32 {
    1
}

pub extern "win64" fn AddFontResourceW(_lpFileName: *const u16) -> i32 {
    1
}

pub extern "win64" fn AddFontResourceExA(_name: *const i8, _fl: u32, _res: *mut std::ffi::c_void) -> i32 {
    1
}

pub extern "win64" fn AddFontResourceExW(_name: *const u16, _fl: u32, _res: *mut std::ffi::c_void) -> i32 {
    1
}

pub extern "win64" fn RemoveFontResourceA(_lpFileName: *const i8) -> i32 {
    1
}

pub extern "win64" fn RemoveFontResourceW(_lpFileName: *const u16) -> i32 {
    1
}

pub extern "win64" fn RemoveFontResourceExA(_name: *const i8, _fl: u32, _res: *mut std::ffi::c_void) -> i32 {
    1
}

pub extern "win64" fn RemoveFontResourceExW(_name: *const u16, _fl: u32, _res: *mut std::ffi::c_void) -> i32 {
    1
}

pub extern "win64" fn GetFontData(
    _hdc: usize,
    _dwTable: u32,
    _dwOffset: u32,
    _pvBuffer: *mut std::ffi::c_void,
    _cjBuffer: u32,
) -> u32 {
    0xFFFFFFFF
}

pub extern "win64" fn GetTextFaceA(_hdc: usize, c: i32, lpName: *mut i8) -> i32 {
    if c <= 0 || lpName.is_null() {
        return 0;
    }
    let font_name = b"Arial\0";
    let len = font_name.len().min(c as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(font_name.as_ptr() as *const i8, lpName, len);
    }
    len as i32
}

pub extern "win64" fn GetTextFaceW(_hdc: usize, c: i32, lpName: *mut u16) -> i32 {
    if c <= 0 || lpName.is_null() {
        return 0;
    }
    let font_name: [u16; 6] = [0x41, 0x72, 0x69, 0x61, 0x6C, 0]; // "Arial\0"
    let len = font_name.len().min(c as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(font_name.as_ptr(), lpName, len);
    }
    len as i32
}

pub extern "win64" fn GetCharWidth32A(
    _hdc: usize,
    _iFirst: u32,
    _iLast: u32,
    lpBuffer: *mut i32,
) -> i32 {
    if lpBuffer.is_null() {
        return 0;
    }
    let count = (_iLast.saturating_sub(_iFirst) + 1) as usize;
    for i in 0..count {
        unsafe {
            *lpBuffer.add(i) = 8;
        }
    }
    1
}

pub extern "win64" fn GetCharWidth32W(
    _hdc: usize,
    _iFirst: u32,
    _iLast: u32,
    lpBuffer: *mut i32,
) -> i32 {
    if lpBuffer.is_null() {
        return 0;
    }
    let count = (_iLast.saturating_sub(_iFirst) + 1) as usize;
    for i in 0..count {
        unsafe {
            *lpBuffer.add(i) = 8;
        }
    }
    1
}

pub extern "win64" fn EnumFontFamiliesExA(
    _hdc: usize,
    _lpLogfont: *const LogFontA,
    _lpProc: usize,
    _lParam: usize,
    _dwFlags: u32,
) -> i32 {
    1
}

pub extern "win64" fn EnumFontFamiliesExW(
    _hdc: usize,
    _lpLogfont: *const LogFontW,
    _lpProc: usize,
    _lParam: usize,
    _dwFlags: u32,
) -> i32 {
    1
}

pub extern "win64" fn EnumFontFamiliesA(
    _hdc: usize,
    _lpLogfont: *const i8,
    _lpProc: usize,
    _lParam: usize,
) -> i32 {
    1
}

pub extern "win64" fn EnumFontFamiliesW(
    _hdc: usize,
    _lpLogfont: *const u16,
    _lpProc: usize,
    _lParam: usize,
) -> i32 {
    1
}

pub extern "win64" fn GetTextMetricsA(_hdc: usize, lptm: *mut std::ffi::c_void) -> i32 {
    if !lptm.is_null() {
        unsafe { std::ptr::write_bytes(lptm.cast::<u8>(), 0, 60); }
    }
    1
}

pub extern "win64" fn GetTextMetricsW(_hdc: usize, lptm: *mut std::ffi::c_void) -> i32 {
    if !lptm.is_null() {
        unsafe { std::ptr::write_bytes(lptm.cast::<u8>(), 0, 60); }
    }
    1
}

pub extern "win64" fn GetOutlineTextMetricsA(_hdc: usize, _cbData: u32, _potm: *mut std::ffi::c_void) -> u32 {
    0
}

pub extern "win64" fn GetOutlineTextMetricsW(_hdc: usize, _cbData: u32, _potm: *mut std::ffi::c_void) -> u32 {
    0
}

pub extern "win64" fn GetTextExtentPoint32A(_hdc: usize, lpString: *const i8, c: i32, lpSize: *mut i32) -> i32 {
    if !lpSize.is_null() {
        unsafe {
            *lpSize = c * 8;
            *lpSize.add(1) = 16;
        }
    }
    1
}

pub extern "win64" fn GetTextExtentPoint32W(_hdc: usize, lpString: *const u16, c: i32, lpSize: *mut i32) -> i32 {
    if !lpSize.is_null() {
        unsafe {
            *lpSize = c * 8;
            *lpSize.add(1) = 16;
        }
    }
    1
}

pub extern "win64" fn ExtTextOutW(
    _hdc: usize,
    _x: i32,
    _y: i32,
    _options: u32,
    _lprect: *const std::ffi::c_void,
    _lpString: *const u16,
    _c: u32,
    _lpDx: *const i32,
) -> i32 {
    1
}

pub extern "win64" fn GetDIBits(
    _hdc: usize,
    _hbm: usize,
    _start: u32,
    _cLines: u32,
    _lpvBits: *mut std::ffi::c_void,
    _lpbmi: *mut std::ffi::c_void,
    _usage: u32,
) -> i32 {
    1
}

pub extern "win64" fn GetDeviceGammaRamp(_hdc: usize, _lpRamp: *mut std::ffi::c_void) -> i32 {
    1
}

pub extern "win64" fn SetDeviceGammaRamp(_hdc: usize, _lpRamp: *const std::ffi::c_void) -> i32 {
    1
}

pub extern "win64" fn GetICMProfileW(_hdc: usize, pBufSize: *mut u32, _pszFilename: *mut u16) -> i32 {
    if !pBufSize.is_null() {
        unsafe { *pBufSize = 0; }
    }
    0
}

pub extern "win64" fn GetPixelFormat(_hdc: usize) -> i32 {
    1
}

pub extern "win64" fn DescribePixelFormat(
    _hdc: usize,
    _iPixelFormat: i32,
    _nBytes: u32,
    ppfd: *mut PixelFormatDescriptor,
) -> i32 {
    if !ppfd.is_null() {
        unsafe {
            (*ppfd).nSize = std::mem::size_of::<PixelFormatDescriptor>() as u16;
            (*ppfd).nVersion = 1;
            (*ppfd).dwFlags = 0x24; // PFD_SUPPORT_OPENGL | PFD_DRAW_TO_WINDOW
            (*ppfd).iPixelType = 0; // PFD_TYPE_RGBA
            (*ppfd).cColorBits = 32;
            (*ppfd).cDepthBits = 24;
            (*ppfd).cStencilBits = 8;
        }
    }
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
    exports.insert("CreateCompatibleBitmap", CreateCompatibleBitmap as usize);
    exports.insert("CreateBitmap", CreateBitmap as usize);
    exports.insert("CreateDIBSection", CreateDIBSection as usize);
    exports.insert("CreateSolidBrush", CreateSolidBrush as usize);
    exports.insert("CreateRectRgn", CreateRectRgn as usize);
    exports.insert("DeleteObject", DeleteObject as usize);
    exports.insert("DeleteDC", DeleteDC as usize);
    exports.insert("SelectObject", SelectObject as usize);
    exports.insert("SetBkMode", SetBkMode as usize);
    exports.insert("GetBkMode", GetBkMode as usize);
    exports.insert("SetBkColor", SetBkColor as usize);
    exports.insert("GetBkColor", GetBkColor as usize);
    exports.insert("SetTextColor", SetTextColor as usize);
    exports.insert("GetTextColor", GetTextColor as usize);
    exports.insert("CreateFontA", CreateFontA as usize);
    exports.insert("CreateFontW", CreateFontW as usize);
    exports.insert("CreateFontIndirectA", CreateFontIndirectA as usize);
    exports.insert("CreateFontIndirectW", CreateFontIndirectW as usize);
    exports.insert("AddFontResourceA", AddFontResourceA as usize);
    exports.insert("AddFontResourceW", AddFontResourceW as usize);
    exports.insert("AddFontResourceExA", AddFontResourceExA as usize);
    exports.insert("AddFontResourceExW", AddFontResourceExW as usize);
    exports.insert("RemoveFontResourceA", RemoveFontResourceA as usize);
    exports.insert("RemoveFontResourceW", RemoveFontResourceW as usize);
    exports.insert("RemoveFontResourceExA", RemoveFontResourceExA as usize);
    exports.insert("RemoveFontResourceExW", RemoveFontResourceExW as usize);
    exports.insert("GetFontData", GetFontData as usize);
    exports.insert("GetTextFaceA", GetTextFaceA as usize);
    exports.insert("GetTextFaceW", GetTextFaceW as usize);
    exports.insert("GetCharWidth32A", GetCharWidth32A as usize);
    exports.insert("GetCharWidth32W", GetCharWidth32W as usize);
    exports.insert("EnumFontFamiliesA", EnumFontFamiliesA as usize);
    exports.insert("EnumFontFamiliesW", EnumFontFamiliesW as usize);
    exports.insert("EnumFontFamiliesExA", EnumFontFamiliesExA as usize);
    exports.insert("EnumFontFamiliesExW", EnumFontFamiliesExW as usize);
    exports.insert("GetTextMetricsA", GetTextMetricsA as usize);
    exports.insert("GetTextMetricsW", GetTextMetricsW as usize);
    exports.insert("GetOutlineTextMetricsA", GetOutlineTextMetricsA as usize);
    exports.insert("GetOutlineTextMetricsW", GetOutlineTextMetricsW as usize);
    exports.insert("GetTextExtentPoint32A", GetTextExtentPoint32A as usize);
    exports.insert("GetTextExtentPoint32W", GetTextExtentPoint32W as usize);
    exports.insert("ExtTextOutW", ExtTextOutW as usize);
    exports.insert("GetDIBits", GetDIBits as usize);
    exports.insert("GetDeviceGammaRamp", GetDeviceGammaRamp as usize);
    exports.insert("SetDeviceGammaRamp", SetDeviceGammaRamp as usize);
    exports.insert("GetICMProfileW", GetICMProfileW as usize);
    exports.insert("GetPixelFormat", GetPixelFormat as usize);
    exports.insert("DescribePixelFormat", DescribePixelFormat as usize);
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
