use crate::win32::user32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceBackend {
    X11,
    Wayland,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VulkanSurfaceBridge {
    pub hwnd: usize,
    pub native_window_id: u64,
    pub backend: SurfaceBackend,
}

pub fn bridge_hwnd_to_surface(
    hwnd: usize,
    backend: SurfaceBackend,
) -> Result<VulkanSurfaceBridge, String> {
    if !user32::window_exists(hwnd) {
        return Err(format!("invalid hwnd: 0x{hwnd:x}"));
    }

    let native_window_id = user32::ensure_native_window_id(hwnd)
        .ok_or_else(|| format!("failed to allocate native window for hwnd: 0x{hwnd:x}"))?;

    Ok(VulkanSurfaceBridge { hwnd, native_window_id, backend })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use crate::win32::user32::{window, WndClassA};

    #[test]
    fn bridges_hwnd_to_surface_descriptor() {
        let _guard = serial_guard();

        let class_name = std::ffi::CString::new("DxvkBridgeClass").expect("class name");
        let title = std::ffi::CString::new("DxvkBridgeWindow").expect("window title");

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

        assert_ne!(window::RegisterClassA(&raw const wnd_class), 0);
        let hwnd = window::CreateWindowExA(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            10,
            10,
            320,
            240,
            0,
            0,
            0,
            std::ptr::null(),
        );
        assert_ne!(hwnd, 0);

        let bridge = bridge_hwnd_to_surface(hwnd, SurfaceBackend::X11)
            .expect("expected valid surface bridge for hwnd");
        assert_eq!(bridge.hwnd, hwnd);
        assert_ne!(bridge.native_window_id, 0);

        assert_eq!(window::DestroyWindow(hwnd), 1);
    }
}
