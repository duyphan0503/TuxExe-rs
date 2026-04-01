use std::collections::HashMap;

use crate::dll_manager::resolve_reimplemented_export;

const REQUIRED_EXPORTS: &[(&str, &str)] = &[
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("user32.dll", "CreateWindowExA"),
    ("user32.dll", "DispatchMessageA"),
    ("user32.dll", "MapVirtualKeyA"),
    ("gdi32.dll", "BeginPaint"),
    ("gdi32.dll", "EndPaint"),
    ("ws2_32.dll", "WSAStartup"),
];

#[derive(Debug, Default)]
pub struct WineApiShimLayer {
    exports: HashMap<String, usize>,
}

impl WineApiShimLayer {
    pub fn required_exports() -> &'static [(&'static str, &'static str)] {
        REQUIRED_EXPORTS
    }

    pub fn build() -> Result<Self, Vec<String>> {
        let mut shim = Self::default();
        let mut missing = Vec::new();

        for (dll, func) in REQUIRED_EXPORTS {
            let addr = resolve_reimplemented_export(dll, func);
            if addr == 0 {
                missing.push(format!("{dll}!{func}"));
                continue;
            }

            shim.exports.insert(format!("{}!{}", dll.to_ascii_lowercase(), func), addr);
        }

        if missing.is_empty() {
            Ok(shim)
        } else {
            Err(missing)
        }
    }

    pub fn resolve(&self, dll_name: &str, func_name: &str) -> Option<usize> {
        self.exports.get(&format!("{}!{}", dll_name.to_ascii_lowercase(), func_name)).copied()
    }

    pub fn len(&self) -> usize {
        self.exports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_exports_list_is_not_empty() {
        assert!(!WineApiShimLayer::required_exports().is_empty());
    }

    #[test]
    fn shim_build_resolves_known_exports() {
        let shim = WineApiShimLayer::build().expect("all required exports should be available");
        assert!(!shim.is_empty());
        assert!(shim.resolve("kernel32.dll", "LoadLibraryA").is_some());
    }
}
