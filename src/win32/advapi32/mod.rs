//! advapi32.dll reimplementation — registry, security, crypto.

pub mod registry;

use std::collections::HashMap;

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    // Registry APIs
    exports.insert("RegOpenKeyExA", registry::RegOpenKeyExA as usize);
    exports.insert("RegOpenKeyExW", registry::RegOpenKeyExW as usize);
    exports.insert("RegCloseKey", registry::RegCloseKey as usize);
    exports.insert("RegQueryValueExA", registry::RegQueryValueExA as usize);
    exports.insert("RegQueryValueExW", registry::RegQueryValueExW as usize);
    exports.insert("RegSetValueExA", registry::RegSetValueExA as usize);
    exports.insert("RegSetValueExW", registry::RegSetValueExW as usize);
    exports.insert("RegCreateKeyExA", registry::RegCreateKeyExA as usize);
    exports.insert("RegCreateKeyExW", registry::RegCreateKeyExW as usize);
    exports.insert("RegDeleteKeyA", registry::RegDeleteKeyA as usize);
    exports.insert("RegDeleteKeyW", registry::RegDeleteKeyW as usize);
    exports.insert("RegEnumKeyExA", registry::RegEnumKeyExA as usize);
    exports.insert("RegEnumKeyExW", registry::RegEnumKeyExW as usize);

    exports
}
