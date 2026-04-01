//! Minimal registry defaults — SystemRoot, ComSpec, CurrentVersion, Environment.

use crate::registry::store::{RegistryError, RegistryStore, REG_SZ};

/// Seed the minimal Windows-like registry keys needed by early-phase binaries.
///
/// Idempotent: can be called multiple times safely.
pub fn seed_minimal_defaults(store: &RegistryStore) -> Result<(), RegistryError> {
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (SystemRoot, etc.)
    let current_version = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    set_sz(store, current_version, Some("SystemRoot"), r"C:\Windows")?;
    set_sz(store, current_version, Some("CurrentVersion"), "10.0")?;
    set_sz(store, current_version, Some("CurrentBuild"), "19045")?;
    set_sz(store, current_version, Some("ProductName"), "Windows 10 Pro")?;
    set_sz(store, current_version, Some("ProgramFilesDir"), r"C:\Program Files")?;
    set_sz(store, current_version, Some("ProgramFilesDir (x86)"), r"C:\Program Files (x86)")?;

    // HKLM\...\Environment-style ComSpec for command invocation defaults.
    let session_env = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    set_sz(store, session_env, Some("ComSpec"), r"C:\Windows\System32\cmd.exe")?;
    set_sz(store, session_env, Some("Path"), r"C:\Windows\System32;C:\Windows")?;

    // HKCU\Environment
    let user_env = r"HKCU\Environment";
    set_sz(store, user_env, Some("TEMP"), r"C:\Users\User\AppData\Local\Temp")?;
    set_sz(store, user_env, Some("TMP"), r"C:\Users\User\AppData\Local\Temp")?;
    set_sz(store, user_env, Some("USERPROFILE"), r"C:\Users\User")?;
    set_sz(store, user_env, Some("APPDATA"), r"C:\Users\User\AppData\Roaming")?;

    // HKCR\.exe → exefile
    set_sz(store, r"HKCR\.exe", Some(""), "exefile")?;

    Ok(())
}

fn set_sz(
    store: &RegistryStore,
    path: &str,
    name: Option<&str>,
    value: &str,
) -> Result<(), RegistryError> {
    store.set_value(path, name, REG_SZ, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::store::RegistryValue;

    fn create_store() -> RegistryStore {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("registry-defaults.db");
        let _leaked = Box::leak(Box::new(temp));
        RegistryStore::new(db_path).expect("registry store")
    }

    fn read_sz(store: &RegistryStore, path: &str, name: Option<&str>) -> RegistryValue {
        store.query_value(path, name).expect("query value").expect("value exists")
    }

    #[test]
    fn seeds_required_defaults() {
        let store = create_store();
        seed_minimal_defaults(&store).expect("seed defaults");

        let system_root = read_sz(
            &store,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            Some("SystemRoot"),
        );
        assert_eq!(system_root.data, b"C:\\Windows");

        let appdata = read_sz(&store, r"HKCU\Environment", Some("APPDATA"));
        assert_eq!(appdata.data, b"C:\\Users\\User\\AppData\\Roaming");

        let exe_assoc = read_sz(&store, r"HKCR\.exe", Some(""));
        assert_eq!(exe_assoc.data, b"exefile");
    }

    #[test]
    fn seeding_is_idempotent() {
        let store = create_store();
        seed_minimal_defaults(&store).expect("first seed");
        seed_minimal_defaults(&store).expect("second seed");

        assert!(store
            .open_key_exists(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .expect("exists"));
        assert!(store.open_key_exists(r"HKCU\Environment").expect("exists"));
        assert!(store.open_key_exists(r"HKCR\.exe").expect("exists"));
    }
}
