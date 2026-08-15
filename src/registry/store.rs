//! SQLite-backed registry store — RegOpenKeyEx, RegQueryValueEx, RegSetValueEx.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::{params, Connection};

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_QWORD: u32 = 11;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValue {
    pub reg_type: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct RegistryStore {
    conn: Mutex<Connection>,
}

impl RegistryStore {
    pub fn new(db_path: PathBuf) -> Result<Self, RegistryError> {
        let candidates = vec![
            db_path.clone(),
            std::env::temp_dir().join("tuxexe_registry.db"),
            PathBuf::from("/tmp/tuxexe_registry.db"),
            PathBuf::from("file:tuxexe_reg?mode=memory&cache=shared"),
        ];

        for path in candidates {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let conn_res = if path.to_string_lossy().starts_with("file:") {
                Connection::open_with_flags(
                    &path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                        | rusqlite::OpenFlags::SQLITE_OPEN_URI,
                )
            } else {
                Connection::open(&path)
            };

            if let Ok(conn) = conn_res {
                let _ = conn.execute_batch(
                    r#"
                    PRAGMA synchronous = OFF;
                    PRAGMA journal_mode = MEMORY;
                    PRAGMA temp_store = MEMORY;
                    CREATE TABLE IF NOT EXISTS reg (
                        path TEXT NOT NULL COLLATE NOCASE,
                        name TEXT NOT NULL COLLATE NOCASE,
                        type INT NOT NULL,
                        data BLOB NOT NULL,
                        PRIMARY KEY(path, name)
                    );
                    CREATE INDEX IF NOT EXISTS idx_reg_path ON reg(path);
                    "#,
                );
                return Ok(Self { conn: Mutex::new(conn) });
            }
        }

        let in_mem = Connection::open_in_memory()?;
        let _ = in_mem.execute_batch(
            r#"
            PRAGMA synchronous = OFF;
            CREATE TABLE IF NOT EXISTS reg (
                path TEXT NOT NULL COLLATE NOCASE,
                name TEXT NOT NULL COLLATE NOCASE,
                type INT NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY(path, name)
            );
            CREATE INDEX IF NOT EXISTS idx_reg_path ON reg(path);
            "#,
        );
        Ok(Self { conn: Mutex::new(in_mem) })
    }

    /// RegOpenKeyEx-like existence check.
    pub fn open_key_exists(&self, path: &str) -> Result<bool, RegistryError> {
        let path = normalize_path(path);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("SELECT 1 FROM reg WHERE path = ?1 OR path LIKE ?2 LIMIT 1")?;
        let mut rows = stmt.query(params![path, format!("{path}\\%")])?;
        Ok(rows.next()?.is_some())
    }

    /// RegQueryValueExA/W-like read.
    pub fn query_value(
        &self,
        path: &str,
        name: Option<&str>,
    ) -> Result<Option<RegistryValue>, RegistryError> {
        let path = normalize_path(path);
        let name = normalize_name(name);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("SELECT type, data FROM reg WHERE path = ?1 AND name = ?2")?;
        let mut rows = stmt.query(params![path, name])?;
        if let Some(row) = rows.next()? {
            Ok(Some(RegistryValue { reg_type: row.get::<_, i64>(0)? as u32, data: row.get(1)? }))
        } else {
            Ok(None)
        }
    }

    /// RegSetValueExA/W-like upsert.
    pub fn set_value(
        &self,
        path: &str,
        name: Option<&str>,
        reg_type: u32,
        data: &[u8],
    ) -> Result<(), RegistryError> {
        let path = normalize_path(path);
        let name = normalize_name(name);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("INSERT OR REPLACE INTO reg(path, name, type, data) VALUES (?1, ?2, ?3, ?4)")?;
        stmt.execute(params![path, name, reg_type as i64, data])?;
        Ok(())
    }

    /// RegEnumKeyExA/W-like immediate subkey listing.
    pub fn enum_subkeys(&self, path: &str) -> Result<Vec<String>, RegistryError> {
        let path = normalize_path(path);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("SELECT DISTINCT path FROM reg WHERE path LIKE ?1")?;
        let mut rows = stmt.query(params![format!("{path}\\%")])?;

        let mut subkeys = BTreeSet::new();
        while let Some(row) = rows.next()? {
            let full_path: String = row.get(0)?;
            if let Some(tail) = full_path.strip_prefix(&(path.clone() + "\\")) {
                let child = tail.split('\\').next().unwrap_or_default().trim();
                if !child.is_empty() {
                    subkeys.insert(child.to_string());
                }
            }
        }

        Ok(subkeys.into_iter().collect())
    }

    /// RegDeleteKeyA/W-like delete branch.
    pub fn delete_key(&self, path: &str) -> Result<usize, RegistryError> {
        let path = normalize_path(path);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("DELETE FROM reg WHERE path = ?1 OR path LIKE ?2")?;
        let affected = stmt.execute(params![path, format!("{path}\\%")])?;
        Ok(affected)
    }

    /// RegDeleteValueA/W-like value deletion.
    pub fn delete_value(&self, path: &str, name: Option<&str>) -> Result<usize, RegistryError> {
        let path = normalize_path(path);
        let name = normalize_name(name);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("DELETE FROM reg WHERE path = ?1 AND name = ?2")?;
        let affected = stmt.execute(params![path, name])?;
        Ok(affected)
    }

    /// RegDeleteTreeA/W-like recursive key + subkey + values deletion.
    pub fn delete_tree(&self, path: &str) -> Result<usize, RegistryError> {
        self.delete_key(path)
    }

    /// RegEnumValueA/W-like value listing for a specific key.
    pub fn enum_values(&self, path: &str) -> Result<Vec<(String, RegistryValue)>, RegistryError> {
        let path = normalize_path(path);
        let conn = self.conn.lock().expect("registry lock poisoned");
        let mut stmt = conn.prepare_cached("SELECT name, type, data FROM reg WHERE path = ?1 ORDER BY name ASC")?;
        let mut rows = stmt.query(params![path])?;
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let reg_type = row.get::<_, i64>(1)? as u32;
            let data: Vec<u8> = row.get(2)?;
            results.push((name, RegistryValue { reg_type, data }));
        }
        Ok(results)
    }
}

fn normalize_path(path: &str) -> String {
    let p = path.trim().replace('/', "\\");
    let mut out = String::with_capacity(p.len());
    let mut prev_sep = false;

    for ch in p.chars() {
        if ch == '\\' {
            if !prev_sep {
                out.push('\\');
                prev_sep = true;
            }
            continue;
        }
        prev_sep = false;
        out.push(ch);
    }

    let out = out.trim_matches('\\').to_string();
    if let Some((hive, rest)) = out.split_once('\\') {
        format!("{}\\{}", hive.to_ascii_uppercase(), rest)
    } else {
        out.to_ascii_uppercase()
    }
}

fn normalize_name(name: Option<&str>) -> String {
    name.unwrap_or_default().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_store() -> RegistryStore {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("registry.db");
        let _leaked = Box::leak(Box::new(temp));
        RegistryStore::new(db_path).expect("registry store")
    }

    #[test]
    fn set_and_query_value_roundtrip() {
        let store = create_store();
        store
            .set_value(
                r"hklm/software/microsoft/windows nt/currentversion",
                Some("SystemRoot"),
                REG_SZ,
                b"C:\\Windows",
            )
            .expect("set");

        let value = store
            .query_value(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", Some("SystemRoot"))
            .expect("query")
            .expect("value exists");

        assert_eq!(value.reg_type, REG_SZ);
        assert_eq!(value.data, b"C:\\Windows");
    }

    #[test]
    fn open_key_exists_detects_branch() {
        let store = create_store();
        store
            .set_value(r"HKCU\Environment", Some("Path"), REG_SZ, b"C:\\Users\\Tester")
            .expect("set");
        assert!(store.open_key_exists(r"HKCU\Environment").expect("exists"));
        assert!(!store.open_key_exists(r"HKCU\Nope").expect("exists"));
    }

    #[test]
    fn enum_subkeys_returns_unique_children() {
        let store = create_store();
        store
            .set_value(r"HKLM\SOFTWARE\Microsoft", Some("A"), REG_DWORD, &1u32.to_le_bytes())
            .expect("set");
        store
            .set_value(r"HKLM\SOFTWARE\Mozilla", Some("B"), REG_DWORD, &2u32.to_le_bytes())
            .expect("set");
        store
            .set_value(
                r"HKLM\SOFTWARE\Microsoft\Windows",
                Some("C"),
                REG_DWORD,
                &3u32.to_le_bytes(),
            )
            .expect("set");

        let children = store.enum_subkeys(r"HKLM\SOFTWARE").expect("enum");
        assert_eq!(children, vec!["Microsoft".to_string(), "Mozilla".to_string()]);
    }

    #[test]
    fn delete_key_removes_entire_branch() {
        let store = create_store();
        store.set_value(r"HKCR\.exe", Some(""), REG_SZ, b"exefile").expect("set");
        store.set_value(r"HKCR\.exe\OpenWithProgids", Some("exefile"), REG_NONE, b"").expect("set");

        let deleted = store.delete_key(r"HKCR\.exe").expect("delete");
        assert!(deleted >= 2);
        assert!(!store.open_key_exists(r"HKCR\.exe").expect("exists"));
    }
}
