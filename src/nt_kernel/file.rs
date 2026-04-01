#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! NtCreateFile, NtReadFile, NtWriteFile, NtClose → open/read/write/close.

use crate::filesystem::{
    case_fold::resolve_case_insensitive,
    drives::DriveMap,
    path::{windows_to_host, SpecialFolders},
};
use crate::utils::handle::{global_table, init_global_table, Handle, HandleObject, StdioHandle};
use std::{ffi::c_void, path::PathBuf};

pub type NtStatus = u32;

pub const STATUS_SUCCESS: NtStatus = 0x00000000;
pub const STATUS_INVALID_HANDLE: NtStatus = 0xC0000008;
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC0000001;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000003A;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC0000034;
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC0000035;
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC0000022;
pub const STATUS_NOT_A_DIRECTORY: NtStatus = 0xC0000103;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000000D;

#[derive(Debug, Clone, Copy)]
pub enum CreateDisposition {
    CreateNew,
    CreateAlways,
    OpenExisting,
    OpenAlways,
    TruncateExisting,
}

#[derive(Debug, Clone)]
pub struct FileInformation {
    pub file_size: u64,
    pub is_directory: bool,
    pub last_access_time_unix: i64,
    pub last_write_time_unix: i64,
}

#[derive(Debug, Clone)]
pub enum SetFileInformation {
    SetEndOfFile(u64),
    Rename { new_windows_path: String, replace_if_exists: bool },
}

#[derive(Debug, Clone)]
pub struct DirectoryEntryInfo {
    pub file_name: String,
    pub is_directory: bool,
    pub file_size: u64,
}

#[derive(Debug)]
pub struct FileHandle {
    pub fd: i32,
    pub host_path: PathBuf,
}

impl HandleObject for FileHandle {
    fn type_name(&self) -> &'static str {
        "FileHandle"
    }

    fn close(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn errno_to_status(errno: i32) -> NtStatus {
    match errno {
        libc::ENOENT => STATUS_OBJECT_NAME_NOT_FOUND,
        libc::ENOTDIR => STATUS_NOT_A_DIRECTORY,
        libc::EACCES | libc::EPERM => STATUS_ACCESS_DENIED,
        libc::EEXIST => STATUS_OBJECT_NAME_COLLISION,
        _ => STATUS_UNSUCCESSFUL,
    }
}

fn default_drives_and_folders() -> (DriveMap, SpecialFolders) {
    (DriveMap::default(), SpecialFolders::from_host_env())
}

fn resolve_windows_path(windows_path: &str, create: bool) -> Result<PathBuf, NtStatus> {
    let (drives, special) = default_drives_and_folders();
    let translated =
        windows_to_host(windows_path, &drives, &special).map_err(|_| STATUS_INVALID_PARAMETER)?;

    if create {
        return Ok(translated);
    }

    if translated.exists() {
        return Ok(translated);
    }

    resolve_case_insensitive(&translated).ok_or(STATUS_OBJECT_PATH_NOT_FOUND)
}

fn open_flags(read: bool, write: bool, disposition: CreateDisposition) -> i32 {
    let mut flags = match (read, write) {
        (true, true) => libc::O_RDWR,
        (false, true) => libc::O_WRONLY,
        _ => libc::O_RDONLY,
    };

    flags |= match disposition {
        CreateDisposition::CreateNew => libc::O_CREAT | libc::O_EXCL,
        CreateDisposition::CreateAlways => libc::O_CREAT | libc::O_TRUNC,
        CreateDisposition::OpenExisting => 0,
        CreateDisposition::OpenAlways => libc::O_CREAT,
        CreateDisposition::TruncateExisting => libc::O_TRUNC,
    };

    flags
}

pub fn nt_create_file(
    windows_path: &str,
    read: bool,
    write: bool,
    disposition: CreateDisposition,
) -> Result<Handle, NtStatus> {
    init_global_table();
    let requires_create = matches!(
        disposition,
        CreateDisposition::CreateNew
            | CreateDisposition::CreateAlways
            | CreateDisposition::OpenAlways
    );
    let host_path = resolve_windows_path(windows_path, requires_create)?;
    let flags = open_flags(read, write, disposition);
    let mode = 0o644;

    let c_path = std::ffi::CString::new(host_path.to_string_lossy().as_bytes())
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(errno_to_status(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
    }

    let handle = global_table().alloc(Box::new(FileHandle { fd, host_path }));
    Ok(handle)
}

pub fn nt_query_information_file(handle: Handle) -> Result<FileInformation, NtStatus> {
    init_global_table();
    let mut out = None;

    global_table().with(handle, |obj| {
        if let Some(file) = obj.as_any().downcast_ref::<FileHandle>() {
            let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(file.fd, &mut stat_buf) };
            if rc == 0 {
                out = Some(Ok(FileInformation {
                    file_size: stat_buf.st_size as u64,
                    is_directory: (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR,
                    last_access_time_unix: stat_buf.st_atime,
                    last_write_time_unix: stat_buf.st_mtime,
                }));
            } else {
                let status =
                    errno_to_status(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
                out = Some(Err(status));
            }
        } else {
            out = Some(Err(STATUS_INVALID_HANDLE));
        }
    });

    out.unwrap_or(Err(STATUS_INVALID_HANDLE))
}

pub fn nt_query_information_by_path(windows_path: &str) -> Result<FileInformation, NtStatus> {
    let host_path = resolve_windows_path(windows_path, false)?;
    let metadata = std::fs::metadata(&host_path)
        .map_err(|e| errno_to_status(e.raw_os_error().unwrap_or(libc::ENOENT)))?;

    let accessed = metadata.accessed().ok();
    let modified = metadata.modified().ok();
    let to_unix = |time: Option<std::time::SystemTime>| -> i64 {
        time.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };

    Ok(FileInformation {
        file_size: metadata.len(),
        is_directory: metadata.is_dir(),
        last_access_time_unix: to_unix(accessed),
        last_write_time_unix: to_unix(modified),
    })
}

pub fn nt_set_file_pointer_ex(
    handle: Handle,
    distance_to_move: i64,
    move_method: u32,
) -> Result<u64, NtStatus> {
    init_global_table();
    let mut out = Err(STATUS_INVALID_HANDLE);

    global_table().with(handle, |obj| {
        let fd = obj
            .as_any()
            .downcast_ref::<StdioHandle>()
            .map(|h| h.fd)
            .or_else(|| obj.as_any().downcast_ref::<FileHandle>().map(|h| h.fd));

        out = if let Some(fd) = fd {
            let whence = match move_method {
                0 => libc::SEEK_SET,
                1 => libc::SEEK_CUR,
                2 => libc::SEEK_END,
                _ => return (out = Err(STATUS_INVALID_PARAMETER)),
            };
            let offset = unsafe { libc::lseek(fd, distance_to_move as libc::off_t, whence) };
            if offset < 0 {
                Err(errno_to_status(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)))
            } else {
                Ok(offset as u64)
            }
        } else {
            Err(STATUS_INVALID_HANDLE)
        };
    });

    out
}

pub fn nt_set_information_file(handle: Handle, update: SetFileInformation) -> NtStatus {
    init_global_table();
    let mut out = STATUS_INVALID_HANDLE;

    global_table().with(handle, |obj| {
        if let Some(file) = obj.as_any().downcast_ref::<FileHandle>() {
            out = match &update {
                SetFileInformation::SetEndOfFile(len) => {
                    let rc = unsafe { libc::ftruncate(file.fd, *len as libc::off_t) };
                    if rc == 0 {
                        STATUS_SUCCESS
                    } else {
                        errno_to_status(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
                    }
                }
                SetFileInformation::Rename { new_windows_path, replace_if_exists } => {
                    let new_host = match resolve_windows_path(new_windows_path, true) {
                        Ok(path) => path,
                        Err(status) => return (out = status),
                    };

                    if !replace_if_exists && new_host.exists() {
                        STATUS_OBJECT_NAME_COLLISION
                    } else {
                        match std::fs::rename(&file.host_path, &new_host) {
                            Ok(_) => STATUS_SUCCESS,
                            Err(err) => errno_to_status(err.raw_os_error().unwrap_or(0)),
                        }
                    }
                }
            };
        } else {
            out = STATUS_INVALID_HANDLE;
        }
    });

    out
}

pub fn nt_query_directory_file(handle: Handle) -> Result<Vec<DirectoryEntryInfo>, NtStatus> {
    init_global_table();
    let mut out = None;

    global_table().with(handle, |obj| {
        if let Some(file) = obj.as_any().downcast_ref::<FileHandle>() {
            match std::fs::read_dir(&file.host_path) {
                Ok(iter) => {
                    let mut entries = Vec::new();
                    for entry in iter.flatten() {
                        if let Ok(metadata) = entry.metadata() {
                            entries.push(DirectoryEntryInfo {
                                file_name: entry.file_name().to_string_lossy().to_string(),
                                is_directory: metadata.is_dir(),
                                file_size: metadata.len(),
                            });
                        }
                    }
                    out = Some(Ok(entries));
                }
                Err(err) => {
                    let status = errno_to_status(err.raw_os_error().unwrap_or(0));
                    out = Some(Err(status));
                }
            }
        } else {
            out = Some(Err(STATUS_INVALID_HANDLE));
        }
    });

    out.unwrap_or(Err(STATUS_INVALID_HANDLE))
}

/// Thin wrapper for NtWriteFile, simplified for now.
pub fn nt_write_file(
    handle: Handle,
    buffer: *const c_void,
    length: u32,
    bytes_written: Option<&mut u32>,
) -> NtStatus {
    init_global_table();
    let mut status = STATUS_INVALID_HANDLE;

    global_table().with(handle, |obj| {
        let fd = obj
            .as_any()
            .downcast_ref::<StdioHandle>()
            .map(|h| h.fd)
            .or_else(|| obj.as_any().downcast_ref::<FileHandle>().map(|h| h.fd));

        if let Some(fd) = fd {
            let written = unsafe { libc::write(fd, buffer, length as libc::size_t) };
            if written >= 0 {
                if let Some(bw) = bytes_written {
                    *bw = written as u32;
                }
                status = STATUS_SUCCESS;
            } else {
                status =
                    errno_to_status(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
            }
        }
    });

    status
}

/// Thin wrapper for NtReadFile, simplified for now.
pub fn nt_read_file(
    handle: Handle,
    buffer: *mut c_void,
    length: u32,
    bytes_read: Option<&mut u32>,
) -> NtStatus {
    init_global_table();
    let mut status = STATUS_INVALID_HANDLE;

    global_table().with(handle, |obj| {
        let fd = obj
            .as_any()
            .downcast_ref::<StdioHandle>()
            .map(|h| h.fd)
            .or_else(|| obj.as_any().downcast_ref::<FileHandle>().map(|h| h.fd));

        if let Some(fd) = fd {
            let read_sz = unsafe { libc::read(fd, buffer, length as libc::size_t) };
            if read_sz >= 0 {
                if let Some(br) = bytes_read {
                    *br = read_sz as u32;
                }
                status = STATUS_SUCCESS;
            } else {
                status =
                    errno_to_status(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
            }
        }
    });

    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use std::io::Read;

    #[test]
    fn create_write_read_and_query_file() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("sample.txt");
        let file_path = file_path.to_string_lossy().to_string();

        let handle = nt_create_file(&file_path, true, true, CreateDisposition::CreateAlways)
            .expect("create file");

        let payload = b"hello-nt";
        let mut written = 0;
        assert_eq!(
            nt_write_file(
                handle,
                payload.as_ptr() as *const c_void,
                payload.len() as u32,
                Some(&mut written),
            ),
            STATUS_SUCCESS
        );
        assert_eq!(written as usize, payload.len());

        let info = nt_query_information_file(handle).expect("query file info");
        assert!(!info.is_directory);
        assert_eq!(info.file_size, payload.len() as u64);

        let host_content = {
            let mut s = String::new();
            std::fs::File::open(temp.path().join("sample.txt"))
                .expect("open host file")
                .read_to_string(&mut s)
                .expect("read host file");
            s
        };
        assert_eq!(host_content, "hello-nt");
    }

    #[test]
    fn truncate_and_rename_file() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("old.txt"), b"abcdefgh").expect("seed");
        let old_path = temp.path().join("old.txt").to_string_lossy().to_string();
        let new_path = temp.path().join("new.txt").to_string_lossy().to_string();

        let handle = nt_create_file(&old_path, true, true, CreateDisposition::OpenExisting)
            .expect("open file");
        assert_eq!(
            nt_set_information_file(handle, SetFileInformation::SetEndOfFile(3)),
            STATUS_SUCCESS
        );
        assert_eq!(std::fs::metadata(temp.path().join("old.txt")).expect("meta").len(), 3);

        assert_eq!(
            nt_set_information_file(
                handle,
                SetFileInformation::Rename { new_windows_path: new_path, replace_if_exists: true }
            ),
            STATUS_SUCCESS
        );
        assert!(!temp.path().join("old.txt").exists());
        assert!(temp.path().join("new.txt").exists());
    }

    #[test]
    fn query_directory_entries() {
        let _guard = serial_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let dir_path = temp.path().join("dir");
        std::fs::create_dir_all(&dir_path).expect("mkdir");
        std::fs::write(dir_path.join("a.txt"), b"a").expect("write a");
        std::fs::write(dir_path.join("b.txt"), b"b").expect("write b");
        let dir_path = dir_path.to_string_lossy().to_string();

        let handle = nt_create_file(&dir_path, true, false, CreateDisposition::OpenExisting)
            .expect("open dir");
        let entries = nt_query_directory_file(handle).expect("query dir");
        let mut names: Vec<_> = entries.into_iter().map(|e| e.file_name).collect();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }
}
