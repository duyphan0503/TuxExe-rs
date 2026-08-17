//! Loader for a bundled DXVK Native build compiled with TuxExe's Win64 ABI.
//!
//! Stock DXVK Native uses the System V ABI and must never be passed to a PE
//! guest. A packaged TuxExe runtime is discovered automatically. An arbitrary
//! `TUXEXE_DXVK_DIR` override requires the `TUXEXE_DXVK_MSABI=1`
//! acknowledgement, so a stock DXVK build is not accidentally loaded.

use std::{
    env,
    ffi::CString,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use tracing::{info, warn};

#[derive(Clone, Copy)]
pub enum Library {
    D3d11,
    Dxgi,
}

struct Runtime {
    d3d11: *mut libc::c_void,
    dxgi: *mut libc::c_void,
}

// dlopen handles are process-lifetime resources and `dlsym` is thread-safe.
unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();

fn library_candidates(library: Library) -> &'static [&'static str] {
    match library {
        // Keep the ABI-stable SONAME first. The full version is intentionally
        // not hard-coded: a packaged fork can be upgraded without a Rust
        // loader change.
        Library::D3d11 => &["libdxvk_d3d11.so.0", "libdxvk_d3d11.so"],
        Library::Dxgi => &["libdxvk_dxgi.so.0", "libdxvk_dxgi.so"],
    }
}

fn library_path(directory: &Path, library: Library) -> Option<PathBuf> {
    let build_subdirectory = match library {
        Library::D3d11 => "d3d11",
        Library::Dxgi => "dxgi",
    };
    // The first two entries support a Meson build tree. The latter two are
    // the portable runtime layout produced by `dxvk::build`: the libraries
    // are installed under `runtime/dxvk/lib`.
    [
        directory.join(build_subdirectory),
        directory.to_path_buf(),
        directory.join("lib"),
        directory.join("lib").join("x86_64-linux-gnu"),
    ]
    .into_iter()
    .flat_map(|base| library_candidates(library).iter().map(move |name| base.join(name)))
    .find(|path| path.is_file())
}

fn default_directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();

    if let Ok(executable) = env::current_exe() {
        if let Some(binary_dir) = executable.parent() {
            // Portable archive: bin/tuxexe and bin/dxvk/…
            directories.push(binary_dir.join("dxvk"));
            // Conventional Linux archive: bin/tuxexe and lib/tuxexe/dxvk/…
            directories.push(binary_dir.join("..").join("lib").join("tuxexe").join("dxvk"));
        }
    }

    // Allows `cargo run` and an unpacked source tree to use the same runtime
    // layout as a release archive, without an absolute /tmp path.
    directories.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("runtime").join("dxvk"));
    directories
}

fn packaged_runtime_directory() -> Option<PathBuf> {
    default_directories().into_iter().find(|directory| {
        library_path(directory, Library::Dxgi).is_some()
            && library_path(directory, Library::D3d11).is_some()
    })
}

unsafe fn open(path: &Path) -> Option<*mut libc::c_void> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
    (!handle.is_null()).then_some(handle)
}

fn load() -> Option<Runtime> {
    // A runtime located in one of TuxExe's own package directories is part of
    // this release and is therefore known to have been built with the MS-ABI
    // patch.  An arbitrary directory override remains opt-in, because stock
    // DXVK Native is SysV ABI and unsafe for PE callers.
    let directory = if let Some(directory) = env::var_os("TUXEXE_DXVK_DIR") {
        if env::var_os("TUXEXE_DXVK_MSABI").as_deref() != Some(std::ffi::OsStr::new("1")) {
            warn!("ignoring TUXEXE_DXVK_DIR without TUXEXE_DXVK_MSABI=1");
            return None;
        }
        PathBuf::from(directory)
    } else {
        packaged_runtime_directory()?
    };
    let dxgi_path = library_path(&directory, Library::Dxgi)?;
    let d3d11_path = library_path(&directory, Library::D3d11)?;

    // The bundled fork includes TuxExe's X11 WSI implementation. DXVK reads
    // this setting while creating its first factory, so establish the default
    // before either library is loaded. Preserve an explicit user choice for
    // diagnostics or future alternate backends.
    if env::var_os("DXVK_WSI_DRIVER").is_none() {
        unsafe { env::set_var("DXVK_WSI_DRIVER", "TUXEXE") };
    }
    if env::var_os("DXVK_FRAME_RATE").is_none() {
        unsafe { env::set_var("DXVK_FRAME_RATE", "60") };
    }

    // DXGI is loaded first so D3D11's DT_NEEDED soname is already available.
    let dxgi = unsafe { open(&dxgi_path) }?;
    let d3d11 = unsafe { open(&d3d11_path) }?;
    info!(directory = %directory.display(), "loaded TuxExe MS-ABI DXVK runtime");
    Some(Runtime { d3d11, dxgi })
}

fn runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_init(load).as_ref()
}

/// Resolves an export only from an explicitly enabled TuxExe MS-ABI DXVK build.
pub fn export(library: Library, name: &str) -> Option<usize> {
    let runtime = runtime()?;
    let symbol = CString::new(name).ok()?;
    let handle = match library {
        Library::D3d11 => runtime.d3d11,
        Library::Dxgi => runtime.dxgi,
    };
    let address = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    if address.is_null() {
        warn!(%name, "TuxExe DXVK runtime has no requested export");
        None
    } else {
        Some(address as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_dxvk_native_library_names() {
        assert!(library_candidates(Library::D3d11).contains(&"libdxvk_d3d11.so.0"));
        assert!(library_candidates(Library::Dxgi).contains(&"libdxvk_dxgi.so.0"));
    }

    #[test]
    fn locates_a_library_in_the_meson_build_layout() {
        let temp = tempfile::tempdir().unwrap();
        let nested = temp.path().join("d3d11");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("libdxvk_d3d11.so.0"), []).unwrap();
        assert!(library_path(temp.path(), Library::D3d11).is_some());
    }

    #[test]
    fn locates_a_library_in_the_packaged_runtime_layout() {
        let temp = tempfile::tempdir().unwrap();
        let lib = temp.path().join("lib");
        std::fs::create_dir(&lib).unwrap();
        std::fs::write(lib.join("libdxvk_dxgi.so.0"), []).unwrap();
        assert!(library_path(temp.path(), Library::Dxgi).is_some());
    }
}
