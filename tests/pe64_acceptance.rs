use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};

fn serial_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn tuxexe_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_tuxexe")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/tuxexe"))
}

fn compile_pe64(source: &str, output: &Path, extra: &[&str]) {
    let status = Command::new("x86_64-w64-mingw32-gcc")
        .arg("-o")
        .arg(output)
        .arg(source)
        .arg("-static")
        .args(extra)
        .status()
        .expect("failed to spawn x86_64-w64-mingw32-gcc");
    assert!(status.success(), "failed to compile {source}");
}

fn run(exe: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(tuxexe_bin())
        .arg("--log-level")
        .arg("error")
        .arg("run")
        .arg(exe)
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd)
        .output()
        .expect("failed to run tuxexe")
}

#[test]
fn pe64_threads_and_waits_without_crashing() {
    let _guard = serial_guard();
    let temp = tempfile::tempdir().expect("temp dir");
    let exe = temp.path().join("threads.exe");
    compile_pe64("tests/test_binaries/test_threads_acceptance.c", &exe, &[]);

    let output = run(&exe, temp.path(), &[]);
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("thread=0"), "stdout={stdout}");
    assert!(stdout.contains("wait=0"), "stdout={stdout}");
}

#[test]
fn pe64_file_io_and_case_fold_work() {
    let _guard = serial_guard();
    let temp = tempfile::tempdir().expect("temp dir");
    let exe = temp.path().join("file.exe");
    compile_pe64("tests/test_binaries/test_file_registry.c", &exe, &[]);

    let output = run(&exe, temp.path(), &[]);
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("file=file-ok bytes=7"));
}

#[test]
fn pe64_registry_roundtrip_works() {
    let _guard = serial_guard();
    let temp = tempfile::tempdir().expect("temp dir");
    let exe = temp.path().join("registry.exe");
    compile_pe64("tests/test_binaries/test_registry.c", &exe, &[]);

    let output = run(&exe, temp.path(), &[]);
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("registry=registry-ok"));
}

#[test]
fn pe64_loadlibrary_and_getprocaddress_work() {
    let _guard = serial_guard();
    let temp = tempfile::tempdir().expect("temp dir");
    let plugin = temp.path().join("acceptance_plugin.dll");
    let plugin_status = Command::new("x86_64-w64-mingw32-gcc")
        .args(["-shared", "-o"])
        .arg(&plugin)
        .arg("tests/test_binaries/acceptance_plugin.c")
        .status()
        .expect("failed to spawn x86_64-w64-mingw32-gcc");
    assert!(plugin_status.success(), "failed to compile plugin");

    let exe = temp.path().join("dynamic.exe");
    compile_pe64("tests/test_binaries/test_dynamic_dll.c", &exe, &[]);
    let output = run(&exe, temp.path(), &[]);
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("answer=42"));
}
