use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn serial_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| Mutex::new(())).lock().expect("serial guard mutex poisoned")
}

fn tuxexe_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_tuxexe") {
        return PathBuf::from(path);
    }

    let mut fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fallback.push("target");
    fallback.push("debug");
    fallback.push(if cfg!(windows) { "tuxexe.exe" } else { "tuxexe" });
    fallback
}

fn compile_pe32_hello(output_path: &Path) {
    let status = Command::new("i686-w64-mingw32-gcc")
        .arg("-o")
        .arg(output_path)
        .arg("tests/test_binaries/hello.c")
        .arg("-static")
        .status()
        .expect("failed to spawn i686-w64-mingw32-gcc");

    assert!(status.success(), "failed to compile PE32 hello.exe");
}

fn compile_pe64_hello(output_path: &Path) {
    let status = Command::new("x86_64-w64-mingw32-gcc")
        .arg("-o")
        .arg(output_path)
        .arg("tests/test_binaries/hello.c")
        .arg("-static")
        .status()
        .expect("failed to spawn x86_64-w64-mingw32-gcc");

    assert!(status.success(), "failed to compile PE64 hello.exe");
}

#[test]
fn pe32_info_reports_x86_metadata() {
    let _guard = serial_guard();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let pe32_path = temp_dir.path().join("hello32.exe");
    compile_pe32_hello(&pe32_path);

    let output = Command::new(tuxexe_bin())
        .arg("info")
        .arg(&pe32_path)
        .output()
        .expect("failed to run tuxexe info");

    assert!(
        output.status.success(),
        "tuxexe info failed: stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Machine:      x86 (PE32)"),
        "expected x86 machine in output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("PE64:         false"),
        "expected PE64 false in output, got:\n{stdout}"
    );
}

#[test]
fn pe64_run_hello_world_end_to_end() {
    let _guard = serial_guard();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let pe64_path = temp_dir.path().join("hello64.exe");
    compile_pe64_hello(&pe64_path);

    let output = Command::new(tuxexe_bin())
        .arg("--log-level")
        .arg("error")
        .arg("run")
        .arg(&pe64_path)
        .output()
        .expect("failed to run tuxexe run");

    assert!(
        output.status.success(),
        "tuxexe run failed: stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hello, TuxExe-rs!"), "expected hello output, got:\n{stdout}");
}

#[test]
#[ignore = "Enable when WoW64 runtime supports full PE32 process execution path"]
fn pe32_run_hello_world_end_to_end() {
    let _guard = serial_guard();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let pe32_path = temp_dir.path().join("hello32.exe");
    compile_pe32_hello(&pe32_path);

    let output = Command::new(tuxexe_bin())
        .arg("--log-level")
        .arg("error")
        .arg("run")
        .arg(&pe32_path)
        .output()
        .expect("failed to run tuxexe run");

    assert!(
        output.status.success(),
        "tuxexe run failed: stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hello, TuxExe-rs!"), "expected hello output, got:\n{stdout}");
}
