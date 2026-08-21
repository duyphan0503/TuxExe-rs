use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn serial_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    match GUARD.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
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

fn prepend_path_with(dir: &Path) -> String {
    let original = std::env::var("PATH").unwrap_or_default();
    if original.is_empty() {
        dir.display().to_string()
    } else {
        format!("{}:{original}", dir.display())
    }
}

#[cfg(unix)]
fn create_fake_wine_binary(dir: &Path) -> PathBuf {
    let marker = dir.join("wine-invoked.marker");
    let fake_wine = dir.join("wine");

    let script = format!("#!/bin/sh\necho invoked > '{}'\nexit 97\n", marker.display());
    std::fs::write(&fake_wine, script).expect("write fake wine binary");

    let mut perms = std::fs::metadata(&fake_wine).expect("stat fake wine").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_wine, perms).expect("chmod fake wine");

    marker
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
fn pe64_run_resolves_relative_exe_before_switching_to_its_directory() {
    let _guard = serial_guard();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let game_dir = temp_dir.path().join("game");
    std::fs::create_dir(&game_dir).expect("create game dir");
    let pe64_path = game_dir.join("hello64.exe");
    compile_pe64_hello(&pe64_path);

    let output = Command::new(tuxexe_bin())
        .arg("--log-level")
        .arg("error")
        .arg("run")
        .arg(Path::new("game").join("hello64.exe"))
        .current_dir(temp_dir.path())
        .output()
        .expect("failed to run tuxexe run with relative executable path");

    assert!(
        output.status.success(),
        "relative tuxexe run failed: stdout=\n{}\nstderr=\n{}",
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

#[test]
fn pe32_run_fails_with_controlled_native_only_error() {
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
        !output.status.success(),
        "expected controlled failure while WoW64 entry transition is missing"
    );

    assert_ne!(output.status.code(), Some(139), "must not segfault (exit 139)");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Native PE32 execution is not available yet"),
        "expected clear native-only error in stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("trampoline dispatcher"),
        "expected WoW64 transition detail in stderr, got:\n{stderr}"
    );
}

#[test]
#[cfg(unix)]
fn pe32_run_never_spawns_wine_even_with_legacy_backend_env() {
    let _guard = serial_guard();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let pe32_path = temp_dir.path().join("hello32.exe");
    compile_pe32_hello(&pe32_path);

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    let marker = create_fake_wine_binary(&fake_bin_dir);

    let output = Command::new(tuxexe_bin())
        .arg("--log-level")
        .arg("warn")
        .arg("run")
        .arg(&pe32_path)
        .env("PATH", prepend_path_with(&fake_bin_dir))
        .env("TUXEXE_X86_BACKEND", "wine")
        .output()
        .expect("failed to run tuxexe run");

    assert!(
        !output.status.success(),
        "expected PE32 run to fail until x86 transition is implemented"
    );
    assert!(
        !marker.exists(),
        "detected fake wine invocation marker; runtime must never spawn wine"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deprecated TUXEXE_X86_BACKEND='wine'"),
        "expected legacy backend warning in stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Native PE32 execution is not available yet"),
        "expected native-only PE32 transition error in stderr, got:\n{stderr}"
    );
}

#[test]
fn audit_reports_import_coverage_for_pe64() {
    let _guard = serial_guard();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let pe64_path = temp_dir.path().join("hello64.exe");
    compile_pe64_hello(&pe64_path);

    let output = Command::new(tuxexe_bin())
        .arg("audit")
        .arg(&pe64_path)
        .output()
        .expect("failed to run tuxexe audit");

    assert!(
        output.status.success(),
        "tuxexe audit failed: stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compatibility Audit:"), "expected audit header, got:\n{stdout}");
    assert!(stdout.contains("By DLL:"), "expected DLL coverage section, got:\n{stdout}");
}
