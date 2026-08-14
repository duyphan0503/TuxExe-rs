use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DxvkBuildConfig {
    pub source_dir: PathBuf,
    pub build_dir: PathBuf,
    pub install_dir: PathBuf,
    pub build_type: String,
}

impl Default for DxvkBuildConfig {
    fn default() -> Self {
        Self {
            source_dir: PathBuf::from("external/dxvk"),
            build_dir: PathBuf::from("build/dxvk"),
            // This is the tree shipped next to TuxExe. It deliberately does
            // not use /tmp, which made the renderer disappear after a reboot
            // or on a different machine.
            install_dir: PathBuf::from("runtime/dxvk"),
            build_type: "release".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildStep {
    pub program: String,
    pub args: Vec<String>,
}

impl BuildStep {
    pub fn render(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

pub fn required_output_libraries() -> Vec<&'static str> {
    vec!["libdxvk_d3d11.so.0", "libdxvk_dxgi.so.0"]
}

pub fn plan_build_steps(config: &DxvkBuildConfig) -> Vec<BuildStep> {
    let build_dir = config.build_dir.display().to_string();
    let source_dir = config.source_dir.display().to_string();
    let install_dir = config.install_dir.display().to_string();

    vec![
        BuildStep {
            program: "meson".to_string(),
            args: vec![
                "setup".to_string(),
                build_dir,
                source_dir,
                format!("--buildtype={}", config.build_type),
                // Only the MS-ABI TuxExe WSI build is valid for PE callers.
                // Stock DXVK Native uses the host SysV ABI and is unsafe here.
                "-Dnative_tuxexe=enabled".to_string(),
                "-Dnative_glfw=disabled".to_string(),
                "-Dnative_sdl2=disabled".to_string(),
                "-Dnative_sdl3=disabled".to_string(),
                "-Denable_d3d8=false".to_string(),
                "-Denable_d3d9=false".to_string(),
                "-Denable_d3d10=false".to_string(),
                "-Denable_d3d11=true".to_string(),
                "-Denable_dxgi=true".to_string(),
                // Install into a relocatable DESTDIR tree. `--libdir=lib`
                // gives the runtime loader one stable lookup location across
                // distributions.
                "--prefix=/".to_string(),
                "--libdir=lib".to_string(),
            ],
        },
        BuildStep {
            program: "ninja".to_string(),
            args: vec!["-C".to_string(), config.build_dir.display().to_string()],
        },
        BuildStep {
            program: "meson".to_string(),
            args: vec![
                "install".to_string(),
                "-C".to_string(),
                config.build_dir.display().to_string(),
                "--destdir".to_string(),
                install_dir,
            ],
        },
    ]
}

pub fn run_build_steps(steps: &[BuildStep]) -> Result<(), String> {
    for step in steps {
        let status = Command::new(&step.program)
            .args(&step.args)
            .status()
            .map_err(|err| format!("failed to execute '{}': {err}", step.render()))?;

        if !status.success() {
            return Err(format!("command '{}' exited with status {status}", step.render()));
        }
    }

    Ok(())
}

pub fn validate_install_tree(install_dir: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();

    for library in required_output_libraries() {
        let unix_style = install_dir.join("lib").join(library);
        let multiarch_style = install_dir.join("lib").join("x86_64-linux-gnu").join(library);
        if !unix_style.exists() && !multiarch_style.exists() {
            missing.push(PathBuf::from(library));
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_plan_contains_meson_and_ninja_steps() {
        let cfg = DxvkBuildConfig::default();
        let steps = plan_build_steps(&cfg);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].program, "meson");
        assert_eq!(steps[1].program, "ninja");
        assert_eq!(steps[2].program, "meson");
        assert!(steps[0].args.contains(&"-Dnative_tuxexe=enabled".to_string()));
        assert!(steps[2].args.contains(&"--destdir".to_string()));
    }

    #[test]
    fn validate_install_tree_reports_missing_libs_in_empty_dir() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let missing = validate_install_tree(temp_dir.path());
        assert_eq!(missing.len(), required_output_libraries().len());
    }
}
