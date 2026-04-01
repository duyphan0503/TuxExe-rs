use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DxvkBuildConfig {
    pub source_dir: PathBuf,
    pub build_dir: PathBuf,
    pub install_dir: PathBuf,
    pub build_type: String,
    pub target_cpu_family: String,
}

impl Default for DxvkBuildConfig {
    fn default() -> Self {
        Self {
            source_dir: PathBuf::from("external/dxvk"),
            build_dir: PathBuf::from("build/dxvk"),
            install_dir: PathBuf::from("build/dxvk-install"),
            build_type: "release".to_string(),
            target_cpu_family: "x86_64".to_string(),
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
    vec!["d3d9.dll.so", "d3d10core.dll.so", "d3d11.dll.so", "dxgi.dll.so"]
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
                format!("-Dcpu_family={}", config.target_cpu_family),
                "-Denable_tests=false".to_string(),
                format!("--prefix={install_dir}"),
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
        let proton_style = install_dir.join("x64").join(library);
        if !unix_style.exists() && !proton_style.exists() {
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
    }

    #[test]
    fn validate_install_tree_reports_missing_libs_in_empty_dir() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let missing = validate_install_tree(temp_dir.path());
        assert_eq!(missing.len(), required_output_libraries().len());
    }
}
