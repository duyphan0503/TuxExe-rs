//! Compatibility profiles and runtime reporting.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityProfile {
    Default,
    MadIsland,
}

impl CompatibilityProfile {
    pub fn from_cli(raw: Option<&str>) -> Result<Self, String> {
        let Some(value) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(Self::Default);
        };

        if value.eq_ignore_ascii_case("default") {
            Ok(Self::Default)
        } else if value.eq_ignore_ascii_case("mad-island")
            || value.eq_ignore_ascii_case("mad_island")
            || value.eq_ignore_ascii_case("madisland")
        {
            Ok(Self::MadIsland)
        } else {
            Err(format!("unknown compatibility profile '{value}' (supported: default, mad-island)"))
        }
    }

    pub fn as_key(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::MadIsland => "mad-island",
        }
    }
}

impl fmt::Display for CompatibilityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_key())
    }
}

#[derive(Debug, Clone)]
pub struct AppliedCompatibility {
    pub profile: CompatibilityProfile,
    pub env_overrides: Vec<(&'static str, String)>,
}

impl AppliedCompatibility {
    pub fn apply(profile: CompatibilityProfile, trace_api_calls: bool) -> Self {
        let mut env_overrides = Vec::new();

        match profile {
            CompatibilityProfile::Default => {
                env_overrides.push(("TUXEXE_IMPORT_POLICY", "strict-startup".to_string()));
            }
            CompatibilityProfile::MadIsland => {
                // Unity bring-up defaults: strict import policy. Native PE DLL
                // lifecycle callbacks are now enabled by the loader contract.
                env_overrides.push(("TUXEXE_IMPORT_POLICY", "strict-startup".to_string()));
                env_overrides.push(("TUXEXE_COMPAT_PROFILE", "mad-island".to_string()));
                // Keep graphics stack explicit for DX12-first path diagnostics.
                env_overrides.push(("DXVK_LOG_LEVEL", "info".to_string()));
                env_overrides.push(("VKD3D_DEBUG", "warn".to_string()));
            }
        }

        if trace_api_calls {
            env_overrides.push(("RUST_LOG", "trace".to_string()));
            env_overrides.push(("TUXEXE_TRACE_API", "1".to_string()));
        }

        for (key, value) in &env_overrides {
            std::env::set_var(key, value);
        }

        Self { profile, env_overrides }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Success,
    Failure,
    Transferred,
}

impl fmt::Display for RunOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Transferred => write!(f, "transferred"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub exe_path: PathBuf,
    pub profile: CompatibilityProfile,
    pub machine: String,
    pub is_pe64: bool,
    pub outcome: RunOutcome,
    pub reason: String,
    pub elapsed: Duration,
    pub env_overrides: Vec<(&'static str, String)>,
}

impl RunReport {
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("tuxexe compatibility run report\n");
        out.push_str("version: 1\n");
        out.push_str(&format!("exe: {}\n", self.exe_path.display()));
        out.push_str(&format!("profile: {}\n", self.profile));
        out.push_str(&format!("machine: {}\n", self.machine));
        out.push_str(&format!("pe64: {}\n", self.is_pe64));
        out.push_str(&format!("outcome: {}\n", self.outcome));
        out.push_str(&format!("reason: {}\n", self.reason));
        out.push_str(&format!("elapsed_ms: {}\n", self.elapsed.as_millis()));
        out.push_str("env_overrides:\n");
        for (key, value) in &self.env_overrides {
            out.push_str(&format!("  {key}={value}\n"));
        }
        out
    }

    pub fn write_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!("failed to create report directory {}: {err}", parent.display())
            })?;
        }
        std::fs::write(path, self.render_text())
            .map_err(|err| format!("failed to write report {}: {err}", path.display()))
    }
}

#[derive(Debug, Clone)]
pub struct RunSession {
    started_at: Instant,
    exe_path: PathBuf,
    profile: CompatibilityProfile,
    machine: String,
    is_pe64: bool,
    env_overrides: Vec<(&'static str, String)>,
}

impl RunSession {
    pub fn start(
        exe_path: &Path,
        profile: CompatibilityProfile,
        machine: impl Into<String>,
        is_pe64: bool,
        env_overrides: Vec<(&'static str, String)>,
    ) -> Self {
        Self {
            started_at: Instant::now(),
            exe_path: exe_path.to_path_buf(),
            profile,
            machine: machine.into(),
            is_pe64,
            env_overrides,
        }
    }

    pub fn finish(self, outcome: RunOutcome, reason: impl Into<String>) -> RunReport {
        RunReport {
            exe_path: self.exe_path,
            profile: self.profile,
            machine: self.machine,
            is_pe64: self.is_pe64,
            outcome,
            reason: reason.into(),
            elapsed: self.started_at.elapsed(),
            env_overrides: self.env_overrides,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile_aliases() {
        assert_eq!(
            CompatibilityProfile::from_cli(None).expect("default"),
            CompatibilityProfile::Default
        );
        assert_eq!(
            CompatibilityProfile::from_cli(Some("mad_island")).expect("alias"),
            CompatibilityProfile::MadIsland
        );
    }

    #[test]
    fn report_contains_profile_and_reason() {
        let applied = AppliedCompatibility::apply(CompatibilityProfile::MadIsland, false);
        let session = RunSession::start(
            std::path::Path::new("/tmp/game.exe"),
            applied.profile,
            "x86-64 (PE32+)",
            true,
            applied.env_overrides,
        );
        let report = session.finish(RunOutcome::Failure, "missing import");
        let text = report.render_text();
        assert!(text.contains("profile: mad-island"));
        assert!(text.contains("reason: missing import"));
    }
}
