//! DXVK integration helpers for Phase 8.

pub mod bridge;
pub mod build;
pub mod runtime;
pub mod shim;

#[cfg(test)]
mod tests {
    use super::build::{required_output_libraries, DxvkBuildConfig};

    #[test]
    fn required_outputs_include_core_dxvk_libraries() {
        let outputs = required_output_libraries();
        assert!(outputs.contains(&"libdxvk_d3d11.so.0"));
        assert!(outputs.contains(&"libdxvk_dxgi.so.0"));
    }

    #[test]
    fn build_config_default_uses_release() {
        let cfg = DxvkBuildConfig::default();
        assert_eq!(cfg.build_type, "release");
    }
}
