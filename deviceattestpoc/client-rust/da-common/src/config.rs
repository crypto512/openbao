//! Configuration helpers for device attestation tools.

use std::env;

/// Default path for da.json configuration file
pub const DEFAULT_DA_JSON_PATH: &str = "/etc/da/da.json";

/// Default TPM device path
pub const DEFAULT_TPM_DEVICE: &str = "/dev/tpmrm0";

/// Get configuration value from flag, environment variable, or default (in priority order)
pub fn get_config_string(flag_value: Option<&str>, env_var: &str, default: &str) -> String {
    if let Some(v) = flag_value {
        if !v.is_empty() {
            return v.to_string();
        }
    }
    if let Ok(v) = env::var(env_var) {
        if !v.is_empty() {
            return v;
        }
    }
    default.to_string()
}

/// Get the path to da.json configuration file
pub fn get_da_config_path() -> String {
    get_config_string(None, "DA_JSON_PATH", DEFAULT_DA_JSON_PATH)
}

/// Get the TPM device path from environment or default
pub fn get_tpm_device(flag_value: Option<&str>) -> String {
    get_config_string(flag_value, "TPM_DEVICE", DEFAULT_TPM_DEVICE)
}

/// Get the output directory for generated certificates
pub fn get_output_dir(flag_value: Option<&str>) -> String {
    get_config_string(flag_value, "DA_OUTPUT_DIR", ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_config_string_flag_priority() {
        let result = get_config_string(Some("flag_value"), "NONEXISTENT_VAR", "default");
        assert_eq!(result, "flag_value");
    }

    #[test]
    fn test_get_config_string_default() {
        let result = get_config_string(None, "NONEXISTENT_VAR_12345", "default_value");
        assert_eq!(result, "default_value");
    }
}
