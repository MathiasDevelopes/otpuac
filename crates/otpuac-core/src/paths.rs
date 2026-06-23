use std::path::{Path, PathBuf};

pub const APP_DIR_NAME: &str = "OTPUAC";
pub const SERVICE_NAME: &str = "OTPUAC";
pub const SETUP_METADATA_FILE: &str = "setup.json";
pub const SERVICE_STATE_FILE: &str = "service-state.json";
pub const VAULT_FILE: &str = "vault.json";
pub const PROVIDER_DLL: &str = "otpuac_provider_rs.dll";
pub const SERVICE_EXE: &str = "otpuac-service.exe";
pub const ADMIN_EXE: &str = "otpuac-admin.exe";

pub fn default_install_dir() -> PathBuf {
    env_path_or_default("ProgramFiles", r"C:\Program Files").join(APP_DIR_NAME)
}

pub fn default_program_data_dir() -> PathBuf {
    env_path_or_default("ProgramData", r"C:\ProgramData").join(APP_DIR_NAME)
}

pub fn default_vault_path() -> PathBuf {
    #[cfg(windows)]
    {
        vault_path(default_program_data_dir())
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("target").join("otpuac-dev").join(VAULT_FILE)
    }
}

pub fn setup_metadata_path(program_data_dir: impl AsRef<Path>) -> PathBuf {
    program_data_dir.as_ref().join(SETUP_METADATA_FILE)
}

pub fn service_state_path(program_data_dir: impl AsRef<Path>) -> PathBuf {
    program_data_dir.as_ref().join(SERVICE_STATE_FILE)
}

pub fn vault_path(program_data_dir: impl AsRef<Path>) -> PathBuf {
    program_data_dir.as_ref().join(VAULT_FILE)
}

fn env_path_or_default(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_program_data_paths_use_shared_filenames() {
        let root = Path::new("program-data");

        assert_eq!(setup_metadata_path(root), root.join(SETUP_METADATA_FILE));
        assert_eq!(service_state_path(root), root.join(SERVICE_STATE_FILE));
        assert_eq!(vault_path(root), root.join(VAULT_FILE));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_default_vault_path_uses_dev_target() {
        assert_eq!(
            default_vault_path(),
            PathBuf::from("target").join("otpuac-dev").join(VAULT_FILE)
        );
    }
}
