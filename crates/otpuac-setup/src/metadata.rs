use otpuac_core::{now_unix, ManagedAccount, Result};
use otpuac_runtime::paths::SERVICE_NAME;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const SETUP_METADATA_VERSION: u32 = 1;
const MANAGED_LOCAL_ADMIN_INSTALL_KIND: &str = "managed-local-admin";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SetupMetadata {
    pub(crate) version: u32,
    pub(crate) install_kind: String,
    pub(crate) managed_account_username: String,
    pub(crate) managed_account_domain: Option<String>,
    pub(crate) managed_account_sid: String,
    pub(crate) managed_account_created_by_otpuac: bool,
    pub(crate) install_dir: PathBuf,
    pub(crate) service_name: String,
    pub(crate) created_at_unix: u64,
}

impl SetupMetadata {
    pub(crate) fn new_managed_local_admin(
        account: &ManagedAccount,
        account_sid: String,
        install_dir: &Path,
    ) -> Self {
        Self {
            version: SETUP_METADATA_VERSION,
            install_kind: MANAGED_LOCAL_ADMIN_INSTALL_KIND.to_string(),
            managed_account_username: account.username.clone(),
            managed_account_domain: account.domain.clone(),
            managed_account_sid: account_sid,
            managed_account_created_by_otpuac: true,
            install_dir: install_dir.to_path_buf(),
            service_name: SERVICE_NAME.to_string(),
            created_at_unix: now_unix(),
        }
    }

    pub(crate) fn is_otpuac_install(&self) -> bool {
        self.version == SETUP_METADATA_VERSION
            && self.install_kind == MANAGED_LOCAL_ADMIN_INSTALL_KIND
            && self.service_name == SERVICE_NAME
    }

    pub(crate) fn read_from_path(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub(crate) fn write_to_path(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        fs::write(path, bytes)?;
        Ok(())
    }
}
