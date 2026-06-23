use otpuac_core::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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

pub(crate) fn read_metadata(path: &Path) -> Result<SetupMetadata> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn write_metadata(path: &Path, metadata: &SetupMetadata) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(metadata)?;
    fs::write(path, bytes)?;
    Ok(())
}
