//! OTPUAC: a valid TOTP code releases a managed administrator credential to
//! the UAC prompt.
//!
//! Everything except the Windows-only helpers in [`win`] is plain Rust and is
//! tested on any platform.

pub mod error;
pub mod guard;
pub mod protect;
pub mod totp;
pub mod unlock;
pub mod vault;
#[cfg(windows)]
pub mod win;

pub use error::{OtpuacError, Result};
pub use unlock::{unlock, verify};
pub use vault::{Credential, ManagedAccount, Vault};

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VAULT_FILE: &str = "vault.json";
pub const GUARD_FILE: &str = "guard.json";

/// `C:\ProgramData\OTPUAC`, readable only by SYSTEM and Administrators.
pub fn default_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("OTPUAC")
}

pub fn vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join(VAULT_FILE)
}

pub fn guard_path(data_dir: &Path) -> PathBuf {
    data_dir.join(GUARD_FILE)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
