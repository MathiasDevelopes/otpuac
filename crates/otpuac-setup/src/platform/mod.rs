#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(not(windows))]
pub(crate) use unsupported::*;

/// Lets the crate build and test elsewhere; every account or ACL change fails.
#[cfg(not(windows))]
mod unsupported {
    use otpuac_core::{OtpuacError, Result};
    use std::path::Path;

    fn unsupported<T>() -> Result<T> {
        Err(OtpuacError::Platform(
            "account and data management is only available on Windows".to_string(),
        ))
    }

    pub(crate) fn create_local_admin_account(_username: &str, _password: &str) -> Result<()> {
        unsupported()
    }

    pub(crate) fn delete_local_account(_username: &str) -> Result<()> {
        unsupported()
    }

    pub(crate) fn hide_local_account_from_sign_in(_username: &str) -> Result<()> {
        unsupported()
    }

    pub(crate) fn unhide_local_account_from_sign_in(_username: &str) -> Result<()> {
        unsupported()
    }

    pub(crate) fn secure_data_dir(_path: &Path) -> Result<()> {
        unsupported()
    }
}
