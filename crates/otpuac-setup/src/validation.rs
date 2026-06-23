use otpuac_core::{
    paths::{ADMIN_EXE, PROVIDER_DLL, SERVICE_EXE},
    Result,
};
use std::path::Path;

const MAX_LOCAL_ACCOUNT_NAME_BYTES: usize = 20;
const INVALID_LOCAL_ACCOUNT_CHARS: [char; 16] = [
    '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@',
];

pub(crate) fn validate_installed_files(install_dir: &Path) -> Result<()> {
    for file in [PROVIDER_DLL, SERVICE_EXE, ADMIN_EXE] {
        let path = install_dir.join(file);
        if !path.exists() {
            return Err(otpuac_core::OtpuacError::InvalidVault(format!(
                "missing installed artifact: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_local_account_name(account_name: &str) -> Result<()> {
    let trimmed = account_name.trim();
    if trimmed.is_empty() {
        return Err(otpuac_core::OtpuacError::InvalidVault(
            "managed account name is required".to_string(),
        ));
    }
    if trimmed != account_name {
        return Err(otpuac_core::OtpuacError::InvalidVault(
            "managed account name must not start or end with whitespace".to_string(),
        ));
    }
    if account_name.len() > MAX_LOCAL_ACCOUNT_NAME_BYTES
        || account_name.chars().any(is_invalid_local_account_char)
    {
        return Err(otpuac_core::OtpuacError::InvalidVault(
            "managed account name is not a valid local Windows account name".to_string(),
        ));
    }
    Ok(())
}

fn is_invalid_local_account_char(ch: char) -> bool {
    INVALID_LOCAL_ACCOUNT_CHARS.contains(&ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_name_validation_rejects_windows_special_characters() {
        assert!(validate_local_account_name("OTPUACAdmin").is_ok());
        assert!(validate_local_account_name("bad\\name").is_err());
        assert!(validate_local_account_name(" name").is_err());
        assert!(validate_local_account_name("averyveryverylongusername").is_err());
    }
}
