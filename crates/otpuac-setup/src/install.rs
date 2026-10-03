use crate::enrollment_text;
use crate::password::generate_windows_password;
use crate::platform;
use otpuac_core::{guard_path, totp, vault_path, ManagedAccount, OtpuacError, Result, Vault};
use serde::Deserialize;
use std::fs;
use std::path::Path;

const MAX_LOCAL_ACCOUNT_NAME_BYTES: usize = 20;
const INVALID_LOCAL_ACCOUNT_CHARS: [char; 16] = [
    '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@',
];
/// Written by OTPUAC 1.0 next to the vault; read only to finish uninstalling
/// such installs.
const LEGACY_SETUP_FILE: &str = "setup.json";
const LEGACY_STATE_FILE: &str = "service-state.json";

pub(crate) fn install(
    account_name: &str,
    data_dir: &Path,
    enrollment_file: Option<&Path>,
) -> Result<()> {
    validate_local_account_name(account_name)?;
    fs::create_dir_all(data_dir)?;
    platform::secure_data_dir(data_dir)?;

    let vault_path = vault_path(data_dir);
    let (vault, is_new) = if vault_path.exists() {
        (Vault::read(&vault_path)?, false)
    } else {
        (provision(account_name, &vault_path)?, true)
    };

    if let Some(path) = enrollment_file {
        if let Err(err) = write_enrollment_file(path, &vault) {
            if is_new {
                rollback(account_name, &vault_path);
            }
            return Err(err);
        }
    }

    println!("OTPUAC installed for {}", vault.account.label());
    Ok(())
}

pub(crate) fn uninstall(data_dir: &Path) -> Result<()> {
    let vault_path = vault_path(data_dir);
    if vault_path.exists() {
        let vault = Vault::read(&vault_path)?;
        if vault.created_account || legacy_install_created_account(data_dir) {
            let username = &vault.account.username;
            platform::unhide_local_account_from_sign_in(username)?;
            platform::delete_local_account(username)?;
        }
    }

    // Remove only the files OTPUAC writes, then the directory if that left it
    // empty, so a mistyped --data-dir cannot delete anything else.
    for path in [
        vault_path,
        guard_path(data_dir),
        data_dir.join(LEGACY_SETUP_FILE),
        data_dir.join(LEGACY_STATE_FILE),
    ] {
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    let _ = fs::remove_dir(data_dir);

    println!("OTPUAC uninstall cleanup completed");
    Ok(())
}

fn provision(account_name: &str, vault_path: &Path) -> Result<Vault> {
    let password = generate_windows_password();
    let account = ManagedAccount {
        username: account_name.to_string(),
        domain: std::env::var("COMPUTERNAME")
            .ok()
            .filter(|name| !name.trim().is_empty()),
    };

    platform::create_local_admin_account(account_name, &password)?;
    let result = (|| {
        platform::hide_local_account_from_sign_in(account_name)?;
        let mut vault = Vault::new(account, &password, &totp::generate_secret())?;
        vault.created_account = true;
        vault.write(vault_path)?;
        Ok(vault)
    })();

    if result.is_err() {
        rollback(account_name, vault_path);
    }
    result
}

fn rollback(account_name: &str, vault_path: &Path) {
    let _ = platform::unhide_local_account_from_sign_in(account_name);
    let _ = platform::delete_local_account(account_name);
    let _ = fs::remove_file(vault_path);
}

fn write_enrollment_file(path: &Path, vault: &Vault) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, enrollment_text(vault)?)?;
    Ok(())
}

fn legacy_install_created_account(data_dir: &Path) -> bool {
    #[derive(Deserialize)]
    struct LegacySetup {
        managed_account_created_by_otpuac: bool,
    }

    fs::read(data_dir.join(LEGACY_SETUP_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<LegacySetup>(&bytes).ok())
        .is_some_and(|setup| setup.managed_account_created_by_otpuac)
}

fn validate_local_account_name(account_name: &str) -> Result<()> {
    let invalid = |reason: &str| Err(OtpuacError::InvalidConfig(reason.to_string()));
    if account_name.trim().is_empty() {
        return invalid("managed account name is required");
    }
    if account_name.trim() != account_name {
        return invalid("managed account name must not start or end with whitespace");
    }
    if account_name.len() > MAX_LOCAL_ACCOUNT_NAME_BYTES
        || account_name
            .chars()
            .any(|ch| INVALID_LOCAL_ACCOUNT_CHARS.contains(&ch))
    {
        return invalid("managed account name is not a valid local Windows account name");
    }
    Ok(())
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

    #[test]
    fn legacy_setup_file_says_whether_setup_created_the_account() {
        let dir = std::env::temp_dir().join(format!("otpuac-setup-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(!legacy_install_created_account(&dir));

        fs::write(
            dir.join(LEGACY_SETUP_FILE),
            r#"{"version":1,"managed_account_created_by_otpuac":true,"service_name":"OTPUAC"}"#,
        )
        .unwrap();
        assert!(legacy_install_created_account(&dir));

        fs::remove_dir_all(&dir).unwrap();
    }
}
