use crate::enrollment::write_enrollment_file;
use crate::machine::local_machine_domain;
use crate::metadata::SetupMetadata;
use crate::password::generate_windows_password;
use crate::platform;
use crate::validation::{validate_installed_files, validate_local_account_name};
use otpuac_core::{
    generate_totp_secret, now_unix, ManagedAccount, Result, SecretProtector, TotpPolicy, VaultFile,
};
use otpuac_runtime::{
    default_protector,
    paths::{setup_metadata_path, vault_path},
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn install_managed(
    account_name: String,
    issuer: String,
    install_dir: PathBuf,
    program_data: PathBuf,
    enrollment_file: Option<PathBuf>,
) -> Result<()> {
    validate_local_account_name(&account_name)?;
    validate_installed_files(&install_dir)?;

    fs::create_dir_all(&program_data)?;
    platform::secure_program_data_dir(&program_data)?;

    let metadata_path = setup_metadata_path(&program_data);
    let vault_path = vault_path(&program_data);
    let protector = default_protector();

    let (metadata, vault, is_new_install) =
        match read_existing_install(&metadata_path, &vault_path)? {
            Some((metadata, vault)) => (metadata, vault, false),
            None => {
                let (metadata, vault) = provision_new_install(
                    &account_name,
                    issuer,
                    &install_dir,
                    &metadata_path,
                    &vault_path,
                    &protector,
                )?;
                (metadata, vault, true)
            }
        };

    if let Some(path) = enrollment_file {
        if let Err(err) = write_enrollment_file(&path, &metadata, &vault, &protector) {
            if is_new_install {
                rollback_new_install(&account_name, &metadata_path, &vault_path);
            }
            return Err(err);
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&InstallSummary {
            status: "installed",
            account: metadata.managed_account_username,
            account_sid: metadata.managed_account_sid,
            vault_path,
        })?
    );

    Ok(())
}

pub(crate) fn verify_code(code: String, program_data: PathBuf) -> Result<()> {
    let protector = default_protector();
    let vault = VaultFile::read_from_path(vault_path(program_data))?;
    vault.accepted_totp_step(&code, now_unix(), &protector)?;
    println!("TOTP accepted for {}", vault.account.label());
    Ok(())
}

pub(crate) fn uninstall(
    program_data: PathBuf,
    remove_data: bool,
    remove_created_account: bool,
) -> Result<()> {
    let metadata_path = setup_metadata_path(&program_data);
    let metadata = if metadata_path.exists() {
        Some(SetupMetadata::read_from_path(&metadata_path)?)
    } else {
        None
    };

    if let Some(metadata) = metadata
        .as_ref()
        .filter(|metadata| metadata.managed_account_created_by_otpuac)
    {
        cleanup_managed_account(metadata, remove_created_account)?;
    }

    if remove_data {
        validate_remove_data_target(&program_data, metadata.as_ref())?;
        if program_data.exists() {
            fs::remove_dir_all(&program_data)?;
        }
    }

    println!("OTPUAC uninstall cleanup completed");
    Ok(())
}

fn read_existing_install(
    metadata_path: &Path,
    vault_path: &Path,
) -> Result<Option<(SetupMetadata, VaultFile)>> {
    match (metadata_path.exists(), vault_path.exists()) {
        (true, true) => Ok(Some((
            SetupMetadata::read_from_path(metadata_path)?,
            VaultFile::read_from_path(vault_path)?,
        ))),
        (false, true) => Err(otpuac_core::OtpuacError::InvalidConfig(format!(
            "{} already exists but {} is missing; uninstall or recover manually before reinstalling",
            vault_path.display(),
            metadata_path.display()
        ))),
        _ => Ok(None),
    }
}

fn provision_new_install(
    account_name: &str,
    issuer: String,
    install_dir: &Path,
    metadata_path: &Path,
    vault_path: &Path,
    protector: &impl SecretProtector,
) -> Result<(SetupMetadata, VaultFile)> {
    let password = generate_windows_password();
    let totp_secret = generate_totp_secret();
    let account = ManagedAccount {
        username: account_name.to_string(),
        domain: local_machine_domain(),
    };
    let policy = TotpPolicy {
        issuer,
        ..TotpPolicy::default()
    };

    let account_sid = platform::create_local_admin_account(account_name, &password)?;

    let provision_result = (|| {
        platform::hide_local_account_from_sign_in(account_name)?;

        let vault = VaultFile::new(account.clone(), &password, &totp_secret, policy, protector)?;
        vault.write_to_path(vault_path)?;

        let metadata = SetupMetadata::new_managed_local_admin(&account, account_sid, install_dir);
        metadata.write_to_path(metadata_path)?;

        Ok((metadata, vault))
    })();

    if provision_result.is_err() {
        rollback_new_install(account_name, metadata_path, vault_path);
    }
    provision_result
}

fn cleanup_managed_account(metadata: &SetupMetadata, remove_created_account: bool) -> Result<()> {
    platform::unhide_local_account_from_sign_in(&metadata.managed_account_username)?;
    if remove_created_account {
        platform::delete_local_account(&metadata.managed_account_username)?;
    }
    Ok(())
}

fn validate_remove_data_target(
    program_data: &Path,
    metadata: Option<&SetupMetadata>,
) -> Result<()> {
    let metadata = metadata.ok_or_else(|| {
        otpuac_core::OtpuacError::InvalidConfig(format!(
            "refusing to remove {} because OTPUAC setup metadata is missing",
            program_data.display()
        ))
    })?;

    if !metadata.is_otpuac_install() {
        return Err(otpuac_core::OtpuacError::InvalidConfig(format!(
            "refusing to remove {} because OTPUAC setup metadata is not valid",
            program_data.display()
        )));
    }

    Ok(())
}

fn rollback_new_install(account_name: &str, metadata_path: &Path, vault_path: &Path) {
    let _ = platform::unhide_local_account_from_sign_in(account_name);
    let _ = platform::delete_local_account(account_name);
    let _ = fs::remove_file(metadata_path);
    let _ = fs::remove_file(vault_path);
}

#[derive(Serialize)]
struct InstallSummary {
    status: &'static str,
    account: String,
    account_sid: String,
    vault_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_data_target_requires_setup_metadata() {
        let err = validate_remove_data_target(Path::new("program-data"), None).unwrap_err();
        assert!(err.to_string().contains("setup metadata is missing"));
    }

    #[test]
    fn remove_data_target_rejects_unexpected_metadata() {
        let mut metadata = valid_metadata();
        metadata.service_name = "OtherService".to_string();

        let err =
            validate_remove_data_target(Path::new("program-data"), Some(&metadata)).unwrap_err();
        assert!(err.to_string().contains("setup metadata is not valid"));
    }

    #[test]
    fn remove_data_target_accepts_otpuac_metadata() {
        let metadata = valid_metadata();

        validate_remove_data_target(Path::new("program-data"), Some(&metadata)).unwrap();
    }

    fn valid_metadata() -> SetupMetadata {
        let account = ManagedAccount {
            username: "OTPUACAdmin".to_string(),
            domain: None,
        };
        SetupMetadata::new_managed_local_admin(
            &account,
            "S-1-5-21-test".to_string(),
            Path::new(r"C:\Program Files\OTPUAC"),
        )
    }
}
