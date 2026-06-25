use crate::enrollment::write_enrollment_file;
use crate::machine::local_machine_domain;
use crate::metadata::{read_metadata, write_metadata, SetupMetadata};
use crate::password::generate_windows_password;
use crate::platform;
use crate::validation::{validate_installed_files, validate_local_account_name};
use otpuac_core::{
    generate_totp_secret, now_unix, ManagedAccount, Result, SecretProtector, TotpPolicy, VaultFile,
};
use otpuac_runtime::{
    default_protector,
    paths::{setup_metadata_path, vault_path, PROVIDER_DLL, SERVICE_EXE, SERVICE_NAME},
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

    let mut rollback_account = None;
    let (metadata, vault) =
        if let Some(installed) = read_existing_install(&metadata_path, &vault_path)? {
            installed
        } else {
            let provisioned = provision_new_install(
                &account_name,
                issuer,
                &install_dir,
                &metadata_path,
                &vault_path,
                &protector,
            )?;
            rollback_account = Some(provisioned.rollback_account_name.clone());
            (provisioned.metadata, provisioned.vault)
        };

    if let Err(err) =
        configure_install(&install_dir, enrollment_file, &metadata, &vault, &protector)
    {
        rollback_new_install(rollback_account.take(), &metadata_path, &vault_path);
        return Err(err);
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
    install_dir: PathBuf,
    program_data: PathBuf,
    remove_data: bool,
    remove_created_account: bool,
) -> Result<()> {
    let metadata_path = setup_metadata_path(&program_data);
    let metadata = if metadata_path.exists() {
        Some(read_metadata(&metadata_path)?)
    } else {
        None
    };

    platform::stop_and_delete_service()?;
    platform::unregister_event_log_source()?;

    let provider_dll = install_dir.join(PROVIDER_DLL);
    if provider_dll.exists() {
        platform::unregister_provider(&provider_dll)?;
    }

    if let Some(metadata) = metadata
        .as_ref()
        .filter(|metadata| metadata.managed_account_created_by_otpuac)
    {
        cleanup_managed_account(metadata, remove_created_account)?;
    }

    if remove_data {
        validate_remove_data_target(&program_data, metadata.as_ref())?;
    }

    if remove_data && program_data.exists() {
        fs::remove_dir_all(&program_data)?;
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
            read_metadata(metadata_path)?,
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
) -> Result<ProvisionedInstall> {
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

        let metadata = SetupMetadata {
            version: 1,
            install_kind: "managed-local-admin".to_string(),
            managed_account_username: account.username.clone(),
            managed_account_domain: account.domain.clone(),
            managed_account_sid: account_sid,
            managed_account_created_by_otpuac: true,
            install_dir: install_dir.to_path_buf(),
            service_name: SERVICE_NAME.to_string(),
            created_at_unix: now_unix(),
        };
        write_metadata(metadata_path, &metadata)?;

        Ok(ProvisionedInstall {
            metadata,
            vault,
            rollback_account_name: account_name.to_string(),
        })
    })();

    if provision_result.is_err() {
        rollback_new_install(Some(account_name.to_string()), metadata_path, vault_path);
    }
    provision_result
}

fn configure_install(
    install_dir: &Path,
    enrollment_file: Option<PathBuf>,
    metadata: &SetupMetadata,
    vault: &VaultFile,
    protector: &impl SecretProtector,
) -> Result<()> {
    platform::register_provider(&install_dir.join(PROVIDER_DLL))?;
    platform::register_event_log_source(&install_dir.join(SERVICE_EXE))?;
    platform::install_or_replace_service(&install_dir.join(SERVICE_EXE))?;

    if let Some(path) = enrollment_file {
        write_enrollment_file(&path, metadata, vault, protector)?;
    }
    Ok(())
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

    if metadata.version != 1
        || metadata.install_kind != "managed-local-admin"
        || metadata.service_name != SERVICE_NAME
    {
        return Err(otpuac_core::OtpuacError::InvalidConfig(format!(
            "refusing to remove {} because OTPUAC setup metadata is not valid",
            program_data.display()
        )));
    }

    Ok(())
}

fn rollback_new_install(account_name: Option<String>, metadata_path: &Path, vault_path: &Path) {
    if let Some(account_name) = account_name {
        let _ = platform::unhide_local_account_from_sign_in(&account_name);
        let _ = platform::delete_local_account(&account_name);
        let _ = fs::remove_file(metadata_path);
        let _ = fs::remove_file(vault_path);
    }
}

#[derive(Serialize)]
struct InstallSummary {
    status: &'static str,
    account: String,
    account_sid: String,
    vault_path: PathBuf,
}

struct ProvisionedInstall {
    metadata: SetupMetadata,
    vault: VaultFile,
    rollback_account_name: String,
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
        SetupMetadata {
            version: 1,
            install_kind: "managed-local-admin".to_string(),
            managed_account_username: "OTPUACAdmin".to_string(),
            managed_account_domain: None,
            managed_account_sid: "S-1-5-21-test".to_string(),
            managed_account_created_by_otpuac: true,
            install_dir: PathBuf::from(r"C:\Program Files\OTPUAC"),
            service_name: SERVICE_NAME.to_string(),
            created_at_unix: 1,
        }
    }
}
