use crate::metadata::SetupMetadata;
use otpuac_core::{otpauth_uri, paths::ADMIN_EXE, Result, VaultFile};
use std::fs;
use std::path::Path;

pub(crate) fn write_enrollment_file(
    path: &Path,
    metadata: &SetupMetadata,
    vault: &VaultFile,
    protector: &impl otpuac_core::SecretProtector,
) -> Result<()> {
    let secret = vault.encoded_totp_secret(protector)?;
    let uri = otpauth_uri(&vault.account.label(), &secret, &vault.totp_policy)?;
    let admin = metadata.install_dir.join(ADMIN_EXE);
    let contents = enrollment_contents(metadata, vault, &secret, &uri, &admin);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    Ok(())
}

fn enrollment_contents(
    metadata: &SetupMetadata,
    vault: &VaultFile,
    secret: &str,
    uri: &str,
    admin: &Path,
) -> String {
    let contents = format!(
        "OTPUAC authenticator enrollment\r\n\
         \r\n\
         Managed account: {account}\r\n\
         Account SID: {sid}\r\n\
         \r\n\
         Add a new TOTP account in your authenticator app with this secret:\r\n\
         {secret}\r\n\
         \r\n\
         Enrollment URI:\r\n\
         {uri}\r\n\
         \r\n\
         After enrollment, verify a code.\r\n\
         \r\n\
         From elevated PowerShell:\r\n\
         & \"{admin}\" verify --code 123456\r\n\
         \r\n\
         From elevated Command Prompt:\r\n\
         \"{admin}\" verify --code 123456\r\n",
        account = vault.account.label(),
        sid = metadata.managed_account_sid,
        secret = secret,
        uri = uri,
        admin = admin.display()
    );
    contents
}
