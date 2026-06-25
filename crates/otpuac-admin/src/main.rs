use clap::{Parser, Subcommand};
use otpuac_core::totp::{encode_totp_secret, otpauth_uri};
use otpuac_core::{
    default_protector, generate_totp_secret, now_unix, ManagedAccount, Result, TotpPolicy,
    VaultFile,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "otpuac-admin")]
#[command(about = "Provision and inspect the OTPUAC managed credential vault.")]
struct Cli {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Provision {
        #[arg(long)]
        username: String,

        #[arg(long)]
        domain: Option<String>,

        #[arg(long)]
        password: Option<String>,

        #[arg(long, default_value = "OTPUAC")]
        issuer: String,

        #[arg(long)]
        force: bool,
    },
    ShowEnrollment,
    Verify {
        #[arg(long)]
        code: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = cli
        .vault
        .unwrap_or_else(otpuac_core::paths::default_vault_path);
    let protector = default_protector();

    match cli.command {
        Command::Provision {
            username,
            domain,
            password,
            issuer,
            force,
        } => provision_vault(
            &vault_path,
            username,
            domain,
            password,
            issuer,
            force,
            &protector,
        )?,
        Command::ShowEnrollment => show_enrollment(&vault_path, &protector)?,
        Command::Verify { code } => verify_code(&vault_path, &code, &protector)?,
    }

    Ok(())
}

fn provision_vault(
    vault_path: &Path,
    username: String,
    domain: Option<String>,
    password: Option<String>,
    issuer: String,
    force: bool,
    protector: &impl otpuac_core::SecretProtector,
) -> Result<()> {
    if vault_path.exists() && !force {
        return Err(otpuac_core::OtpuacError::InvalidVault(format!(
            "{} already exists; pass --force to overwrite it",
            vault_path.display()
        )));
    }

    let account = ManagedAccount { username, domain };
    let password = prompt_password(password)?;
    let secret = generate_totp_secret();
    let policy = TotpPolicy {
        issuer,
        ..TotpPolicy::default()
    };
    let vault = VaultFile::new(
        account.clone(),
        &password,
        &secret,
        policy.clone(),
        protector,
    )?;
    vault.write_to_path(vault_path)?;

    println!("Vault written: {}", vault_path.display());
    print_enrollment(&account, &encode_totp_secret(&secret), &policy)
}

fn show_enrollment(vault_path: &Path, protector: &impl otpuac_core::SecretProtector) -> Result<()> {
    let vault = VaultFile::read_from_path(vault_path)?;
    let encoded_secret = vault.encoded_totp_secret(protector)?;
    print_enrollment(&vault.account, &encoded_secret, &vault.totp_policy)
}

fn verify_code(
    vault_path: &Path,
    code: &str,
    protector: &impl otpuac_core::SecretProtector,
) -> Result<()> {
    let vault = VaultFile::read_from_path(vault_path)?;
    vault.accepted_totp_step(code, now_unix(), protector)?;
    println!("TOTP accepted for {}", vault.account.label());
    Ok(())
}

fn prompt_password(password: Option<String>) -> Result<Zeroizing<String>> {
    password
        .map(Zeroizing::new)
        .map(Ok)
        .unwrap_or_else(|| {
            rpassword::prompt_password("Managed admin password: ").map(Zeroizing::new)
        })
        .map_err(Into::into)
}

fn print_enrollment(
    account: &ManagedAccount,
    encoded_secret: &str,
    policy: &TotpPolicy,
) -> Result<()> {
    println!("Managed account: {}", account.label());
    println!("TOTP secret: {encoded_secret}");
    println!(
        "Enrollment URI: {}",
        otpauth_uri(&account.label(), encoded_secret, policy)?
    );
    Ok(())
}
