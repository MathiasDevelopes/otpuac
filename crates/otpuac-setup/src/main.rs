mod install;
mod password;
mod platform;

use clap::{Parser, Subcommand};
use otpuac_core::totp::{encode_secret, otpauth_uri};
use otpuac_core::{default_data_dir, now_unix, vault_path, Result, Vault};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "otpuac-setup")]
#[command(about = "Install, enroll, and remove OTPUAC.")]
struct Cli {
    /// Directory holding the vault, `C:\ProgramData\OTPUAC` by default.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the managed administrator and its vault, or keep an existing one.
    Install {
        #[arg(long, default_value = "OTPUACAdmin")]
        account_name: String,

        /// Also write the enrollment details to this file.
        #[arg(long)]
        enrollment_file: Option<PathBuf>,
    },
    /// Print the TOTP secret and enrollment URI for an authenticator app.
    Enrollment,
    /// Check a code from the authenticator app without using it up.
    Verify {
        #[arg(long)]
        code: String,
    },
    /// Delete the managed administrator setup created and the OTPUAC data.
    Uninstall,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);

    match cli.command {
        Command::Install {
            account_name,
            enrollment_file,
        } => install::install(&account_name, &data_dir, enrollment_file.as_deref()),
        Command::Enrollment => {
            print!(
                "{}",
                enrollment_text(&Vault::read(&vault_path(&data_dir))?)?
            );
            Ok(())
        }
        Command::Verify { code } => {
            let vault = otpuac_core::verify(&data_dir, &code, now_unix())?;
            println!("Code accepted for {}", vault.account.label());
            Ok(())
        }
        Command::Uninstall => install::uninstall(&data_dir),
    }
}

pub(crate) fn enrollment_text(vault: &Vault) -> Result<String> {
    let account = vault.account.label();
    let secret = encode_secret(&vault.totp_secret()?);
    let uri = otpauth_uri(&account, &secret);
    let setup = std::env::current_exe()?;
    Ok(format!(
        "OTPUAC authenticator enrollment\r\n\
         \r\n\
         Managed account: {account}\r\n\
         \r\n\
         Add a TOTP account in your authenticator app with this secret:\r\n\
         {secret}\r\n\
         \r\n\
         or this enrollment URI:\r\n\
         {uri}\r\n\
         \r\n\
         Then check a code from an elevated prompt:\r\n\
         \"{setup}\" verify --code 123456\r\n",
        setup = setup.display()
    ))
}
