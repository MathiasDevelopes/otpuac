mod cli;
mod enrollment;
mod install;
mod machine;
mod metadata;
mod password;
mod platform;
mod validation;

use clap::Parser;
use cli::{Cli, Command};
use install::{install_managed, uninstall, verify_code};
use otpuac_core::Result;
use otpuac_runtime::paths::default_program_data_dir;
use std::path::PathBuf;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::InstallManaged {
            account_name,
            issuer,
            install_dir,
            program_data,
            enrollment_file,
        } => install_managed(
            account_name,
            issuer,
            install_dir.map_or_else(helper_install_dir, Ok)?,
            program_data.unwrap_or_else(default_program_data_dir),
            enrollment_file,
        ),
        Command::Verify { code, program_data } => {
            verify_code(code, program_data.unwrap_or_else(default_program_data_dir))
        }
        Command::Uninstall {
            program_data,
            remove_data,
            remove_created_account,
        } => uninstall(
            program_data.unwrap_or_else(default_program_data_dir),
            remove_data,
            remove_created_account,
        ),
    }
}

/// The MSI installs this helper next to the files it provisions, so its own
/// directory is the install directory unless one is passed explicitly.
fn helper_install_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent().map(PathBuf::from).ok_or_else(|| {
        otpuac_core::OtpuacError::InvalidConfig(format!(
            "cannot resolve install directory from {}",
            exe.display()
        ))
    })
}
