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
use otpuac_runtime::paths::{default_install_dir, default_program_data_dir};

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
            install_dir.unwrap_or_else(default_install_dir),
            program_data.unwrap_or_else(default_program_data_dir),
            enrollment_file,
        ),
        Command::Verify { code, program_data } => {
            verify_code(code, program_data.unwrap_or_else(default_program_data_dir))
        }
        Command::Uninstall {
            install_dir,
            program_data,
            remove_data,
            remove_created_account,
        } => uninstall(
            install_dir.unwrap_or_else(default_install_dir),
            program_data.unwrap_or_else(default_program_data_dir),
            remove_data,
            remove_created_account,
        ),
    }
}
