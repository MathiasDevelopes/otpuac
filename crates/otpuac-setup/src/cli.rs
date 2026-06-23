use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "otpuac-setup")]
#[command(about = "OTPUAC Windows installer helper.")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    InstallManaged {
        #[arg(long, default_value = "OTPUACAdmin")]
        account_name: String,

        #[arg(long, default_value = "OTPUAC")]
        issuer: String,

        #[arg(long)]
        install_dir: Option<PathBuf>,

        #[arg(long)]
        program_data: Option<PathBuf>,

        #[arg(long)]
        enrollment_file: Option<PathBuf>,
    },
    Verify {
        #[arg(long)]
        code: String,

        #[arg(long)]
        program_data: Option<PathBuf>,
    },
    Uninstall {
        #[arg(long)]
        install_dir: Option<PathBuf>,

        #[arg(long)]
        program_data: Option<PathBuf>,

        #[arg(long)]
        remove_data: bool,

        #[arg(long)]
        remove_created_account: bool,
    },
}
