use clap::{Parser, Subcommand};
#[cfg(debug_assertions)]
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "otpuac-service")]
#[command(about = "OTPUAC Windows service host.")]
pub(crate) struct Cli {
    #[cfg(debug_assertions)]
    #[arg(long, global = true)]
    pub(crate) vault: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    #[cfg(debug_assertions)]
    Check {
        #[arg(long)]
        code: String,
    },
    #[cfg(debug_assertions)]
    PipeCheck {
        #[arg(long)]
        code: String,
    },
    #[cfg(debug_assertions)]
    ServeForeground,
    #[cfg(debug_assertions)]
    HandleJson {
        request_json: String,

        #[arg(long)]
        emit_secret: bool,
    },
    Run,
}
