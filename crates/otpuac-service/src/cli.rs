use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "otpuac-service")]
#[command(about = "OTPUAC LocalSystem service host and debug unlock handler.")]
pub(crate) struct Cli {
    #[arg(long, global = true)]
    pub(crate) vault: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Check {
        #[arg(long)]
        code: String,
    },
    PipeCheck {
        #[arg(long)]
        code: String,
    },
    ServeForeground,
    HandleJson {
        request_json: String,

        #[arg(long)]
        emit_secret: bool,
    },
    Run,
}
