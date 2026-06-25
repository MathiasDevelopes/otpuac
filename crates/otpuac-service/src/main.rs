mod audit;
mod cli;
mod platform;
mod state;
#[cfg(any(windows, debug_assertions))]
mod unlock;

use clap::Parser;
use cli::{Cli, Command};
use otpuac_core::{paths::default_vault_path, Result};
#[cfg(debug_assertions)]
use otpuac_core::{ProviderUnlockRequest, CRED_UI_USAGE_SCENARIO};
use platform::run_service;
#[cfg(debug_assertions)]
use platform::{pipe_check, serve_foreground};
#[cfg(debug_assertions)]
use unlock::{handle_unlock_request, redact_response};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(default_vault_path);

    match cli.command {
        #[cfg(debug_assertions)]
        Command::Check { code } => {
            let request = credential_ui_request("debug-check", code);
            let response = handle_unlock_request(&vault_path, request, false)?;
            print_json_pretty(&response)?;
        }
        #[cfg(debug_assertions)]
        Command::PipeCheck { code } => {
            let request = credential_ui_request("pipe-check", code);
            let response = pipe_check(request)?;
            print_json_pretty(&redact_response(response))?;
        }
        #[cfg(debug_assertions)]
        Command::ServeForeground => serve_foreground(&vault_path)?,
        #[cfg(debug_assertions)]
        Command::HandleJson {
            request_json,
            emit_secret,
        } => {
            let request = serde_json::from_str::<ProviderUnlockRequest>(&request_json)?;
            let response = handle_unlock_request(&vault_path, request, emit_secret)?;
            println!("{}", serde_json::to_string(&response)?);
        }
        Command::Run => run_service(&vault_path)?,
    }

    Ok(())
}

#[cfg(debug_assertions)]
fn credential_ui_request(request_id: &str, totp_code: String) -> ProviderUnlockRequest {
    ProviderUnlockRequest {
        request_id: request_id.to_string(),
        usage_scenario: CRED_UI_USAGE_SCENARIO.to_string(),
        totp_code,
    }
}

#[cfg(debug_assertions)]
fn print_json_pretty(response: &otpuac_core::ProviderUnlockResponse) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(response)?);
    Ok(())
}
