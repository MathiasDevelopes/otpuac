mod audit;
mod cli;
mod platform;
mod state;
mod unlock;

use clap::Parser;
use cli::{Cli, Command};
use otpuac_core::{
    paths::default_vault_path, ProviderUnlockRequest, Result, CRED_UI_USAGE_SCENARIO,
};
use platform::{pipe_check, run_service, serve_foreground};
use unlock::{handle_unlock_request, redact_response};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(default_vault_path);

    match cli.command {
        Command::Check { code } => {
            let request = credential_ui_request("debug-check", code);
            let response = handle_unlock_request(&vault_path, request, false)?;
            print_json_pretty(&response)?;
        }
        Command::PipeCheck { code } => {
            let request = credential_ui_request("pipe-check", code);
            let response = pipe_check(request)?;
            print_json_pretty(&redact_response(response))?;
        }
        Command::ServeForeground => serve_foreground(&vault_path)?,
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

fn credential_ui_request(request_id: &str, totp_code: String) -> ProviderUnlockRequest {
    ProviderUnlockRequest {
        request_id: request_id.to_string(),
        usage_scenario: CRED_UI_USAGE_SCENARIO.to_string(),
        totp_code,
    }
}

fn print_json_pretty(response: &otpuac_core::ProviderUnlockResponse) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(response)?);
    Ok(())
}
