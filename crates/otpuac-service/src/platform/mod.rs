use otpuac_core::Result;
#[cfg(debug_assertions)]
use otpuac_core::{ProviderUnlockRequest, ProviderUnlockResponse};
use std::path::Path;

#[cfg(windows)]
mod windows_ipc;
#[cfg(windows)]
mod windows_service_host;

#[cfg(all(not(windows), debug_assertions))]
const UNSUPPORTED_PIPE_SERVER: &str = "named-pipe server is only available on Windows";
#[cfg(all(not(windows), debug_assertions))]
const UNSUPPORTED_PIPE_CLIENT: &str = "named-pipe client is only available on Windows";
#[cfg(not(windows))]
const UNSUPPORTED_SERVICE_MODE: &str = "Windows service mode is only available on Windows";

#[cfg(all(windows, debug_assertions))]
pub(crate) fn serve_foreground(vault_path: &Path) -> Result<()> {
    windows_ipc::serve_pipe(vault_path, || false, windows_ipc::ClientPolicy::AllowAny)
}

#[cfg(all(windows, debug_assertions))]
pub(crate) fn pipe_check(request: ProviderUnlockRequest) -> Result<ProviderUnlockResponse> {
    windows_ipc::pipe_round_trip(request)
}

#[cfg(all(not(windows), debug_assertions))]
pub(crate) fn serve_foreground(_vault_path: &Path) -> Result<()> {
    unsupported(UNSUPPORTED_PIPE_SERVER)
}

#[cfg(all(not(windows), debug_assertions))]
pub(crate) fn pipe_check(_request: ProviderUnlockRequest) -> Result<ProviderUnlockResponse> {
    unsupported(UNSUPPORTED_PIPE_CLIENT)
}

#[cfg(windows)]
pub(crate) fn run_service(_vault_path: &Path) -> Result<()> {
    windows_service_host::run()
}

#[cfg(not(windows))]
pub(crate) fn run_service(_vault_path: &Path) -> Result<()> {
    unsupported(UNSUPPORTED_SERVICE_MODE)
}

#[cfg(not(windows))]
fn unsupported<T>(message: &'static str) -> Result<T> {
    Err(otpuac_core::OtpuacError::UnsupportedPlatform(message))
}
