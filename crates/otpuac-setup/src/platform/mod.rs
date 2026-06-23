#[cfg(not(windows))]
use otpuac_core::Result;
#[cfg(not(windows))]
use std::path::Path;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(not(windows))]
const UNSUPPORTED_SETUP_PLATFORM: &str =
    "setup account and service management is only available on Windows";

#[cfg(not(windows))]
pub(crate) fn create_local_admin_account(_username: &str, _password: &str) -> Result<String> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn delete_local_account(_username: &str) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn hide_local_account_from_sign_in(_username: &str) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn unhide_local_account_from_sign_in(_username: &str) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn secure_program_data_dir(_path: &Path) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn register_event_log_source(_message_file: &Path) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn unregister_event_log_source() -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn install_or_replace_service(_service_exe: &Path) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn stop_and_delete_service() -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn register_provider(_provider_dll: &Path) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
pub(crate) fn unregister_provider(_provider_dll: &Path) -> Result<()> {
    unsupported()
}

#[cfg(not(windows))]
fn unsupported<T>() -> Result<T> {
    Err(otpuac_core::OtpuacError::UnsupportedPlatform(
        UNSUPPORTED_SETUP_PLATFORM,
    ))
}
