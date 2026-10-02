use super::error::win_error;
use otpuac_core::Result;
use otpuac_windows::system::system32_dir;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn register_provider(provider_dll: &Path) -> Result<()> {
    run_regsvr32(provider_dll, false)
}

pub(crate) fn unregister_provider(provider_dll: &Path) -> Result<()> {
    run_regsvr32(provider_dll, true)
}

fn run_regsvr32(provider_dll: &Path, unregister: bool) -> Result<()> {
    let mut command = Command::new(system32_exe("regsvr32.exe")?);
    if unregister {
        command.arg("/u");
    }
    let status = command.arg("/s").arg(provider_dll).status()?;
    if !status.success() {
        return Err(otpuac_core::OtpuacError::Platform(format!(
            "regsvr32 failed for {} with {status}",
            provider_dll.display()
        )));
    }
    Ok(())
}

fn system32_exe(name: &str) -> Result<PathBuf> {
    let system32 = system32_dir().map_err(|code| win_error("GetSystemDirectoryW", code))?;
    Ok(system32.join(name))
}
