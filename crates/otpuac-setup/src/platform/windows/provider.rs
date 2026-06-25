use super::error::{last_error, win_error};
use otpuac_core::Result;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

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
        return Err(otpuac_core::OtpuacError::InvalidVault(format!(
            "regsvr32 failed for {} with {status}",
            provider_dll.display()
        )));
    }
    Ok(())
}

fn system32_exe(name: &str) -> Result<PathBuf> {
    Ok(system32_dir()?.join(name))
}

fn system32_dir() -> Result<PathBuf> {
    let mut buf = vec![0_u16; 32768];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return Err(last_error("GetSystemDirectoryW"));
    }
    if len as usize > buf.len() {
        return Err(win_error("GetSystemDirectoryW", ERROR_INSUFFICIENT_BUFFER));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}
