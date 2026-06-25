use windows_sys::Win32::Foundation::GetLastError;

pub(super) fn win_error(function: &str, code: u32) -> otpuac_core::OtpuacError {
    otpuac_core::OtpuacError::InvalidVault(format!("{function} failed with {code}"))
}

pub(super) fn last_error(function: &str) -> otpuac_core::OtpuacError {
    win_error(function, unsafe { GetLastError() })
}
