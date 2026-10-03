mod account;
mod registry;
mod security;

pub(crate) use account::{
    create_local_admin_account, delete_local_account, hide_local_account_from_sign_in,
    unhide_local_account_from_sign_in,
};
pub(crate) use security::secure_data_dir;

use windows_sys::Win32::Foundation::GetLastError;

fn win_error(function: &str, code: u32) -> otpuac_core::OtpuacError {
    otpuac_core::OtpuacError::Platform(format!("{function} failed with {code}"))
}

fn last_error(function: &str) -> otpuac_core::OtpuacError {
    win_error(function, unsafe { GetLastError() })
}
