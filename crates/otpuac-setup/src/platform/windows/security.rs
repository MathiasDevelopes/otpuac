use super::error::{last_error, win_error};
use otpuac_core::Result;
use otpuac_windows::system::security_descriptor_from_sddl;
use otpuac_windows::wide::wide_null_os;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};

pub(crate) fn secure_program_data_dir(path: &Path) -> Result<()> {
    let path_w = wide_null_os(path.as_os_str());
    let descriptor = security_descriptor_from_sddl("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .map_err(|code| win_error("ConvertStringSecurityDescriptorToSecurityDescriptorW", code))?;

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if ok == 0 || dacl_present == 0 || dacl.is_null() {
        return Err(last_error("GetSecurityDescriptorDacl"));
    }

    let status = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(win_error("SetNamedSecurityInfoW", status));
    }
    Ok(())
}
