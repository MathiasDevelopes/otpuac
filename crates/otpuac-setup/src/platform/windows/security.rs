use super::error::{last_error, win_error};
use super::local_alloc::LocalAllocPtr;
use otpuac_core::Result;
use otpuac_windows_support::wide::{wide_null, wide_null_os};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

pub(crate) fn secure_program_data_dir(path: &Path) -> Result<()> {
    let path_w = wide_null_os(path.as_os_str());
    let sddl = wide_null("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    let _descriptor = LocalAllocPtr(descriptor);

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
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
