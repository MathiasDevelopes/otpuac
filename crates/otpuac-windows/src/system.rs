//! Small Win32 wrappers shared by the OTPUAC service and setup helpers.
//!
//! Failures are reported as raw Win32 error codes so each caller keeps its
//! own error variant and message.

use crate::wide::wide_null;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

/// Owns memory returned by a Win32 API that must be released with `LocalFree`.
pub struct LocalAllocPtr(*mut core::ffi::c_void);

impl LocalAllocPtr {
    /// # Safety
    ///
    /// `ptr` must be null or a `LocalAlloc` allocation that nothing else frees.
    pub unsafe fn from_raw(ptr: *mut core::ffi::c_void) -> Self {
        Self(ptr)
    }

    pub fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0
    }
}

impl Drop for LocalAllocPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Returns the Windows system directory, usually `C:\Windows\System32`.
pub fn system32_dir() -> std::result::Result<PathBuf, u32> {
    let mut buf = vec![0_u16; 32768];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return Err(unsafe { GetLastError() });
    }
    if len as usize > buf.len() {
        return Err(ERROR_INSUFFICIENT_BUFFER);
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// Converts an SDDL string into a self-relative security descriptor.
///
/// The descriptor is `LocalAllocPtr::as_ptr` of the returned value and stays
/// valid until that value is dropped.
pub fn security_descriptor_from_sddl(sddl: &str) -> std::result::Result<LocalAllocPtr, u32> {
    let sddl = wide_null(sddl);
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
        return Err(unsafe { GetLastError() });
    }
    Ok(unsafe { LocalAllocPtr::from_raw(descriptor) })
}
