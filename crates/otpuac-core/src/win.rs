//! The few Win32 helpers the provider and setup share: UTF-16 strings,
//! `LocalFree`-owned memory, SDDL, and machine-scoped DPAPI.

use crate::error::{OtpuacError, Result};
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use zeroize::Zeroize;

pub fn wide_null(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(once(0)).collect()
}

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

/// Converts an SDDL string into a self-relative security descriptor, valid
/// until the returned value is dropped.
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

pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    let input = input_blob(plaintext);
    let mut output = empty_blob();
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(OtpuacError::Crypto("CryptProtectData failed".to_string()));
    }
    Ok(unsafe { take_output_blob(output, false) })
}

pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let input = input_blob(ciphertext);
    let mut output = empty_blob();
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(OtpuacError::Crypto("CryptUnprotectData failed".to_string()));
    }
    Ok(unsafe { take_output_blob(output, true) })
}

fn input_blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

fn empty_blob() -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    }
}

/// Copies a DPAPI output blob, optionally zeroizes it, then frees it.
///
/// # Safety
///
/// `blob` must be an output blob filled by a successful DPAPI call.
unsafe fn take_output_blob(blob: CRYPT_INTEGER_BLOB, zeroize: bool) -> Vec<u8> {
    let _allocation = LocalAllocPtr::from_raw(blob.pbData.cast());
    let slice = std::slice::from_raw_parts_mut(blob.pbData, blob.cbData as usize);
    let data = slice.to_vec();
    if zeroize {
        slice.zeroize();
    }
    data
}
