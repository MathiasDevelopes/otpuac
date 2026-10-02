use crate::system::LocalAllocPtr;
use otpuac_core::{OtpuacError, Result, SecretProtector};
use std::ptr;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Default)]
pub struct DpapiProtector;

impl SecretProtector for DpapiProtector {
    fn scheme(&self) -> &'static str {
        "windows-dpapi-local-machine"
    }

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        dpapi_protect(plaintext)
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        dpapi_unprotect(ciphertext)
    }
}

fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
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

fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
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
