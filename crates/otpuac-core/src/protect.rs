#[cfg(windows)]
use crate::error::OtpuacError;
use crate::error::Result;

pub trait SecretProtector {
    fn scheme(&self) -> &'static str;
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(windows)]
pub fn default_protector() -> DpapiProtector {
    DpapiProtector
}

#[cfg(not(windows))]
pub fn default_protector() -> InsecureDevProtector {
    InsecureDevProtector
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InsecureDevProtector;

#[cfg(not(windows))]
impl SecretProtector for InsecureDevProtector {
    fn scheme(&self) -> &'static str {
        "insecure-dev-plaintext"
    }

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DpapiProtector;

#[cfg(windows)]
impl SecretProtector for DpapiProtector {
    fn scheme(&self) -> &'static str {
        "windows-dpapi-local-machine"
    }

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        dpapi_protect(plaintext, true)
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        dpapi_unprotect(ciphertext)
    }
}

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8], local_machine: bool) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let flags = if local_machine {
        CRYPTPROTECT_LOCAL_MACHINE
    } else {
        0
    };

    let ok = unsafe {
        CryptProtectData(
            &mut input,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
            &mut output,
        )
    };

    if ok == 0 {
        return Err(OtpuacError::Crypto("CryptProtectData failed".to_string()));
    }

    let protected = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let protected = slice.to_vec();
        LocalFree(output.pbData.cast());
        protected
    };

    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
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

    let plaintext = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let plaintext = slice.to_vec();
        LocalFree(output.pbData.cast());
        plaintext
    };

    Ok(plaintext)
}
