#[cfg(all(not(windows), not(debug_assertions)))]
use otpuac_core::OtpuacError;
use otpuac_core::{Result, SecretProtector};

#[cfg(windows)]
pub fn default_protector() -> otpuac_windows::protect::DpapiProtector {
    otpuac_windows::protect::DpapiProtector
}

#[cfg(all(not(windows), debug_assertions))]
pub fn default_protector() -> InsecureDevProtector {
    InsecureDevProtector
}

#[cfg(all(not(windows), not(debug_assertions)))]
pub fn default_protector() -> UnsupportedProtector {
    UnsupportedProtector
}

#[cfg(all(not(windows), debug_assertions))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InsecureDevProtector;

#[cfg(all(not(windows), debug_assertions))]
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

#[cfg(all(not(windows), not(debug_assertions)))]
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedProtector;

#[cfg(all(not(windows), not(debug_assertions)))]
impl SecretProtector for UnsupportedProtector {
    fn scheme(&self) -> &'static str {
        "unsupported"
    }

    fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(OtpuacError::UnsupportedPlatform(
            "secret protection is only available in Windows release builds",
        ))
    }

    fn unprotect(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(OtpuacError::UnsupportedPlatform(
            "secret protection is only available in Windows release builds",
        ))
    }
}
