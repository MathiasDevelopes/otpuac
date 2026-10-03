//! Machine-scoped DPAPI on Windows. Other platforms only build OTPUAC for
//! tests and development, so there the "protection" is a labelled no-op that a
//! Windows build refuses to read.

#[cfg(windows)]
pub const SCHEME: &str = "windows-dpapi-local-machine";
#[cfg(not(windows))]
pub const SCHEME: &str = "insecure-dev-plaintext";

#[cfg(windows)]
pub use crate::win::{dpapi_protect as protect, dpapi_unprotect as unprotect};

#[cfg(not(windows))]
pub fn protect(plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    Ok(plaintext.to_vec())
}

#[cfg(not(windows))]
pub fn unprotect(ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
    Ok(ciphertext.to_vec())
}
