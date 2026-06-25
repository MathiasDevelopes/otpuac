use crate::error::Result;

pub trait SecretProtector {
    fn scheme(&self) -> &'static str;
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
