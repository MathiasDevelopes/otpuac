use crate::error::{OtpuacError, Result};
use crate::protect::SecretProtector;
use crate::time::now_unix;
use crate::totp::{accepted_step_at, encode_totp_secret, TotpPolicy};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const VAULT_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedAccount {
    pub username: String,
    pub domain: Option<String>,
}

impl ManagedAccount {
    pub fn label(&self) -> String {
        match self.domain.as_deref() {
            Some(domain) if !domain.trim().is_empty() => format!("{domain}\\{}", self.username),
            _ => self.username.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultFile {
    pub version: u32,
    pub account: ManagedAccount,
    pub password: ProtectedBlob,
    pub totp_secret: ProtectedBlob,
    pub totp_policy: TotpPolicy,
    pub created_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProtectedBlob {
    pub scheme: String,
    pub data_base64: String,
}

#[derive(Debug)]
pub struct ReleasedCredential {
    pub account: ManagedAccount,
    pub password: String,
}

impl Drop for ReleasedCredential {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl VaultFile {
    pub fn new(
        account: ManagedAccount,
        password: &str,
        totp_secret: &[u8],
        totp_policy: TotpPolicy,
        protector: &impl SecretProtector,
    ) -> Result<Self> {
        validate_account(&account)?;
        totp_policy.validate()?;

        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
        let totp_bytes = Zeroizing::new(totp_secret.to_vec());

        Ok(Self {
            version: VAULT_VERSION,
            account,
            password: protect_blob(protector, &password_bytes)?,
            totp_secret: protect_blob(protector, &totp_bytes)?,
            totp_policy,
            created_at_unix: now_unix(),
        })
    }

    pub fn read_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path)?;
        let vault = serde_json::from_slice::<Self>(&bytes)?;
        vault.validate()?;
        Ok(vault)
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != VAULT_VERSION {
            return Err(OtpuacError::InvalidVault(format!(
                "unsupported version {}",
                self.version
            )));
        }
        validate_account(&self.account)?;
        self.totp_policy.validate()?;
        if self.has_empty_secret_blob() {
            return Err(OtpuacError::InvalidVault(
                "protected secret blobs must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    pub fn encoded_totp_secret(&self, protector: &impl SecretProtector) -> Result<String> {
        let secret = unprotect_blob(protector, &self.totp_secret)?;
        Ok(encode_totp_secret(&secret))
    }

    pub fn unlock(
        &self,
        code: &str,
        unix_time: u64,
        protector: &impl SecretProtector,
    ) -> Result<ReleasedCredential> {
        self.unlock_with_step(code, unix_time, protector)
            .map(|(credential, _step)| credential)
    }

    pub fn unlock_with_step(
        &self,
        code: &str,
        unix_time: u64,
        protector: &impl SecretProtector,
    ) -> Result<(ReleasedCredential, u64)> {
        let step = self.accepted_totp_step(code, unix_time, protector)?;
        let credential = self.release_credential(protector)?;
        Ok((credential, step))
    }

    pub fn accepted_totp_step(
        &self,
        code: &str,
        unix_time: u64,
        protector: &impl SecretProtector,
    ) -> Result<u64> {
        self.validate()?;
        let totp_secret = unprotect_blob(protector, &self.totp_secret)?;
        accepted_step_at(&totp_secret, &self.totp_policy, code, unix_time)?
            .ok_or(OtpuacError::TotpRejected)
    }

    pub fn release_credential(
        &self,
        protector: &impl SecretProtector,
    ) -> Result<ReleasedCredential> {
        self.validate()?;
        let password = zeroizing_utf8(unprotect_blob(protector, &self.password)?)?;

        Ok(ReleasedCredential {
            account: self.account.clone(),
            password,
        })
    }

    fn has_empty_secret_blob(&self) -> bool {
        self.password.is_empty() || self.totp_secret.is_empty()
    }
}

fn validate_account(account: &ManagedAccount) -> Result<()> {
    if account.username.trim().is_empty() {
        return Err(OtpuacError::InvalidVault(
            "managed account username is required".to_string(),
        ));
    }
    Ok(())
}

fn protect_blob(protector: &impl SecretProtector, plaintext: &[u8]) -> Result<ProtectedBlob> {
    let protected = protector.protect(plaintext)?;
    Ok(ProtectedBlob {
        scheme: protector.scheme().to_string(),
        data_base64: BASE64.encode(protected),
    })
}

fn unprotect_blob(
    protector: &impl SecretProtector,
    protected_blob: &ProtectedBlob,
) -> Result<Zeroizing<Vec<u8>>> {
    if protected_blob.scheme != protector.scheme() {
        return Err(OtpuacError::SchemeMismatch {
            expected: protector.scheme().to_string(),
            actual: protected_blob.scheme.clone(),
        });
    }
    let ciphertext = BASE64.decode(&protected_blob.data_base64)?;
    protector.unprotect(&ciphertext).map(Zeroizing::new)
}

impl ProtectedBlob {
    fn is_empty(&self) -> bool {
        self.data_base64.is_empty()
    }
}

fn zeroizing_utf8(mut bytes: Zeroizing<Vec<u8>>) -> Result<String> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(password) => Ok(password),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(OtpuacError::InvalidVault(
                "password is not valid UTF-8".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::code_at;

    #[derive(Clone, Copy, Debug)]
    struct TestProtector;

    impl SecretProtector for TestProtector {
        fn scheme(&self) -> &'static str {
            "test-plaintext"
        }

        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(plaintext.to_vec())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            Ok(ciphertext.to_vec())
        }
    }

    #[test]
    fn vault_unlocks_with_valid_totp() {
        let protector = TestProtector;
        let policy = TotpPolicy::default();
        let secret = b"12345678901234567890";
        let vault = VaultFile::new(
            ManagedAccount {
                username: "admin".to_string(),
                domain: Some("TESTPC".to_string()),
            },
            "correct horse battery staple",
            secret,
            policy.clone(),
            &protector,
        )
        .unwrap();
        let code = code_at(secret, &policy, 1_700_000_000).unwrap();

        let credential = vault.unlock(&code, 1_700_000_000, &protector).unwrap();

        assert_eq!(credential.account.label(), "TESTPC\\admin");
        assert_eq!(credential.password, "correct horse battery staple");
    }

    #[test]
    fn vault_rejects_invalid_totp() {
        let protector = TestProtector;
        let policy = TotpPolicy::default();
        let secret = b"12345678901234567890";
        let vault = VaultFile::new(
            ManagedAccount {
                username: "admin".to_string(),
                domain: None,
            },
            "password",
            secret,
            policy,
            &protector,
        )
        .unwrap();

        assert!(matches!(
            vault.unlock("000000", 1_700_000_000, &protector),
            Err(OtpuacError::TotpRejected)
        ));
    }
}
