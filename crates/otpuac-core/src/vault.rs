use crate::error::{OtpuacError, Result};
use crate::protect;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Unchanged since 1.0, so vaults from earlier installs still load. Fields
/// those versions also wrote (TOTP policy, timestamps) are ignored.
const VAULT_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedAccount {
    pub username: String,
    pub domain: Option<String>,
}

impl ManagedAccount {
    /// `DOMAIN\user`, or `user` without a domain.
    pub fn label(&self) -> String {
        match self.domain.as_deref() {
            Some(domain) if !domain.trim().is_empty() => format!("{domain}\\{}", self.username),
            _ => self.username.clone(),
        }
    }
}

/// The managed administrator and the TOTP secret that unlocks it.
#[derive(Debug, Deserialize, Serialize)]
pub struct Vault {
    version: u32,
    pub account: ManagedAccount,
    password: Protected,
    totp_secret: Protected,
    /// Setup created the account, so uninstall may delete it.
    #[serde(default)]
    pub created_account: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Protected {
    scheme: String,
    data_base64: String,
}

/// The managed administrator's password, wiped when dropped.
pub struct Credential {
    pub account: ManagedAccount,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Vault {
    pub fn new(account: ManagedAccount, password: &str, totp_secret: &[u8]) -> Result<Self> {
        if account.username.trim().is_empty() {
            return Err(OtpuacError::InvalidVault(
                "managed account username is required".to_string(),
            ));
        }
        Ok(Self {
            version: VAULT_VERSION,
            account,
            password: Protected::seal(password.as_bytes())?,
            totp_secret: Protected::seal(totp_secret)?,
            created_account: false,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let vault: Self = serde_json::from_slice(&fs::read(path)?)?;
        if vault.version != VAULT_VERSION {
            return Err(OtpuacError::InvalidVault(format!(
                "unsupported version {}",
                vault.version
            )));
        }
        Ok(vault)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn totp_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.totp_secret.open()
    }

    pub fn credential(&self) -> Result<Credential> {
        let password =
            String::from_utf8(std::mem::take(&mut *self.password.open()?)).map_err(|err| {
                err.into_bytes().zeroize();
                OtpuacError::InvalidVault("password is not valid UTF-8".to_string())
            })?;
        Ok(Credential {
            account: self.account.clone(),
            password: Zeroizing::new(password),
        })
    }
}

impl Protected {
    fn seal(plaintext: &[u8]) -> Result<Self> {
        Ok(Self {
            scheme: protect::SCHEME.to_string(),
            data_base64: BASE64.encode(&protect::protect(plaintext)?),
        })
    }

    fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.scheme != protect::SCHEME {
            return Err(OtpuacError::InvalidVault(format!(
                "secret is protected with {}, expected {}",
                self.scheme,
                protect::SCHEME
            )));
        }
        let ciphertext = BASE64.decode(self.data_base64.as_bytes())?;
        protect::unprotect(&ciphertext).map(Zeroizing::new)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn round_trips_account_password_and_secret() {
        let dir = tempdir();
        let path = dir.join("vault.json");
        let account = ManagedAccount {
            username: "admin".to_string(),
            domain: Some("PC".to_string()),
        };
        Vault::new(account.clone(), "hunter2", b"secret")
            .unwrap()
            .write(&path)
            .unwrap();

        let vault = Vault::read(&path).unwrap();
        let credential = vault.credential().unwrap();

        assert_eq!(credential.account, account);
        assert_eq!(credential.account.label(), r"PC\admin");
        assert_eq!(credential.password.as_str(), "hunter2");
        assert_eq!(&**vault.totp_secret().unwrap(), b"secret");
    }

    #[test]
    fn reads_vaults_written_by_earlier_versions() {
        let dir = tempdir();
        let path = dir.join("vault.json");
        let blob = |plain: &str| {
            format!(
                r#"{{"scheme":"{}","data_base64":"{}"}}"#,
                protect::SCHEME,
                BASE64.encode(plain.as_bytes())
            )
        };
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"account":{{"username":"admin","domain":null}},
                "password":{},"totp_secret":{},
                "totp_policy":{{"digits":6,"step_seconds":30,"skew_steps":1,"issuer":"OTPUAC"}},
                "created_at_unix":1700000000}}"#,
                blob("pw"),
                blob("key")
            ),
        )
        .unwrap();

        let vault = Vault::read(&path).unwrap();

        assert_eq!(vault.credential().unwrap().password.as_str(), "pw");
        assert_eq!(&**vault.totp_secret().unwrap(), b"key");
    }

    pub(crate) fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "otpuac-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
