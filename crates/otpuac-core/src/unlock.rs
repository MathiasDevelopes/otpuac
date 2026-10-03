//! The whole product: a valid, unused TOTP code releases the managed
//! administrator credential.

use crate::error::{OtpuacError, Result};
use crate::guard::Guard;
use crate::vault::{Credential, Vault};
use crate::{guard_path, totp, vault_path};
use std::path::Path;

/// Checks `code` against the vault in `data_dir` and, if it is valid and
/// unused, returns the managed credential. Every attempt is recorded in the
/// guard file first, so a failure to record it denies the attempt.
pub fn unlock(data_dir: &Path, code: &str, now: u64) -> Result<Credential> {
    let guard_path = guard_path(data_dir);
    let mut guard = Guard::read(&guard_path)?;
    if guard.is_locked(now) {
        return Err(OtpuacError::LockedOut);
    }

    let vault = Vault::read(&vault_path(data_dir))?;
    let step = totp::matching_step(&vault.totp_secret()?, code, now);

    let outcome = match step {
        Some(step) if guard.is_spent(step) => Err(OtpuacError::CodeReused),
        Some(step) => {
            guard.record_success(step);
            Ok(())
        }
        None => Err(OtpuacError::CodeRejected),
    };
    if outcome.is_err() {
        guard.record_failure(now);
    }
    guard.write(&guard_path)?;
    outcome?;

    vault.credential()
}

/// Checks `code` without spending it or touching the guard, for confirming an
/// authenticator enrollment.
pub fn verify(data_dir: &Path, code: &str, now: u64) -> Result<Vault> {
    let vault = Vault::read(&vault_path(data_dir))?;
    match totp::matching_step(&vault.totp_secret()?, code, now) {
        Some(_) => Ok(vault),
        None => Err(OtpuacError::CodeRejected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::code_at;
    use crate::vault::{tests::tempdir, ManagedAccount};

    const SECRET: &[u8] = b"12345678901234567890";
    const NOW: u64 = 1_700_000_000;

    fn provisioned_dir() -> std::path::PathBuf {
        let dir = tempdir();
        let account = ManagedAccount {
            username: "admin".to_string(),
            domain: None,
        };
        Vault::new(account, "hunter2", SECRET)
            .unwrap()
            .write(&vault_path(&dir))
            .unwrap();
        dir
    }

    #[test]
    fn valid_code_releases_the_credential_once() {
        let dir = provisioned_dir();
        let code = code_at(SECRET, NOW);

        let credential = unlock(&dir, &code, NOW).unwrap();
        assert_eq!(credential.password.as_str(), "hunter2");

        assert!(matches!(
            unlock(&dir, &code, NOW + 1),
            Err(OtpuacError::CodeReused)
        ));
    }

    #[test]
    fn wrong_codes_lock_out_even_the_right_one() {
        let dir = provisioned_dir();
        for _ in 0..5 {
            assert!(matches!(
                unlock(&dir, "000000", NOW),
                Err(OtpuacError::CodeRejected)
            ));
        }

        assert!(matches!(
            unlock(&dir, &code_at(SECRET, NOW), NOW),
            Err(OtpuacError::LockedOut)
        ));
    }

    #[test]
    fn verify_does_not_spend_the_code() {
        let dir = provisioned_dir();
        let code = code_at(SECRET, NOW);

        verify(&dir, &code, NOW).unwrap();
        verify(&dir, &code, NOW).unwrap();
        unlock(&dir, &code, NOW).unwrap();
    }

    #[test]
    fn missing_vault_is_an_error_not_a_denial() {
        let err = unlock(&tempdir(), "123456", NOW).unwrap_err();
        assert!(!err.is_denial());
    }
}
