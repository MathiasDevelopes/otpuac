//! Replay and brute-force protection, kept on disk because every UAC prompt
//! runs in a fresh `consent.exe`.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// Failed attempts allowed within [`LOCKOUT_SECONDS`].
const MAX_FAILURES: usize = 5;
/// Five failures within this window lock the prompt until the oldest of them
/// is this old.
const LOCKOUT_SECONDS: u64 = 300;

#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Guard {
    /// The newest TOTP step that unlocked; it and older steps are spent.
    last_step: Option<u64>,
    /// Unix times of recent failed attempts.
    failures: Vec<u64>,
}

impl Guard {
    /// A missing file means nothing has been attempted yet.
    pub fn read(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        fs::write(path, serde_json::to_vec(self)?)?;
        Ok(())
    }

    pub fn is_locked(&mut self, now: u64) -> bool {
        self.failures
            .retain(|&at| now.saturating_sub(at) < LOCKOUT_SECONDS);
        self.failures.len() >= MAX_FAILURES
    }

    pub fn is_spent(&self, step: u64) -> bool {
        self.last_step.is_some_and(|last| step <= last)
    }

    pub fn record_failure(&mut self, now: u64) {
        self.failures.push(now);
    }

    pub fn record_success(&mut self, step: u64) {
        self.failures.clear();
        self.last_step = Some(self.last_step.map_or(step, |last| last.max(step)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_five_recent_failures_and_unlocks_when_they_age_out() {
        let mut guard = Guard::default();
        for at in 0..5 {
            assert!(!guard.is_locked(at));
            guard.record_failure(at);
        }

        assert!(guard.is_locked(10));
        assert!(guard.is_locked(LOCKOUT_SECONDS - 1));
        assert!(!guard.is_locked(LOCKOUT_SECONDS));
    }

    #[test]
    fn success_spends_its_step_and_clears_failures() {
        let mut guard = Guard::default();
        guard.record_failure(0);
        guard.record_success(10);

        assert!(guard.is_spent(10));
        assert!(guard.is_spent(9));
        assert!(!guard.is_spent(11));
        assert!(guard.failures.is_empty());
    }

    #[test]
    fn missing_file_is_a_fresh_guard() {
        let path = crate::vault::tests::tempdir().join("missing.json");
        assert_eq!(Guard::read(&path).unwrap(), Guard::default());
    }
}
