#![cfg_attr(not(windows), allow(dead_code))]

use otpuac_core::{OtpuacError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RuntimeState {
    pub(crate) version: u32,
    pub(crate) last_accepted_totp_step: Option<u64>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RuntimeState {
    pub(crate) fn read_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new(None));
        }

        let bytes = fs::read(path)?;
        let state = serde_json::from_slice::<Self>(&bytes)?;
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn new(last_accepted_totp_step: Option<u64>) -> Self {
        Self {
            version: STATE_VERSION,
            last_accepted_totp_step,
        }
    }

    pub(crate) fn write_to_path(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION {
            return Err(OtpuacError::InvalidState(format!(
                "unsupported service state version {}",
                self.version
            )));
        }
        Ok(())
    }
}
