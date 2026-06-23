use serde::{Deserialize, Serialize};
use std::mem::size_of;
use zeroize::Zeroize;

use crate::error::{OtpuacError, Result};

pub const PIPE_NAME: &str = r"\\.\pipe\OTPUAC";
pub const MAX_IPC_MESSAGE_BYTES: usize = 64 * 1024;
pub const CRED_UI_USAGE_SCENARIO: &str = "CPUS_CREDUI";
const FRAME_LENGTH_PREFIX_BYTES: usize = size_of::<u32>();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderUnlockRequest {
    pub request_id: String,
    pub usage_scenario: String,
    pub totp_code: String,
}

impl Drop for ProviderUnlockRequest {
    fn drop(&mut self) {
        self.totp_code.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderUnlockResponse {
    pub request_id: String,
    pub decision: UnlockDecision,
}

impl ProviderUnlockResponse {
    pub fn into_decision(mut self) -> UnlockDecision {
        std::mem::replace(
            &mut self.decision,
            UnlockDecision::Error {
                message: String::new(),
            },
        )
    }

    pub fn zeroize_secrets(&mut self) {
        if let UnlockDecision::Approved { password, .. } = &mut self.decision {
            password.zeroize();
        }
    }
}

impl Drop for ProviderUnlockResponse {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UnlockDecision {
    Approved {
        username: String,
        domain: Option<String>,
        password: String,
    },
    Denied {
        reason: UnlockFailureReason,
        message: String,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlockFailureReason {
    InvalidCode,
    RateLimited,
    ReplayDetected,
    UnsupportedUsageScenario,
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(OtpuacError::InvalidIpc(format!(
            "message is too large: {} bytes",
            payload.len()
        )));
    }

    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T> {
    if frame.len() < FRAME_LENGTH_PREFIX_BYTES {
        return Err(OtpuacError::InvalidIpc(
            "frame must include a four-byte length prefix".to_string(),
        ));
    }

    let (declared_len, payload) = split_frame(frame)?;
    let len = declared_len as usize;
    if len > MAX_IPC_MESSAGE_BYTES {
        return Err(OtpuacError::InvalidIpc(format!(
            "declared message is too large: {len} bytes"
        )));
    }
    if payload.len() != len {
        return Err(OtpuacError::InvalidIpc(format!(
            "declared message length {len} does not match frame payload length {}",
            payload.len()
        )));
    }

    serde_json::from_slice(payload).map_err(Into::into)
}

fn split_frame(frame: &[u8]) -> Result<(u32, &[u8])> {
    let (prefix, payload) = frame.split_at(FRAME_LENGTH_PREFIX_BYTES);
    let len = u32::from_le_bytes(prefix.try_into().map_err(|_| {
        OtpuacError::InvalidIpc("frame length prefix must be four bytes".to_string())
    })?);
    Ok((len, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_frame_round_trips() {
        let request = ProviderUnlockRequest {
            request_id: "req".to_string(),
            usage_scenario: CRED_UI_USAGE_SCENARIO.to_string(),
            totp_code: "123456".to_string(),
        };

        let frame = encode_frame(&request).unwrap();
        let decoded = decode_frame::<ProviderUnlockRequest>(&frame).unwrap();

        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.usage_scenario, request.usage_scenario);
        assert_eq!(decoded.totp_code, request.totp_code);
    }
}
