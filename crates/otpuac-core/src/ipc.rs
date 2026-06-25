use serde::{Deserialize, Serialize};
use std::fmt;
use std::mem::size_of;
use zeroize::Zeroize;

use crate::error::{OtpuacError, Result};

pub const PIPE_NAME: &str = r"\\.\pipe\OTPUAC";
pub const MAX_IPC_MESSAGE_BYTES: usize = 64 * 1024;
pub const CRED_UI_USAGE_SCENARIO: &str = "CPUS_CREDUI";
const FRAME_LENGTH_PREFIX_BYTES: usize = size_of::<u32>();

#[derive(Clone, Deserialize, Serialize)]
pub struct ProviderUnlockRequest {
    pub request_id: String,
    pub usage_scenario: String,
    pub totp_code: String,
}

impl fmt::Debug for ProviderUnlockRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderUnlockRequest")
            .field("request_id", &self.request_id)
            .field("usage_scenario", &self.usage_scenario)
            .field("totp_code", &"<redacted>")
            .finish()
    }
}

impl ProviderUnlockRequest {
    pub fn credential_ui(request_id: impl Into<String>, totp_code: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            usage_scenario: CRED_UI_USAGE_SCENARIO.to_string(),
            totp_code: totp_code.into(),
        }
    }
}

impl Drop for ProviderUnlockRequest {
    fn drop(&mut self) {
        self.totp_code.zeroize();
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ProviderUnlockResponse {
    pub request_id: String,
    pub decision: UnlockDecision,
}

impl fmt::Debug for ProviderUnlockResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderUnlockResponse")
            .field("request_id", &self.request_id)
            .field("decision", &self.decision)
            .finish()
    }
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

#[derive(Clone, Deserialize, Serialize)]
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

impl fmt::Debug for UnlockDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved {
                username, domain, ..
            } => f
                .debug_struct("Approved")
                .field("username", username)
                .field("domain", domain)
                .field("password", &"<redacted>")
                .finish(),
            Self::Denied { reason, message } => f
                .debug_struct("Denied")
                .field("reason", reason)
                .field("message", message)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
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
    let mut payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_IPC_MESSAGE_BYTES {
        let len = payload.len();
        payload.zeroize();
        return Err(OtpuacError::InvalidIpc(format!(
            "message is too large: {len} bytes"
        )));
    }

    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    payload.zeroize();
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
        let request = ProviderUnlockRequest::credential_ui("req", "123456");

        let frame = encode_frame(&request).unwrap();
        let decoded = decode_frame::<ProviderUnlockRequest>(&frame).unwrap();

        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.usage_scenario, request.usage_scenario);
        assert_eq!(decoded.totp_code, request.totp_code);
    }

    #[test]
    fn debug_output_redacts_ipc_secrets() {
        let request = ProviderUnlockRequest::credential_ui("req", "123456");
        let response = ProviderUnlockResponse {
            request_id: "req".to_string(),
            decision: UnlockDecision::Approved {
                username: "admin".to_string(),
                domain: None,
                password: "correct horse battery staple".to_string(),
            },
        };

        let debug = format!("{request:?} {response:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("123456"));
        assert!(!debug.contains("correct horse battery staple"));
    }

    #[test]
    fn credential_ui_request_uses_shared_scenario() {
        let request = ProviderUnlockRequest::credential_ui("req", "123456");

        assert_eq!(request.request_id, "req");
        assert_eq!(request.usage_scenario, CRED_UI_USAGE_SCENARIO);
        assert_eq!(request.totp_code, "123456");
    }
}
