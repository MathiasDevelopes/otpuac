//! Rust Credential Provider implementation.
//!
//! The Windows COM implementation is isolated behind `cfg(windows)` so the
//! core TOTP and IPC logic remains buildable and testable on other platforms.

use otpuac_core::{ProviderUnlockRequest, CRED_UI_USAGE_SCENARIO};

pub const OTPUAC_PROVIDER_CLSID: &str = "{B6B6F0C2-4CCB-487E-9B58-681099865B10}";
pub const OTPUAC_USAGE_SCENARIO: &str = CRED_UI_USAGE_SCENARIO;

pub fn build_unlock_request(
    request_id: impl Into<String>,
    totp_code: impl Into<String>,
) -> ProviderUnlockRequest {
    ProviderUnlockRequest {
        request_id: request_id.into(),
        usage_scenario: OTPUAC_USAGE_SCENARIO.to_string(),
        totp_code: totp_code.into(),
    }
}

#[cfg(windows)]
mod windows_provider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uses_uac_credential_ui_scenario() {
        let request = build_unlock_request("req-1", "123456");

        assert_eq!(request.request_id, "req-1");
        assert_eq!(request.usage_scenario, OTPUAC_USAGE_SCENARIO);
        assert_eq!(request.totp_code, "123456");
    }
}
