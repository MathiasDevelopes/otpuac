use crate::audit;
use otpuac_core::{
    now_unix, ProviderUnlockRequest, ProviderUnlockResponse, Result, UnlockDecision,
    UnlockFailureReason, VaultFile, CRED_UI_USAGE_SCENARIO,
};
use otpuac_runtime::default_protector;
use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, SystemTime};

const MAX_FAILURES: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const LOCKOUT_DURATION: Duration = Duration::from_secs(300);
const REDACTED_PASSWORD: &str = "<redacted>";

#[cfg(debug_assertions)]
pub(crate) fn redact_response(mut response: ProviderUnlockResponse) -> ProviderUnlockResponse {
    if let UnlockDecision::Approved { password, .. } = &mut response.decision {
        *password = REDACTED_PASSWORD.to_string();
    }
    response
}

pub(crate) struct RateLimiter {
    failures: VecDeque<SystemTime>,
    max_failures: usize,
    window: Duration,
    lockout: Duration,
    lockout_until: Option<SystemTime>,
    last_accepted_step: Option<u64>,
}

impl RateLimiter {
    #[cfg(any(debug_assertions, test))]
    pub(crate) fn new() -> Self {
        Self::with_last_accepted_step(None)
    }

    pub(crate) fn with_last_accepted_step(last_accepted_step: Option<u64>) -> Self {
        Self::with_policy(
            MAX_FAILURES,
            FAILURE_WINDOW,
            LOCKOUT_DURATION,
            last_accepted_step,
        )
    }

    fn with_policy(
        max_failures: usize,
        window: Duration,
        lockout: Duration,
        last_accepted_step: Option<u64>,
    ) -> Self {
        Self {
            failures: VecDeque::new(),
            max_failures,
            window,
            lockout,
            lockout_until: None,
            last_accepted_step,
        }
    }

    fn is_limited(&mut self, now: SystemTime) -> bool {
        if let Some(until) = self.lockout_until {
            if now < until {
                return true;
            }
            self.lockout_until = None;
            self.failures.clear();
        }

        self.prune(now);
        self.failures.len() >= self.max_failures
    }

    fn record_failure(&mut self, now: SystemTime) {
        self.failures.push_back(now);
        self.prune(now);
        if self.failures.len() >= self.max_failures {
            self.lockout_until = Some(now + self.lockout);
        }
    }

    fn record_success(&mut self, accepted_step: u64) {
        self.failures.clear();
        self.lockout_until = None;
        self.last_accepted_step = Some(
            self.last_accepted_step
                .map(|last_step| last_step.max(accepted_step))
                .unwrap_or(accepted_step),
        );
    }

    fn is_replay(&self, accepted_step: u64) -> bool {
        self.last_accepted_step
            .map(|last_step| accepted_step <= last_step)
            .unwrap_or(false)
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn last_accepted_step(&self) -> Option<u64> {
        self.last_accepted_step
    }

    fn prune(&mut self, now: SystemTime) {
        while let Some(front) = self.failures.front() {
            if failure_expired(now, *front, self.window) {
                self.failures.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(debug_assertions)]
pub(crate) fn handle_unlock_request(
    vault_path: &Path,
    request: ProviderUnlockRequest,
    emit_secret: bool,
) -> Result<ProviderUnlockResponse> {
    let mut rate_limiter = RateLimiter::new();
    handle_unlock_request_with_limiter(vault_path, request, emit_secret, &mut rate_limiter)
}

pub(crate) fn handle_unlock_request_with_limiter(
    vault_path: &Path,
    request: ProviderUnlockRequest,
    emit_secret: bool,
    rate_limiter: &mut RateLimiter,
) -> Result<ProviderUnlockResponse> {
    let request_id = request.request_id.clone();
    if request.usage_scenario != CRED_UI_USAGE_SCENARIO {
        audit::unlock_rejected(&request_id, "unsupported usage scenario");
        return Ok(unsupported_usage_response(request_id));
    }

    let now = SystemTime::now();
    if rate_limiter.is_limited(now) {
        audit::unlock_rate_limited(&request_id);
        return Ok(rate_limited_response(request_id));
    }

    let protector = default_protector();
    let vault = match VaultFile::read_from_path(vault_path) {
        Ok(vault) => vault,
        Err(err) => {
            audit::vault_error(&request_id, err.to_string());
            return Ok(unlock_error_response(request_id));
        }
    };
    let step = match vault.accepted_totp_step(&request.totp_code, now_unix(), &protector) {
        Ok(step) => step,
        Err(otpuac_core::OtpuacError::InvalidTotpCode | otpuac_core::OtpuacError::TotpRejected) => {
            rate_limiter.record_failure(now);
            audit::unlock_rejected(&request_id, "invalid TOTP code");
            return Ok(invalid_code_response(request_id));
        }
        Err(err) => {
            audit::vault_error(&request_id, err.to_string());
            return Ok(unlock_error_response(request_id));
        }
    };

    if rate_limiter.is_replay(step) {
        rate_limiter.record_failure(now);
        audit::unlock_rejected(&request_id, "replayed TOTP code");
        return Ok(replay_detected_response(request_id));
    }

    let credential = match vault.release_credential(&protector) {
        Ok(credential) => credential,
        Err(err) => {
            audit::vault_error(&request_id, err.to_string());
            return Ok(unlock_error_response(request_id));
        }
    };
    rate_limiter.record_success(step);
    audit::unlock_accepted(&request_id, &credential.account.label());
    Ok(approved_response(request_id, credential, emit_secret))
}

fn unlock_error_response(request_id: String) -> ProviderUnlockResponse {
    ProviderUnlockResponse {
        request_id,
        decision: UnlockDecision::Error {
            message: "OTPUAC could not unlock the managed credential".to_string(),
        },
    }
}

fn denied_response(
    request_id: String,
    reason: UnlockFailureReason,
    message: &'static str,
) -> ProviderUnlockResponse {
    ProviderUnlockResponse {
        request_id,
        decision: UnlockDecision::Denied {
            reason,
            message: message.to_string(),
        },
    }
}

fn unsupported_usage_response(request_id: String) -> ProviderUnlockResponse {
    denied_response(
        request_id,
        UnlockFailureReason::UnsupportedUsageScenario,
        "OTPUAC only supports UAC Credential UI requests",
    )
}

fn rate_limited_response(request_id: String) -> ProviderUnlockResponse {
    denied_response(
        request_id,
        UnlockFailureReason::RateLimited,
        "Too many failed attempts; wait before trying again",
    )
}

fn invalid_code_response(request_id: String) -> ProviderUnlockResponse {
    denied_response(
        request_id,
        UnlockFailureReason::InvalidCode,
        "TOTP code was rejected",
    )
}

fn replay_detected_response(request_id: String) -> ProviderUnlockResponse {
    denied_response(
        request_id,
        UnlockFailureReason::ReplayDetected,
        "This TOTP code was already used",
    )
}

fn approved_response(
    request_id: String,
    mut credential: otpuac_core::ReleasedCredential,
    emit_secret: bool,
) -> ProviderUnlockResponse {
    let password = if emit_secret {
        std::mem::take(&mut credential.password)
    } else {
        REDACTED_PASSWORD.to_string()
    };
    let account = credential.account.clone();

    ProviderUnlockResponse {
        request_id,
        decision: UnlockDecision::Approved {
            username: account.username,
            domain: account.domain,
            password,
        },
    }
}

fn failure_expired(now: SystemTime, failure: SystemTime, window: Duration) -> bool {
    now.duration_since(failure)
        .map(|age| age > window)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_after_configured_failures() {
        let mut limiter =
            RateLimiter::with_policy(2, Duration::from_secs(60), Duration::from_secs(300), None);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        assert!(!limiter.is_limited(now));
        limiter.record_failure(now);
        assert!(!limiter.is_limited(now));
        limiter.record_failure(now);
        assert!(limiter.is_limited(now));
    }

    #[test]
    fn rate_limiter_expires_old_failures() {
        let mut limiter =
            RateLimiter::with_policy(1, Duration::from_secs(60), Duration::from_secs(1), None);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        limiter.record_failure(now);
        assert!(limiter.is_limited(now));
        assert!(!limiter.is_limited(now + Duration::from_secs(2)));
    }

    #[test]
    fn rate_limiter_rejects_replayed_totp_steps() {
        let mut limiter = RateLimiter::new();

        assert!(!limiter.is_replay(10));
        limiter.record_success(10);

        assert!(limiter.is_replay(10));
        assert!(limiter.is_replay(9));
        assert!(!limiter.is_replay(11));
    }
}
