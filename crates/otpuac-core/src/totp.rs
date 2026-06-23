use crate::error::{OtpuacError, Result};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha1 = Hmac<Sha1>;

const DEFAULT_DIGITS: u32 = 6;
const MIN_DIGITS: u32 = 6;
const MAX_DIGITS: u32 = 8;
const DEFAULT_STEP_SECONDS: u64 = 30;
const DEFAULT_SKEW_STEPS: u8 = 1;
const MAX_SKEW_STEPS: u8 = 2;
const DEFAULT_ISSUER: &str = "OTPUAC";
const TOTP_SECRET_BYTES: usize = 20;
const SHA1_DIGEST_BYTES: usize = 20;
const DYNAMIC_TRUNCATION_OFFSET_INDEX: usize = SHA1_DIGEST_BYTES - 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TotpPolicy {
    pub digits: u32,
    pub step_seconds: u64,
    pub skew_steps: u8,
    pub issuer: String,
}

impl Default for TotpPolicy {
    fn default() -> Self {
        Self {
            digits: DEFAULT_DIGITS,
            step_seconds: DEFAULT_STEP_SECONDS,
            skew_steps: DEFAULT_SKEW_STEPS,
            issuer: DEFAULT_ISSUER.to_string(),
        }
    }
}

impl TotpPolicy {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) {
            return Err(OtpuacError::InvalidTotpPolicy(
                "digits must be between 6 and 8",
            ));
        }
        if self.step_seconds == 0 {
            return Err(OtpuacError::InvalidTotpPolicy(
                "step_seconds must be greater than zero",
            ));
        }
        if self.skew_steps > MAX_SKEW_STEPS {
            return Err(OtpuacError::InvalidTotpPolicy(
                "skew_steps must not exceed two",
            ));
        }
        if self.issuer.trim().is_empty() {
            return Err(OtpuacError::InvalidTotpPolicy("issuer is required"));
        }
        Ok(())
    }
}

pub fn generate_totp_secret() -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(vec![0_u8; TOTP_SECRET_BYTES]);
    OsRng.fill_bytes(&mut secret);
    secret
}

pub fn encode_totp_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

pub fn decode_totp_secret(encoded: &str) -> Result<Zeroizing<Vec<u8>>> {
    let normalized = normalize_base32_secret(encoded);

    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| OtpuacError::Base32)
}

pub fn code_at(secret: &[u8], policy: &TotpPolicy, unix_time: u64) -> Result<String> {
    policy.validate()?;
    let counter = totp_step(unix_time, policy);
    hotp(secret, counter, policy.digits)
}

pub fn verify_at(secret: &[u8], policy: &TotpPolicy, code: &str, unix_time: u64) -> Result<bool> {
    Ok(accepted_step_at(secret, policy, code, unix_time)?.is_some())
}

pub fn accepted_step_at(
    secret: &[u8],
    policy: &TotpPolicy,
    code: &str,
    unix_time: u64,
) -> Result<Option<u64>> {
    policy.validate()?;

    let candidate = code.trim();
    validate_candidate_code(candidate, policy.digits)?;

    let current_step = totp_step(unix_time, policy);

    for offset in accepted_step_offsets(policy.skew_steps) {
        let Some(step) = add_signed(current_step, offset) else {
            continue;
        };
        let expected = hotp(secret, step, policy.digits)?;
        if bool::from(expected.as_bytes().ct_eq(candidate.as_bytes())) {
            return Ok(Some(step));
        }
    }

    Ok(None)
}

pub fn otpauth_uri(
    account_label: &str,
    encoded_secret: &str,
    policy: &TotpPolicy,
) -> Result<String> {
    policy.validate()?;
    let issuer = url_component(&policy.issuer);
    let label = url_component(&format!("{}:{}", policy.issuer, account_label));
    Ok(format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={digits}&period={period}",
        label = label,
        secret = encoded_secret,
        issuer = issuer,
        digits = policy.digits,
        period = policy.step_seconds
    ))
}

fn normalize_base32_secret(encoded: &str) -> String {
    encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .filter(|c| *c != '=')
        .flat_map(char::to_uppercase)
        .collect()
}

fn validate_candidate_code(candidate: &str, digits: u32) -> Result<()> {
    if candidate.len() == digits as usize && candidate.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(OtpuacError::InvalidTotpCode)
    }
}

fn totp_step(unix_time: u64, policy: &TotpPolicy) -> u64 {
    unix_time / policy.step_seconds
}

fn accepted_step_offsets(skew_steps: u8) -> std::ops::RangeInclusive<i64> {
    let skew_steps = i64::from(skew_steps);
    -skew_steps..=skew_steps
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret)
        .map_err(|err| OtpuacError::Crypto(format!("invalid HMAC key: {err}")))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let binary = dynamic_truncate(&digest);
    let modulus = 10_u32.pow(digits);
    Ok(format!(
        "{code:0width$}",
        code = binary % modulus,
        width = digits as usize
    ))
}

fn dynamic_truncate(digest: &[u8]) -> u32 {
    let offset = (digest[DYNAMIC_TRUNCATION_OFFSET_INDEX] & 0x0f) as usize;
    (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32)
}

fn add_signed(value: u64, offset: i64) -> Option<u64> {
    if offset.is_negative() {
        value.checked_sub(offset.unsigned_abs())
    } else {
        value.checked_add(offset as u64)
    }
}

fn url_component(value: &str) -> String {
    // Keep this local to avoid making the core URI generation depend on a URL
    // crate. Authenticator labels only need RFC3986-style percent escaping.
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotp_matches_rfc_4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, expected_code) in expected.into_iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64, 6).unwrap(), expected_code);
        }
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vector() {
        let secret = b"12345678901234567890";
        let policy = TotpPolicy {
            digits: 8,
            step_seconds: 30,
            skew_steps: 1,
            issuer: "OTPUAC".to_string(),
        };

        assert_eq!(code_at(secret, &policy, 59).unwrap(), "94287082");
    }

    #[test]
    fn verify_allows_configured_clock_skew() {
        let secret = b"12345678901234567890";
        let policy = TotpPolicy::default();
        let code = code_at(secret, &policy, 60).unwrap();

        assert!(verify_at(secret, &policy, &code, 61).unwrap());
        assert!(verify_at(secret, &policy, &code, 89).unwrap());
        assert!(!verify_at(secret, &policy, &code, 121).unwrap());
    }

    #[test]
    fn base32_secret_round_trips() {
        let secret = generate_totp_secret();
        let encoded = encode_totp_secret(&secret);
        let decoded = decode_totp_secret(&encoded).unwrap();

        assert_eq!(&*decoded, &*secret);
    }
}
