//! RFC 6238 TOTP with the settings every authenticator app assumes:
//! HMAC-SHA1, six digits, 30-second steps, one step of clock skew.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::{rngs::SysRng, TryRng};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const DIGITS: usize = 6;
pub const STEP_SECONDS: u64 = 30;
const SKEW_STEPS: u64 = 1;
const SECRET_BYTES: usize = 20;
const ISSUER: &str = "OTPUAC";

pub fn generate_secret() -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(vec![0_u8; SECRET_BYTES]);
    SysRng
        .try_fill_bytes(&mut secret)
        .expect("OS random source is available");
    secret
}

pub fn encode_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// Returns the time step `code` is valid for at `unix_time`, if any.
pub fn matching_step(secret: &[u8], code: &str, unix_time: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let current = unix_time / STEP_SECONDS;
    (current.saturating_sub(SKEW_STEPS)..=current + SKEW_STEPS)
        .find(|&step| bool::from(hotp(secret, step).as_bytes().ct_eq(code.as_bytes())))
}

pub fn otpauth_uri(account_label: &str, encoded_secret: &str) -> String {
    let label = url_component(&format!("{ISSUER}:{account_label}"));
    format!(
        "otpauth://totp/{label}?secret={encoded_secret}&issuer={ISSUER}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
}

#[cfg(test)]
pub(crate) fn code_at(secret: &[u8], unix_time: u64) -> String {
    hotp(secret, unix_time / STEP_SECONDS)
}

fn hotp(secret: &[u8], counter: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!("{:0DIGITS$}", binary % 10_u32.pow(DIGITS as u32))
}

fn url_component(value: &str) -> String {
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

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_rfc_4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.into_iter().enumerate() {
            assert_eq!(hotp(RFC_SECRET, counter as u64), code);
        }
    }

    #[test]
    fn accepts_one_step_of_clock_skew() {
        let code = code_at(RFC_SECRET, 60);

        assert_eq!(matching_step(RFC_SECRET, &code, 61), Some(2));
        assert_eq!(matching_step(RFC_SECRET, &code, 89), Some(2));
        assert_eq!(matching_step(RFC_SECRET, &code, 30), Some(2));
        assert_eq!(matching_step(RFC_SECRET, &code, 121), None);
    }

    #[test]
    fn rejects_malformed_codes() {
        assert_eq!(matching_step(RFC_SECRET, "12345", 0), None);
        assert_eq!(matching_step(RFC_SECRET, "12345a", 0), None);
        assert_eq!(matching_step(RFC_SECRET, "", 0), None);
    }

    #[test]
    fn uri_escapes_the_label() {
        let uri = otpauth_uri(r"PC\admin", "ABC");
        assert!(uri.starts_with("otpauth://totp/OTPUAC%3APC%5Cadmin?secret=ABC&"));
    }

    #[test]
    fn base32_secret_round_trips() {
        let secret = generate_secret();
        let decoded = BASE32_NOPAD
            .decode(encode_secret(&secret).as_bytes())
            .unwrap();
        assert_eq!(&*decoded, &*secret);
    }
}
