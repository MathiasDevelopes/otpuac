//! Rust Credential Provider implementation.
//!
//! The Windows COM implementation is isolated behind `cfg(windows)` so the
//! core TOTP and IPC logic remains buildable and testable on other platforms.

pub const OTPUAC_PROVIDER_CLSID: &str = "{B6B6F0C2-4CCB-487E-9B58-681099865B10}";

/// Parses a braced registry-format GUID string into its `u128` form.
///
/// Evaluated at compile time for the provider CLSID, so a malformed string
/// fails the build.
#[cfg_attr(not(windows), allow(dead_code))]
const fn parse_guid_u128(guid: &str) -> u128 {
    let bytes = guid.as_bytes();
    assert!(bytes.len() == 38, "GUID must be 38 characters");
    assert!(bytes[0] == b'{' && bytes[37] == b'}', "GUID must be braced");

    let mut value: u128 = 0;
    let mut i = 1;
    while i < 37 {
        let byte = bytes[i];
        if i == 9 || i == 14 || i == 19 || i == 24 {
            assert!(byte == b'-', "GUID separator must be '-'");
        } else {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'A'..=b'F' => byte - b'A' + 10,
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("GUID digit must be hexadecimal"),
            };
            value = (value << 4) | digit as u128;
        }
        i += 1;
    }
    value
}

#[cfg(windows)]
mod windows_provider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_format_guid() {
        assert_eq!(
            parse_guid_u128("{00000001-0000-0000-C000-000000000046}"),
            0x00000001_0000_0000_C000_000000000046
        );
        assert_eq!(
            parse_guid_u128("{d27c3481-5a1c-45b2-8aaa-c20ebbe8229e}"),
            0xD27C3481_5A1C_45B2_8AAA_C20EBBE8229E
        );
    }

    #[test]
    fn provider_clsid_is_well_formed() {
        parse_guid_u128(OTPUAC_PROVIDER_CLSID);
    }
}
