use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use zeroize::Zeroizing;

const PASSWORD_LEN: usize = 32;
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!#$%+-.=?@_";
const PASSWORD_CLASSES: [&[u8]; 4] = [LOWER, UPPER, DIGITS, SYMBOLS];
const PASSWORD_ALPHABET: &[u8] =
    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#$%+-.=?@_";

pub(crate) fn generate_windows_password() -> Zeroizing<String> {
    let mut rng = OsRng;
    let mut bytes = Vec::with_capacity(PASSWORD_LEN);
    for class in PASSWORD_CLASSES {
        bytes.push(*class.choose(&mut rng).expect("password class is non-empty"));
    }
    for _ in bytes.len()..PASSWORD_LEN {
        bytes.push(
            *PASSWORD_ALPHABET
                .choose(&mut rng)
                .expect("password alphabet is non-empty"),
        );
    }
    bytes.shuffle(&mut rng);

    Zeroizing::new(String::from_utf8(bytes).expect("password alphabet is ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_contains_required_character_classes() {
        let password = generate_windows_password();

        assert_eq!(password.len(), PASSWORD_LEN);
        assert!(password.bytes().any(|byte| byte.is_ascii_lowercase()));
        assert!(password.bytes().any(|byte| byte.is_ascii_uppercase()));
        assert!(password.bytes().any(|byte| byte.is_ascii_digit()));
        assert!(password.bytes().any(|byte| !byte.is_ascii_alphanumeric()));
    }
}
