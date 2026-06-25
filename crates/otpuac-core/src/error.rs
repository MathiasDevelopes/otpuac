use thiserror::Error;

pub type Result<T> = std::result::Result<T, OtpuacError>;

#[derive(Debug, Error)]
pub enum OtpuacError {
    #[error("invalid TOTP policy: {0}")]
    InvalidTotpPolicy(&'static str),

    #[error("TOTP code must contain only ASCII digits")]
    InvalidTotpCode,

    #[error("TOTP code was rejected")]
    TotpRejected,

    #[error("secret protection failed: {0}")]
    Crypto(String),

    #[error("protected blob scheme mismatch: expected {expected}, got {actual}")]
    SchemeMismatch { expected: String, actual: String },

    #[error("invalid vault: {0}")]
    InvalidVault(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid runtime state: {0}")]
    InvalidState(String),

    #[error("invalid IPC message: {0}")]
    InvalidIpc(String),

    #[error("platform operation failed: {0}")]
    Platform(String),

    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("base32 error")]
    Base32,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported platform feature: {0}")]
    UnsupportedPlatform(&'static str),
}
