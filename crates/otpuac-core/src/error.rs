use thiserror::Error;

pub type Result<T> = std::result::Result<T, OtpuacError>;

#[derive(Debug, Error)]
pub enum OtpuacError {
    #[error("The authenticator code was rejected")]
    CodeRejected,

    #[error("This authenticator code was already used")]
    CodeReused,

    #[error("Too many failed attempts; try again in a few minutes")]
    LockedOut,

    #[error("secret protection failed: {0}")]
    Crypto(String),

    #[error("invalid vault: {0}")]
    InvalidVault(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("platform operation failed: {0}")]
    Platform(String),

    #[error("base64 error: {0}")]
    Base64(#[from] data_encoding::DecodeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl OtpuacError {
    /// True when the code itself was refused, as opposed to OTPUAC failing.
    pub fn is_denial(&self) -> bool {
        matches!(
            self,
            Self::CodeRejected | Self::CodeReused | Self::LockedOut
        )
    }
}
