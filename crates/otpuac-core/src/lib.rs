//! Shared OTPUAC logic.
//!
//! This crate intentionally contains the policy, TOTP, vault, and IPC data
//! contracts that can be tested without loading a Windows Credential Provider.

pub mod error;
pub mod ipc;
pub mod protect;
pub mod time;
pub mod totp;
pub mod vault;

pub use error::{OtpuacError, Result};
pub use ipc::{
    decode_frame, encode_frame, ProviderUnlockRequest, ProviderUnlockResponse, UnlockDecision,
    UnlockFailureReason, CRED_UI_USAGE_SCENARIO, MAX_IPC_MESSAGE_BYTES, PIPE_NAME,
};
pub use protect::SecretProtector;
pub use time::now_unix;
pub use totp::{generate_totp_secret, otpauth_uri, TotpPolicy};
pub use vault::{ManagedAccount, ReleasedCredential, VaultFile};
