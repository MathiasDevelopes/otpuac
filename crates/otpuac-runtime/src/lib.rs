//! OTPUAC product runtime configuration.
//!
//! This crate owns install paths and platform-specific default selections used
//! by the binaries. Reusable vault, TOTP, and IPC contracts stay in
//! `otpuac-core`.

pub mod paths;
pub mod protect;

pub use protect::default_protector;
