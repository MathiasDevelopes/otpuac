//! Windows-specific OTPUAC helpers.

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod protect;
#[cfg(windows)]
pub mod wide;
