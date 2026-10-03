# Repository Guidelines

## Project Structure & Module Organization

This is a Rust workspace for OTPUAC, a Windows UAC credential-provider system.
Workspace crates live under `crates/`:

- `otpuac-core`: the unlock decision, TOTP, vault, replay/lockout guard, and
  the shared Win32 helpers (DPAPI, SDDL, UTF-16).
- `otpuac-provider`: Rust Credential Provider COM DLL; calls `otpuac_core::unlock`.
- `otpuac-setup`: CLI for install, enrollment, code checks, and uninstall; the
  MSI runs it as custom actions.

Production-facing documentation is in `docs/`, the WiX MSI source is in
`installer/`, and helper scripts are in `scripts/`.

## Build Commands

- `cargo build --workspace`: build all workspace crates for the host target.
- `.\scripts\build-windows.ps1`: build Windows release artifacts.
- On Windows, `.\scripts\build-installer.ps1` builds the release MSI (needs the
  WiX Toolset: `dotnet tool install --global wix --version 5.0.2`).
- `.\scripts\test-installer.ps1 -Msi <path>` installs and uninstalls the MSI and
  checks the result. It creates a real admin account, so use a disposable VM.

## Coding Style & Naming Conventions

Use Rust 2021 style and `rustfmt` defaults. Prefer small modules matching the
existing crate boundaries. Keep public API names descriptive and snake_case for
functions, modules, and variables; use PascalCase for types and enum variants.
Keep unsafe Windows/COM code narrow, documented by structure, and consistent
with surrounding Win32 wrapper patterns.

## Security & Configuration Tips

Do not store personal administrator credentials in the vault. Keep Microsoft
credential providers enabled so machines remain recoverable if OTPUAC fails.
Use a dedicated managed administrator account and rotate it according to the
operations guide.
