# Repository Guidelines

## Project Structure & Module Organization

This is a Rust workspace for OTPUAC, a Windows UAC credential-provider system.
Workspace crates live under `crates/`:

- `otpuac-core`: shared TOTP, vault, IPC contracts, and protection abstractions.
- `otpuac-admin`: CLI for provisioning, enrollment, and TOTP verification.
- `otpuac-service`: Windows service, named-pipe unlock handler, and audit logging.
- `otpuac-setup`: installer helper for account, vault, service, provider, and uninstall work.
- `otpuac-provider`: Rust Credential Provider COM DLL.
- `otpuac-runtime`: OTPUAC runtime paths and default platform selections.
- `otpuac-windows`: shared OTPUAC Windows helpers for pipes, DPAPI, COM, and UTF-16.

Production-facing documentation is in `docs/`, installer packaging is in
`installer/`, and helper scripts are in `scripts/`.

## Build Commands

- `cargo build --workspace`: build all workspace crates for the host target.
- `.\scripts\build-windows.ps1`: build Windows release artifacts.
- On Windows, `.\scripts\build-installer.ps1` builds the release installer.

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
