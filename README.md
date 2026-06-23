# OTPUAC

OTPUAC adds a TOTP challenge to Windows UAC prompts before releasing a managed
administrator credential. It is designed for controlled elevation: a standard
user still goes through normal UAC, and OTPUAC only supplies the managed admin
credential after the authenticator code is accepted.

OTPUAC does not bypass UAC, create administrator rights for standard users, or
disable Microsoft credential providers.

## What It Installs

- A dedicated managed local administrator account.
- A DPAPI-protected vault in `C:\ProgramData\OTPUAC`.
- The `OTPUAC` Windows service.
- A UAC-only Windows Credential Provider tile.
- An administrator CLI for enrollment, verification, and maintenance.
- Windows Application log audit events under the `OTPUAC` source.

## Requirements

- Windows 10/11 x64.
- An existing administrator account to approve installation.
- A mobile authenticator app that supports TOTP.
- A signed OTPUAC installer package from your approved release channel.

Keep the built-in Microsoft credential providers enabled. They are the recovery
path if the OTPUAC service, vault, or authenticator enrollment is unavailable.

## Install

> [!CAUTION]
> This project is entirely vibe coded, use at your own risk!

Run the OTPUAC installer and approve the Windows elevation prompt with an
existing administrator account. During setup, choose:

- the local managed administrator account name, for example `OTPUACAdmin`;
- the authenticator issuer label, for example `OTPUAC`.

Setup creates the managed local administrator account, generates a strong random
password, stores that password only in the DPAPI-protected vault, registers the
service and Credential Provider, and opens the authenticator enrollment details.

Enroll the displayed TOTP secret or URI in the intended authenticator app.

## Use

When Windows shows a UAC prompt, select the OTPUAC tile and enter the current
authenticator code. If the code is accepted, Windows receives the managed
administrator credential and continues the elevation.

Reused or old TOTP steps are rejected. Several failed attempts in a short
window trigger a temporary lockout.

## Maintain

Use Windows Apps & Features / Add or Remove Programs to uninstall OTPUAC.
Uninstall removes the service, Credential Provider registration, OTPUAC data,
and the managed local admin account when OTPUAC created it.

For day-to-day administration, audit review, credential rotation, and recovery
procedures, see [Operations](docs/operations.md).

## Documentation

- [Installation](docs/installation.md)
- [Operations](docs/operations.md)
- [Security Model](docs/security-model.md)
- [Architecture](docs/architecture.md)
- [Credential Provider](docs/provider.md)
