# Installation

## Before You Start

Confirm that you have:

- a Windows 10/11 x64 machine;
- an existing administrator account;
- a mobile authenticator app that supports TOTP;
- the signed OTPUAC installer from your approved release channel.

Do not disable built-in Microsoft credential providers. They provide the
recovery path if OTPUAC cannot unlock the managed credential.

## Install OTPUAC

1. Run the OTPUAC installer.
2. Approve the Windows elevation prompt with an existing administrator account.
3. Choose the managed local administrator account name.
4. Choose the authenticator issuer label.
5. Complete setup.

The installer creates the managed local administrator account, generates its
password, stores the password in the DPAPI-protected OTPUAC vault, registers the
Windows service, registers the Credential Provider, and opens the authenticator
enrollment details.

## Enroll the Authenticator

Add the displayed TOTP secret or enrollment URI to the intended authenticator
app. Store emergency administrator credentials separately from the authenticator
device.

The managed account password is not displayed by setup and is not passed through
installer command-line arguments.

## Use OTPUAC

When a UAC prompt appears:

1. Select the OTPUAC tile.
2. Enter the current authenticator code.
3. Continue the elevated action after Windows accepts the managed credential.

OTPUAC rejects invalid codes, already-used TOTP steps, and older TOTP steps.
Repeated failures trigger a temporary lockout.

## Installed Locations

- Program files: `C:\Program Files\OTPUAC`
- Vault and runtime state: `C:\ProgramData\OTPUAC`
- Windows service: `OTPUAC`
- Event Log source: `OTPUAC`
- Managed account default: `OTPUACAdmin`

The `C:\ProgramData\OTPUAC` directory should remain restricted to `SYSTEM` and
local Administrators.

## Uninstall

Use Windows Apps & Features / Add or Remove Programs and uninstall OTPUAC.

The uninstaller removes the OTPUAC service, unregisters the Credential Provider,
deletes OTPUAC data, and deletes the managed local administrator account when
OTPUAC metadata says setup created it.
