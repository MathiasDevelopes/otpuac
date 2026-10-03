# Installation

## Before You Start

Confirm that you have:

- a Windows 10/11 x64 machine;
- an existing administrator account;
- a mobile authenticator app that supports TOTP;
- the signed OTPUAC MSI (`OTPUAC-<version>-x64.msi`) from your approved release
  channel.

Do not disable built-in Microsoft credential providers. They provide the
recovery path if OTPUAC cannot unlock the managed credential.

## Install OTPUAC

1. Run the OTPUAC MSI.
2. Choose the managed local administrator account name.
3. Click Install and approve the Windows elevation prompt with an existing
   administrator account.
4. Click Finish to open the authenticator enrollment details in Notepad.

The installer creates the managed local administrator account, generates its
password, stores the password in the DPAPI-protected OTPUAC vault, registers the
Credential Provider, and writes the
authenticator enrollment details to a file in your temp folder. Setup deletes
that file after you close Notepad.

If an earlier OTPUAC setup `.exe` is installed, the MSI asks you to uninstall it
first. That uninstall removes the old managed account and vault, so enroll the
authenticator again after installing the MSI.

### Unattended Install

The MSI accepts these public properties:

- `OTPUACACCOUNTNAME`: managed account name, default `OTPUACAdmin`.
- `OTPUACENROLLMENTFILE`: optional path for the enrollment details file. Silent
  installs write no enrollment file unless this is set.

```powershell
msiexec /i OTPUAC-1.0.1-x64.msi /qn OTPUACACCOUNTNAME=OTPUACAdmin OTPUACENROLLMENTFILE="C:\Secure\otpuac-enrollment.txt"
```

Without an enrollment file, show the enrollment details later from an elevated
prompt with `otpuac-setup enrollment`. Delete any enrollment file once the
authenticator is enrolled; it contains the TOTP secret.

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
- Vault and replay/lockout state: `C:\ProgramData\OTPUAC`
- Managed account default: `OTPUACAdmin`

The `C:\ProgramData\OTPUAC` directory should remain restricted to `SYSTEM` and
local Administrators.

## Uninstall

Use Windows Apps & Features / Add or Remove Programs and uninstall OTPUAC, or
run `msiexec /x OTPUAC-<version>-x64.msi /qn`.

The uninstaller unregisters the Credential Provider, deletes OTPUAC data, and
deletes the managed local administrator account when setup created it. Upgrading to a newer MSI keeps the
managed account and vault.
