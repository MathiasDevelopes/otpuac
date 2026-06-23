# Operations

## Normal Use

OTPUAC is used from a Windows UAC prompt. The user selects the OTPUAC tile,
enters the current authenticator code, and Windows receives the managed
administrator credential only after OTPUAC accepts the code.

The managed account should be dedicated to OTPUAC. Do not store a personal
administrator password in the OTPUAC vault.

## Enrollment

During installation, OTPUAC opens the authenticator enrollment details. Enroll
the displayed TOTP secret or URI in the intended authenticator app.

If enrollment needs to be displayed again, run from an elevated PowerShell
session:

```powershell
& "$env:ProgramFiles\OTPUAC\otpuac-admin.exe" show-enrollment
```

Protect the enrollment secret. Anyone with the secret can generate valid codes.

## Code Check

To confirm that an authenticator code matches the installed vault, run:

```powershell
& "$env:ProgramFiles\OTPUAC\otpuac-admin.exe" verify --code 123456
```

Replace `123456` with the current authenticator code.

## Audit Review

OTPUAC writes audit events to the Windows Application log under the `OTPUAC`
source.

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'OTPUAC' } -MaxEvents 20 |
    Select-Object TimeCreated, LevelDisplayName, Message
```

Review events for:

- accepted unlocks;
- invalid TOTP attempts;
- replayed TOTP steps;
- temporary lockouts;
- vault load or decrypt failures;
- named-pipe client errors;
- service start, stop, and failure events.

## Rotate the Managed Credential

Rotate the managed administrator password if a device is lost, the vault is
exposed, an operator leaves, or your normal password-rotation policy requires
it.

After changing the managed account password, reprovision the OTPUAC vault from
an elevated PowerShell session:

```powershell
& "$env:ProgramFiles\OTPUAC\otpuac-admin.exe" provision --username OTPUACAdmin --force
```

Re-enroll the authenticator app if the TOTP secret changes.

## Service Control

The installed Windows service name is `OTPUAC`.

```powershell
Get-Service OTPUAC
Restart-Service OTPUAC
```

Stopping the service prevents the OTPUAC Credential Provider tile from
unlocking the managed credential.

## Recovery

Keep a normal administrator credential available outside OTPUAC. Recovery
options are:

- sign in or approve UAC with a normal administrator credential;
- restart the `OTPUAC` service;
- uninstall OTPUAC;
- rotate the managed account password;
- re-enroll the authenticator app.

Never remove or disable built-in Microsoft credential providers as part of
OTPUAC deployment.

## Uninstall

Use Windows Apps & Features / Add or Remove Programs and uninstall OTPUAC.

The uninstaller removes the service, unregisters the Credential Provider,
removes OTPUAC data, and deletes the managed local administrator account when
OTPUAC created it.
