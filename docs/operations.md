# Operations

## Normal Use

OTPUAC is used from a Windows UAC prompt. The user selects the OTPUAC tile,
enters the current authenticator code, and Windows receives the managed
administrator credential only after OTPUAC accepts the code.

## Enrollment

During installation, OTPUAC opens the authenticator enrollment details. Enroll
the displayed TOTP secret or URI in the intended authenticator app.

To show the enrollment details again, run from an elevated PowerShell session:

```powershell
& "$env:ProgramFiles\OTPUAC\otpuac-setup.exe" enrollment
```

Protect the enrollment secret. Anyone with the secret can generate valid codes.

## Code Check

To confirm that an authenticator code matches the installed vault without using
it up, run from an elevated PowerShell session:

```powershell
& "$env:ProgramFiles\OTPUAC\otpuac-setup.exe" verify --code 123456
```

## Audit Review

Each successful elevation is a logon by the managed account, so the Security
log records it like any other (event 4624, or 4625 for a failed logon):

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } -MaxEvents 50 |
    Where-Object { $_.Properties[5].Value -eq 'OTPUACAdmin' }
```

## Rotate the Credential or Secret

Uninstall and reinstall OTPUAC if a device is lost, the vault may have been
exposed, an operator leaves, or your rotation policy requires it. Reinstalling
creates a new managed account password and TOTP secret; enroll the
authenticator again afterwards.

## Recovery

Keep a normal administrator credential available outside OTPUAC. Never remove
or disable built-in Microsoft credential providers as part of OTPUAC
deployment.

## Uninstall

Use Windows Apps & Features / Add or Remove Programs and uninstall OTPUAC, or
run `msiexec /x OTPUAC-<version>-x64.msi /qn`.

The uninstaller unregisters the Credential Provider, removes OTPUAC data, and
deletes the managed local administrator account when OTPUAC created it.
