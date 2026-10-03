# Security Model

## Purpose

OTPUAC adds a second factor before a managed administrator credential is released
to a Windows UAC prompt.

It does not create administrator rights, bypass UAC, exploit Windows, or disable
Microsoft credential providers. Windows still makes the elevation decision.

## Managed Credential

Setup creates a dedicated local administrator account with a random 32-character
password that nobody sees, and hides it from the sign-in screen. Do not place a
personal administrator password in the OTPUAC vault.

## Secret Storage

The vault in `C:\ProgramData\OTPUAC` holds the managed password and the TOTP
secret, each protected with machine-scoped DPAPI. The directory is restricted to
`SYSTEM` and local Administrators; that ACL is what keeps ordinary users away
from the secrets, since machine-scoped DPAPI alone does not.

Plaintext handling is short-lived:

- the password is decrypted only after the code is accepted;
- the provider holds it only long enough to serialize it for Windows;
- secret buffers are cleared as soon as possible.

## UAC Boundary

The provider supports the UAC Credential UI scenario only. The UAC prompt host,
`consent.exe`, runs as SYSTEM and can read the vault. If any other process loads
the provider, it cannot open the vault and the tile reports an error.

## Replay and Lockout

`guard.json` records the last accepted TOTP step; that step and older ones are
rejected. Five failed attempts within five minutes lock the tile until the
oldest of them is five minutes old. Every attempt is recorded before the
credential is released, and a failure to record it denies the attempt.

## Recovery

Keep built-in Microsoft credential providers enabled and keep a normal
administrator credential available. Recovery options include:

- using a normal administrator credential;
- uninstalling and reinstalling OTPUAC, which creates a fresh account, password,
  and TOTP secret.

## Not Covered

OTPUAC does not protect against:

- a compromised administrator or LocalSystem process;
- malware that can read privileged process memory;
- malware that can inject into or replace trusted Windows credential UI hosts;
- phishing or shoulder-surfing of current TOTP codes;
- missing organizational procedures for rotation and audit review.
