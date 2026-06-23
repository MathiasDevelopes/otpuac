# Security Model

## Purpose

OTPUAC adds a second factor before a managed administrator credential is released
to a Windows UAC prompt.

It does not create administrator rights, bypass UAC, exploit Windows, or disable
Microsoft credential providers. Windows still makes the elevation decision.

## Managed Credential

Use a dedicated managed administrator account. Do not place a personal
administrator password in the OTPUAC vault.

Rotate the managed password when:

- a device is lost;
- the vault may have been exposed;
- an operator leaves;
- your account policy requires rotation.

## Secret Storage

On Windows, OTPUAC protects vault secrets with machine-scoped DPAPI. The vault
directory is `C:\ProgramData\OTPUAC` and should remain accessible only to
`SYSTEM` and local Administrators.

The OTPUAC service is the component that decrypts the vault. The Credential
Provider receives the managed credential only after the service accepts the TOTP
code.

Plaintext handling is intentionally short-lived:

- the service decrypts the managed password only after TOTP succeeds;
- the provider receives the password only long enough to serialize it for
  Windows;
- secret buffers are cleared as soon as possible.

## UAC Boundary

The provider supports the UAC Credential UI scenario only. It is not intended
for workstation sign-in or unlock.

The service listens on `\\.\pipe\OTPUAC`. The installed service checks the
connected client process image and serves known Windows credential UI hosts from
`System32`, such as `consent.exe`, `LogonUI.exe`, and
`CredentialUIBroker.exe`.

This caller check blocks ordinary user processes from directly exchanging a TOTP
code for the managed password. It is process allowlisting, not cryptographic
caller attestation.

## Replay and Lockout

OTPUAC stores the last accepted TOTP time step in
`C:\ProgramData\OTPUAC\service-state.json`. Reused or older steps are rejected.

Repeated invalid attempts trigger a temporary lockout.

## Recovery

Keep built-in Microsoft credential providers enabled and keep a normal
administrator credential available. Recovery options include:

- using a normal administrator credential;
- restarting or uninstalling OTPUAC;
- rotating the managed account password;
- re-enrolling the authenticator app.

## Not Covered

OTPUAC does not protect against:

- a fully compromised administrator or LocalSystem process;
- malware that can read privileged process memory;
- malware that can inject into or replace trusted Windows credential UI hosts;
- phishing or shoulder-surfing of current TOTP codes;
- weak managed administrator passwords;
- missing organizational procedures for password rotation and audit review.
