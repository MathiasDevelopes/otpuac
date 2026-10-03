# Credential Provider

## Purpose

`otpuac-provider` is the native Rust COM Credential Provider DLL used by the
Windows UAC Credential UI path. Its release DLL is `otpuac_provider.dll`, and
the MSI registers it under a stable CLSID.

## Scope

The provider supports only `CPUS_CREDUI`, the UAC Credential UI scenario. It is
not intended for workstation sign-in or unlock.

Built-in Microsoft credential providers should remain enabled so administrators
retain a recovery path.

## Runtime Flow

1. Windows loads the provider for a UAC prompt.
2. The provider displays the TOTP input tile.
3. The user submits the current authenticator code.
4. The provider calls `otpuac_core::unlock` with `C:\ProgramData\OTPUAC`.
5. On success it calls `CredPackAuthenticationBufferW` and returns the
   credential serialization to Windows; otherwise it shows why.
6. Plaintext password and TOTP buffers are cleared.

## Implementation Files

- `windows_provider.rs`: DLL entry points.
- `windows_provider/provider.rs`: `ICredentialProvider`.
- `windows_provider/credential.rs`: `ICredentialProviderCredential` and the
  submit path.
- `windows_provider/fields.rs`: tile fields.
- `windows_provider/credential_pack.rs`: Windows credential serialization.
- `windows_provider/class_factory.rs`, `ids.rs`, `hresult.rs`, `wide.rs`: COM
  plumbing.
