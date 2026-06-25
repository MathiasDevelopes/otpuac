# Credential Provider

## Purpose

`otpuac-provider` is the native Rust COM Credential Provider DLL used by the
Windows UAC Credential UI path. Its release DLL is `otpuac_provider.dll`.

It registers a stable CLSID, exposes the required COM entry points, displays a
single OTPUAC tile, sends TOTP unlock requests to the OTPUAC service, and packs
the approved managed credential for Windows.

## Scope

The provider supports only `CPUS_CREDUI`, the UAC Credential UI scenario. It is
not intended for workstation sign-in or unlock.

Built-in Microsoft credential providers should remain enabled so administrators
retain a recovery path.

## Runtime Flow

1. Windows loads the provider for a UAC prompt.
2. The provider displays the TOTP input tile.
3. The user submits the current authenticator code.
4. The provider sends a framed `ProviderUnlockRequest` to `\\.\pipe\OTPUAC`.
5. The service approves or denies the request.
6. On approval, the provider calls `CredPackAuthenticationBufferW` and returns
   the credential serialization to Windows.
7. Plaintext password and TOTP buffers are cleared.

## Boundaries

- The provider does not read the vault.
- The provider does not decrypt secrets.
- The provider does not decide account policy.
- The provider only serializes credentials returned by the service.

## Implementation Files

- `windows_provider.rs`: COM object and UI field state.
- `windows_provider/ipc.rs`: named-pipe client with bounded waits.
- `windows_provider/credential_pack.rs`: Windows credential serialization.
- `windows_provider/registry.rs`: COM and Credential Provider registration.
- `windows_provider/hresult.rs`: Win32-to-HRESULT conversion.
- `otpuac-windows/src/wide.rs`: shared UTF-16 allocation and clearing helpers.
