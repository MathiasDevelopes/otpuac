# Architecture

## Overview

OTPUAC is split into separate components so the Windows Credential Provider,
Windows service, installer helper, and shared security logic each have a clear
responsibility.

## Components

- `otpuac-core`: TOTP verification, vault format, secret protection
  abstraction, and provider/service IPC contracts.
- `otpuac-runtime`: OTPUAC product paths, installed artifact names, and default
  runtime selections such as the platform secret protector.
- `otpuac-admin`: administrator CLI for provisioning, enrollment display, and
  TOTP verification.
- `otpuac-service`: Windows service that validates unlock requests and releases
  the managed credential after TOTP succeeds.
- `otpuac-setup`: installer helper for account creation, vault provisioning,
  service registration, Credential Provider registration, and uninstall cleanup.
- `otpuac-provider`: native Rust Windows Credential Provider DLL for the UAC
  prompt.
- `otpuac-windows`: OTPUAC Windows helper crate for DPAPI, named pipes, COM
  allocations, handles, and UTF-16 conversion.

## UAC Flow

1. Windows shows a UAC Credential UI prompt.
2. The user selects the OTPUAC tile and enters a TOTP code.
3. The Credential Provider sends a framed unlock request to the OTPUAC service.
4. The service confirms the request is for the UAC Credential UI scenario.
5. The service validates the TOTP code, checks replay state, and releases the
   managed credential only on success.
6. The provider packs the credential for Windows and clears plaintext buffers.

The provider does not read or decrypt the vault. Vault access stays in the
service process.

## Vault

The Windows vault is stored at:

```text
C:\ProgramData\OTPUAC\vault.json
```

It contains:

- the managed account name and optional domain;
- the protected managed account password;
- the protected TOTP secret;
- the TOTP policy;
- vault metadata.

Secrets are protected with machine-scoped DPAPI on Windows. The vault directory
should remain restricted to `SYSTEM` and local Administrators.

## IPC

The provider and service communicate over:

```text
\\.\pipe\OTPUAC
```

Messages are length-prefixed JSON frames with a maximum size. Provider IPC has
bounded connect and I/O waits so a stalled service returns an error instead of
leaving the UAC prompt waiting indefinitely.

The installed service accepts requests only from known Windows credential UI
host processes.

## Audit and State

Audit events are written to the Windows Application log under the `OTPUAC`
source.

Replay state is stored at:

```text
C:\ProgramData\OTPUAC\service-state.json
```

This state records the last accepted TOTP step so reused or older codes can be
rejected.
