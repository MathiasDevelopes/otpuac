# Architecture

## The Idea

UAC elevation only accepts a real Windows credential, and a TOTP code is not
one. OTPUAC therefore makes a valid TOTP code release the password of a
dedicated local administrator account that only OTPUAC knows. Windows still
authenticates that account and makes the elevation decision.

## Components

- `otpuac-core`: the unlock decision (`unlock()`), TOTP, the vault, and the
  replay/lockout guard. Plain Rust, tested on any platform; its `win` module
  holds the few shared Win32 helpers (DPAPI, SDDL, UTF-16).
- `otpuac-provider`: the Credential Provider COM DLL that shows the OTPUAC
  tile in the UAC prompt and calls `unlock()`.
- `otpuac-setup`: one CLI for install, enrollment, code checks, and uninstall.
  The MSI (`installer/`) runs it as custom actions; administrators can run it
  by hand.

## UAC Flow

1. Windows shows the UAC credential prompt in `consent.exe`, which runs as
   SYSTEM on the secure desktop and loads the OTPUAC provider.
2. The user selects the OTPUAC tile and enters a TOTP code.
3. The provider calls `unlock()`, which:
   - refuses while locked out;
   - reads and decrypts the vault;
   - checks the code (SHA-1, 6 digits, 30-second steps, one step of skew);
   - refuses a step at or before the last accepted one;
   - records the outcome in the guard file before returning.
4. On success the provider packs the managed credential for Windows and clears
   the plaintext.

## Data

`C:\ProgramData\OTPUAC`, restricted to SYSTEM and Administrators, holds:

- `vault.json`: the managed account name, its DPAPI-protected password, the
  DPAPI-protected TOTP secret, and whether setup created the account.
- `guard.json`: the last accepted TOTP step and the times of recent failures.

The directory's ACL is the access control: a process that is not SYSTEM or an
administrator cannot open the vault, so the provider fails closed anywhere
other than an elevated prompt host.
