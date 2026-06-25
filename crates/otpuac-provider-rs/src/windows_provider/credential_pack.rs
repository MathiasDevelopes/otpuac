use std::ptr;
use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, E_OUTOFMEMORY, HANDLE, S_OK,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage,
    LsaNtStatusToWinError, LSA_STRING,
};
use windows_sys::Win32::Security::Credentials::{
    CredPackAuthenticationBufferW, CRED_PACK_PROTECTED_CREDENTIALS, CRED_PACK_WOW_BUFFER,
};
use windows_sys::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows_sys::Win32::UI::Shell::CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION as CredentialProviderCredentialSerialization;

use super::hresult::{hresult_from_last_error, hresult_from_win32};
use super::ids::CLSID_OTPUAC;
use otpuac_windows_support::wide::{secure_zero_u16, wide_null};

pub(super) unsafe fn pack_credential(
    qualified_username: &str,
    password: &mut str,
    use_wow_buffer: bool,
    serialization: *mut CredentialProviderCredentialSerialization,
) -> HRESULT {
    let username_w = wide_null(qualified_username);
    let mut password_w = wide_null(password);
    let flags = credential_pack_flags(use_wow_buffer);
    let mut buffer_size = 0_u32;

    let first = CredPackAuthenticationBufferW(
        flags,
        username_w.as_ptr(),
        password_w.as_ptr(),
        ptr::null_mut(),
        &mut buffer_size,
    );
    if first != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        secure_zero_u16(&mut password_w);
        return hresult_from_last_error();
    }

    let buffer = CoTaskMemAlloc(buffer_size as usize) as *mut u8;
    if buffer.is_null() {
        secure_zero_u16(&mut password_w);
        return E_OUTOFMEMORY;
    }

    let ok = CredPackAuthenticationBufferW(
        flags,
        username_w.as_ptr(),
        password_w.as_ptr(),
        buffer,
        &mut buffer_size,
    );
    secure_zero_u16(&mut password_w);
    if ok == 0 {
        CoTaskMemFree(buffer.cast());
        return hresult_from_last_error();
    }

    let mut auth_package = 0_u32;
    let hr = retrieve_negotiate_auth_package(&mut auth_package);
    if hr != S_OK {
        CoTaskMemFree(buffer.cast());
        return hr;
    }

    (*serialization).ulAuthenticationPackage = auth_package;
    (*serialization).clsidCredentialProvider = CLSID_OTPUAC;
    (*serialization).cbSerialization = buffer_size;
    (*serialization).rgbSerialization = buffer;
    S_OK
}

fn credential_pack_flags(use_wow_buffer: bool) -> u32 {
    let mut flags = CRED_PACK_PROTECTED_CREDENTIALS;
    if use_wow_buffer {
        flags |= CRED_PACK_WOW_BUFFER;
    }
    flags
}

unsafe fn retrieve_negotiate_auth_package(auth_package: *mut u32) -> HRESULT {
    let mut lsa_handle: HANDLE = ptr::null_mut();
    let status = LsaConnectUntrusted(&mut lsa_handle);
    if status != 0 {
        return hresult_from_win32(LsaNtStatusToWinError(status));
    }

    let mut package_name = b"Negotiate\0".to_vec();
    let lsa_string = LSA_STRING {
        Length: 9,
        MaximumLength: 10,
        Buffer: package_name.as_mut_ptr().cast(),
    };
    let status = LsaLookupAuthenticationPackage(lsa_handle, &lsa_string, auth_package);
    LsaDeregisterLogonProcess(lsa_handle);
    if status != 0 {
        hresult_from_win32(LsaNtStatusToWinError(status))
    } else {
        S_OK
    }
}
