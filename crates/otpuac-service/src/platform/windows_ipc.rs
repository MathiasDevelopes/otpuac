use crate::audit;
use crate::state::RuntimeState;
use crate::unlock::{handle_unlock_request_with_limiter, RateLimiter};
#[cfg(debug_assertions)]
use otpuac_core::ProviderUnlockResponse;
use otpuac_core::{
    paths::service_state_path, ProviderUnlockRequest, Result, MAX_IPC_MESSAGE_BYTES, PIPE_NAME,
};
#[cfg(debug_assertions)]
use otpuac_windows_support::pipe::{connect_client_pipe, DEFAULT_PIPE_CONNECT_ATTEMPTS};
use otpuac_windows_support::pipe::{
    read_framed_message, wait_for_overlapped, write_framed_message, OverlappedOperation,
    OwnedHandle, DEFAULT_PIPE_CONNECT_TIMEOUT_MS,
};
use otpuac_windows_support::wide::wide_null;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum ClientPolicy {
    #[cfg(debug_assertions)]
    AllowAny,
    CredentialUiHostsOnly,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub(crate) fn serve_pipe(
    vault_path: &Path,
    should_stop: impl Fn() -> bool,
    client_policy: ClientPolicy,
) -> Result<()> {
    let state_path = state_path_for_vault(vault_path);
    let state = RuntimeState::read_from_path(&state_path)?;
    let mut limiter = RateLimiter::with_last_accepted_step(state.last_accepted_totp_step);
    while !should_stop() {
        let pipe = create_pipe()?;
        if connect(pipe.raw())? {
            if let Err(err) = handle_client(
                pipe.raw(),
                vault_path,
                &state_path,
                &mut limiter,
                client_policy,
            ) {
                audit::ipc_error(err.to_string());
                tracing::warn!("named-pipe client failed: {err}");
            }
            unsafe {
                DisconnectNamedPipe(pipe.raw());
            }
        }
    }
    Ok(())
}

fn create_pipe() -> Result<OwnedHandle> {
    let name = wide_null(PIPE_NAME);
    let (security_attributes, _security_descriptor) = pipe_security_attributes()?;
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            MAX_IPC_MESSAGE_BYTES as u32,
            MAX_IPC_MESSAGE_BYTES as u32,
            5_000,
            &security_attributes,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "CreateNamedPipeW failed with {}",
            unsafe { GetLastError() }
        )));
    }

    Ok(unsafe { OwnedHandle::from_raw(handle) })
}

fn pipe_security_attributes() -> Result<(SECURITY_ATTRIBUTES, LocalSecurityDescriptor)> {
    let sddl = wide_null("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed with {}",
            unsafe { GetLastError() }
        )));
    }

    Ok((
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        },
        LocalSecurityDescriptor(descriptor),
    ))
}

fn connect(handle: HANDLE) -> Result<bool> {
    let mut operation = OverlappedOperation::new()?;
    let ok = unsafe { ConnectNamedPipe(handle, operation.overlapped_mut()) };
    if ok != 0 {
        return Ok(true);
    }

    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Ok(true),
        ERROR_BROKEN_PIPE => Ok(false),
        ERROR_IO_PENDING => match unsafe {
            wait_for_overlapped(
                handle,
                operation.overlapped_mut(),
                "ConnectNamedPipe",
                DEFAULT_PIPE_CONNECT_TIMEOUT_MS,
            )
        }? {
            Some(_) => Ok(true),
            None => Ok(false),
        },
        err => Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "ConnectNamedPipe failed with {err}"
        ))),
    }
}

fn handle_client(
    handle: HANDLE,
    vault_path: &Path,
    state_path: &Path,
    limiter: &mut RateLimiter,
    client_policy: ClientPolicy,
) -> Result<()> {
    validate_client(handle, client_policy)?;
    let request = read_framed_message::<ProviderUnlockRequest>(handle)?;
    let previous_step = limiter.last_accepted_step();
    let mut response = handle_unlock_request_with_limiter(vault_path, request, true, limiter)?;
    if limiter.last_accepted_step() != previous_step {
        RuntimeState::new(limiter.last_accepted_step()).write_to_path(state_path)?;
    }

    let write_result = write_framed_message(handle, &response);
    response.zeroize_secrets();
    write_result?;

    if unsafe { FlushFileBuffers(handle) } == 0 {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "FlushFileBuffers failed with {}",
            unsafe { GetLastError() }
        )));
    }
    Ok(())
}

#[cfg(debug_assertions)]
pub(crate) fn pipe_round_trip(request: ProviderUnlockRequest) -> Result<ProviderUnlockResponse> {
    let pipe = connect_client_pipe(
        PIPE_NAME,
        DEFAULT_PIPE_CONNECT_ATTEMPTS,
        DEFAULT_PIPE_CONNECT_TIMEOUT_MS,
    )?;

    let result = (|| {
        write_framed_message(pipe.raw(), &request)?;
        read_framed_message::<ProviderUnlockResponse>(pipe.raw())
    })();
    result
}

fn validate_client(handle: HANDLE, _policy: ClientPolicy) -> Result<()> {
    #[cfg(debug_assertions)]
    if matches!(_policy, ClientPolicy::AllowAny) {
        return Ok(());
    }

    let image = client_process_image(handle)?;
    if is_allowed_credential_ui_host(&image) {
        Ok(())
    } else {
        Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "unauthorized named-pipe client process: {image}"
        )))
    }
}

fn client_process_image(handle: HANDLE) -> Result<String> {
    let mut process_id = 0_u32;
    let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) };
    if ok == 0 {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "GetNamedPipeClientProcessId failed with {}",
            unsafe { GetLastError() }
        )));
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "OpenProcess({process_id}) failed with {}",
            unsafe { GetLastError() }
        )));
    }
    let _process = unsafe { OwnedHandle::from_raw(process) };

    let mut image = vec![0_u16; 32768];
    let mut len = image.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "QueryFullProcessImageNameW failed with {}",
            unsafe { GetLastError() }
        )));
    }
    Ok(String::from_utf16_lossy(&image[..len as usize]))
}

fn is_allowed_credential_ui_host(image: &str) -> bool {
    let system32 = system32_dir().unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"));

    ["consent.exe", "LogonUI.exe", "CredentialUIBroker.exe"]
        .iter()
        .any(|exe| {
            normalize_windows_path(image)
                == normalize_windows_path(&system32.join(exe).display().to_string())
        })
}

fn system32_dir() -> Option<PathBuf> {
    let mut buf = vec![0_u16; 32768];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 || len as usize > buf.len() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

fn state_path_for_vault(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .map(service_state_path)
        .unwrap_or_else(|| PathBuf::from(otpuac_core::paths::SERVICE_STATE_FILE))
}

fn normalize_windows_path(path: &str) -> String {
    path.trim_start_matches("\\\\?\\")
        .replace('/', "\\")
        .to_ascii_lowercase()
}
