use crate::audit;
use crate::state::RuntimeState;
use crate::unlock::{handle_unlock_request_with_limiter, RateLimiter};
#[cfg(debug_assertions)]
use otpuac_core::ProviderUnlockResponse;
use otpuac_core::{
    decode_frame, encode_frame, paths::service_state_path, ProviderUnlockRequest, Result,
    MAX_IPC_MESSAGE_BYTES, PIPE_NAME,
};
use std::ffi::OsStr;
use std::iter::once;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING,
    ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(debug_assertions)]
use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
#[cfg(debug_assertions)]
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
#[cfg(debug_assertions)]
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject, INFINITE,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use zeroize::Zeroize;

const PIPE_CONNECT_TIMEOUT_MS: u32 = 1_000;
#[cfg(debug_assertions)]
const PIPE_CONNECT_ATTEMPTS: u32 = 5;
const PIPE_IO_TIMEOUT_MS: u32 = 5_000;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ClientPolicy {
    #[cfg(debug_assertions)]
    AllowAny,
    CredentialUiHostsOnly,
}

struct PipeHandle(HANDLE);

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
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
        if connect(pipe.0)? {
            if let Err(err) =
                handle_client(pipe.0, vault_path, &state_path, &mut limiter, client_policy)
            {
                audit::ipc_error(err.to_string());
                tracing::warn!("named-pipe client failed: {err}");
            }
            unsafe {
                DisconnectNamedPipe(pipe.0);
            }
        }
    }
    Ok(())
}

fn create_pipe() -> Result<PipeHandle> {
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

    Ok(PipeHandle(handle))
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
    let mut operation = unsafe { OverlappedOperation::new()? };
    let ok = unsafe { ConnectNamedPipe(handle, &mut operation.overlapped) };
    if ok != 0 {
        return Ok(true);
    }

    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Ok(true),
        ERROR_BROKEN_PIPE => Ok(false),
        ERROR_IO_PENDING => match wait_for_overlapped(
            handle,
            &mut operation.overlapped,
            "ConnectNamedPipe",
            PIPE_CONNECT_TIMEOUT_MS,
        )? {
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
    let request = read_message::<ProviderUnlockRequest>(handle)?;
    let previous_step = limiter.last_accepted_step();
    let mut response = handle_unlock_request_with_limiter(vault_path, request, true, limiter)?;
    if limiter.last_accepted_step() != previous_step {
        RuntimeState::new(limiter.last_accepted_step()).write_to_path(state_path)?;
    }

    let write_result = write_message(handle, &response);
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
    let pipe = connect_client_pipe()?;

    let result = (|| {
        write_message(pipe.0, &request)?;
        read_message::<ProviderUnlockResponse>(pipe.0)
    })();
    result
}

#[cfg(debug_assertions)]
fn connect_client_pipe() -> Result<PipeHandle> {
    let pipe_name = wide_null(PIPE_NAME);
    let mut attempts = 0;
    let handle = loop {
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            break handle;
        }

        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_BUSY || attempts >= PIPE_CONNECT_ATTEMPTS {
            return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "Could not connect to OTPUAC service pipe: {err}"
            )));
        }
        attempts += 1;
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), PIPE_CONNECT_TIMEOUT_MS) } == 0 {
            return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "Timed out waiting for OTPUAC service pipe: {}",
                unsafe { GetLastError() }
            )));
        }
    };
    Ok(PipeHandle(handle))
}

fn read_message<T: for<'de> serde::Deserialize<'de>>(handle: HANDLE) -> Result<T> {
    let mut len_buf = [0_u8; 4];
    read_exact(handle, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_MESSAGE_BYTES {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "incoming message too large: {len}"
        )));
    }

    let mut payload = vec![0_u8; len];
    read_exact(handle, &mut payload)?;
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload);
    let decoded = decode_frame(&frame);
    frame.zeroize();
    payload.zeroize();
    decoded
}

fn write_message<T: serde::Serialize>(handle: HANDLE, message: &T) -> Result<()> {
    let mut frame = encode_frame(message)?;
    let result = write_all(handle, &frame);
    frame.zeroize();
    result
}

fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let read = read_once(handle, &mut buf[offset..])?;
        if read == 0 {
            return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "ReadFile failed with {}",
                unsafe { GetLastError() }
            )));
        }
        offset += read;
    }
    Ok(())
}

fn write_all(handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let written = write_once(handle, &buf[offset..])?;
        if written == 0 {
            return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "WriteFile failed with {}",
                unsafe { GetLastError() }
            )));
        }
        offset += written;
    }
    Ok(())
}

fn read_once(handle: HANDLE, buf: &mut [u8]) -> Result<usize> {
    let mut operation = unsafe { OverlappedOperation::new()? };
    let ok = unsafe {
        ReadFile(
            handle,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            ptr::null_mut(),
            &mut operation.overlapped,
        )
    };
    complete_overlapped(handle, &mut operation.overlapped, ok, "ReadFile")
}

fn write_once(handle: HANDLE, buf: &[u8]) -> Result<usize> {
    let mut operation = unsafe { OverlappedOperation::new()? };
    let ok = unsafe {
        WriteFile(
            handle,
            buf.as_ptr().cast(),
            buf.len() as u32,
            ptr::null_mut(),
            &mut operation.overlapped,
        )
    };
    complete_overlapped(handle, &mut operation.overlapped, ok, "WriteFile")
}

fn complete_overlapped(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    immediate_ok: i32,
    operation: &str,
) -> Result<usize> {
    if immediate_ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "{operation} failed with {err}"
            )));
        }

        return wait_for_overlapped(handle, overlapped, operation, PIPE_IO_TIMEOUT_MS)?.ok_or_else(
            || {
                otpuac_core::OtpuacError::InvalidIpc(format!(
                    "{operation} timed out after {PIPE_IO_TIMEOUT_MS} ms"
                ))
            },
        );
    }

    get_overlapped_result(handle, overlapped, operation)
}

fn wait_for_overlapped(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    operation: &str,
    timeout_ms: u32,
) -> Result<Option<usize>> {
    match unsafe { WaitForSingleObject((*overlapped).hEvent, timeout_ms) } {
        WAIT_OBJECT_0 => get_overlapped_result(handle, overlapped, operation).map(Some),
        WAIT_TIMEOUT => {
            unsafe {
                CancelIoEx(handle, overlapped);
                WaitForSingleObject((*overlapped).hEvent, INFINITE);
            }
            Ok(None)
        }
        wait => {
            unsafe {
                CancelIoEx(handle, overlapped);
                WaitForSingleObject((*overlapped).hEvent, INFINITE);
            }
            Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "{operation} wait failed with {wait}"
            )))
        }
    }
}

fn get_overlapped_result(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    operation: &str,
) -> Result<usize> {
    let mut transferred = 0_u32;
    let ok = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 0) };
    if ok == 0 {
        return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
            "{operation} completion failed with {}",
            unsafe { GetLastError() }
        )));
    }
    Ok(transferred as usize)
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
    let _process = PipeHandle(process);

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

struct OverlappedOperation {
    event: HANDLE,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    unsafe fn new() -> Result<Self> {
        let event = CreateEventW(ptr::null(), 1, 0, ptr::null());
        if event.is_null() {
            return Err(otpuac_core::OtpuacError::InvalidIpc(format!(
                "CreateEventW failed with {}",
                GetLastError()
            )));
        }
        let mut overlapped = zeroed::<OVERLAPPED>();
        overlapped.hEvent = event;
        Ok(Self { event, overlapped })
    }
}

impl Drop for OverlappedOperation {
    fn drop(&mut self) {
        if !self.event.is_null() {
            unsafe {
                CloseHandle(self.event);
            }
        }
    }
}

fn normalize_windows_path(path: &str) -> String {
    path.trim_start_matches("\\\\?\\")
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}
