use crate::wide::wide_null;
use otpuac_core::{
    decode_frame, encode_frame, OtpuacError, Result, MAX_IPC_MESSAGE_BYTES, PIPE_NAME,
};
use std::mem::{size_of, zeroed};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use zeroize::Zeroize;

pub const DEFAULT_PIPE_CONNECT_ATTEMPTS: u32 = 5;
pub const DEFAULT_PIPE_CONNECT_TIMEOUT_MS: u32 = 1_000;
pub const DEFAULT_PIPE_IO_TIMEOUT_MS: u32 = 5_000;

const IPC_FRAME_LENGTH_BYTES: usize = size_of::<u32>();

pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// # Safety
    ///
    /// `handle` must be a valid owned Windows handle that can be closed with
    /// `CloseHandle`, and ownership must be transferred to the returned value.
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub struct OverlappedOperation {
    event: HANDLE,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    pub fn new() -> Result<Self> {
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(OtpuacError::InvalidIpc(format!(
                "CreateEventW failed with {}",
                unsafe { GetLastError() }
            )));
        }
        let mut overlapped = unsafe { zeroed::<OVERLAPPED>() };
        overlapped.hEvent = event;
        Ok(Self { event, overlapped })
    }

    pub fn overlapped_mut(&mut self) -> *mut OVERLAPPED {
        &mut self.overlapped
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

pub fn connect_default_client_pipe() -> Result<OwnedHandle> {
    connect_client_pipe(
        PIPE_NAME,
        DEFAULT_PIPE_CONNECT_ATTEMPTS,
        DEFAULT_PIPE_CONNECT_TIMEOUT_MS,
    )
}

pub fn connect_client_pipe(
    pipe_name: &str,
    attempts: u32,
    connect_wait_ms: u32,
) -> Result<OwnedHandle> {
    let pipe_name = wide_null(pipe_name);
    let mut attempt = 0;
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
        if err != ERROR_PIPE_BUSY || attempt >= attempts {
            return Err(OtpuacError::InvalidIpc(format!(
                "Could not connect to OTPUAC service pipe: {err}"
            )));
        }
        attempt += 1;
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), connect_wait_ms) } == 0 {
            return Err(OtpuacError::InvalidIpc(format!(
                "Timed out waiting for OTPUAC service pipe: {}",
                unsafe { GetLastError() }
            )));
        }
    };
    Ok(unsafe { OwnedHandle::from_raw(handle) })
}

pub fn read_framed_message<T: for<'de> serde::Deserialize<'de>>(handle: HANDLE) -> Result<T> {
    let mut frame = read_frame(handle)?;
    let decoded = decode_frame(&frame);
    frame.zeroize();
    decoded
}

pub fn write_framed_message<T: serde::Serialize>(handle: HANDLE, message: &T) -> Result<()> {
    let mut frame = encode_frame(message)?;
    let result = write_all(handle, &frame);
    frame.zeroize();
    result
}

pub fn read_frame(handle: HANDLE) -> Result<Vec<u8>> {
    let mut len_buf = [0_u8; IPC_FRAME_LENGTH_BYTES];
    read_exact(handle, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_MESSAGE_BYTES {
        return Err(OtpuacError::InvalidIpc(format!(
            "incoming message too large: {len}"
        )));
    }

    let mut frame = Vec::with_capacity(IPC_FRAME_LENGTH_BYTES + len);
    frame.extend_from_slice(&len_buf);
    let mut payload = vec![0_u8; len];
    read_exact(handle, &mut payload)?;
    frame.extend_from_slice(&payload);
    payload.zeroize();
    Ok(frame)
}

pub fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let read = read_once(handle, &mut buf[offset..])?;
        if read == 0 {
            return Err(OtpuacError::InvalidIpc(
                "ReadFile returned end-of-stream".to_string(),
            ));
        }
        offset += read;
    }
    Ok(())
}

pub fn write_all(handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let written = write_once(handle, &buf[offset..])?;
        if written == 0 {
            return Err(OtpuacError::InvalidIpc(
                "WriteFile returned zero bytes written".to_string(),
            ));
        }
        offset += written;
    }
    Ok(())
}

fn read_once(handle: HANDLE, buf: &mut [u8]) -> Result<usize> {
    let mut operation = OverlappedOperation::new()?;
    let ok = unsafe {
        ReadFile(
            handle,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            ptr::null_mut(),
            operation.overlapped_mut(),
        )
    };
    unsafe { complete_overlapped(handle, operation.overlapped_mut(), ok, "ReadFile") }
}

fn write_once(handle: HANDLE, buf: &[u8]) -> Result<usize> {
    let mut operation = OverlappedOperation::new()?;
    let ok = unsafe {
        WriteFile(
            handle,
            buf.as_ptr().cast(),
            buf.len() as u32,
            ptr::null_mut(),
            operation.overlapped_mut(),
        )
    };
    unsafe { complete_overlapped(handle, operation.overlapped_mut(), ok, "WriteFile") }
}

/// # Safety
///
/// `overlapped` must point to a valid `OVERLAPPED` whose event handle remains
/// valid for the duration of this call.
pub unsafe fn complete_overlapped(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    immediate_ok: i32,
    operation: &str,
) -> Result<usize> {
    if immediate_ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(OtpuacError::InvalidIpc(format!(
                "{operation} failed with {err}"
            )));
        }

        return unsafe {
            wait_for_overlapped(handle, overlapped, operation, DEFAULT_PIPE_IO_TIMEOUT_MS)
        }?
        .ok_or_else(|| {
            OtpuacError::InvalidIpc(format!(
                "{operation} timed out after {DEFAULT_PIPE_IO_TIMEOUT_MS} ms"
            ))
        });
    }

    unsafe { get_overlapped_result(handle, overlapped, operation) }
}

/// # Safety
///
/// `overlapped` must point to a valid `OVERLAPPED` whose event handle remains
/// valid for the duration of this call.
pub unsafe fn wait_for_overlapped(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    operation: &str,
    timeout_ms: u32,
) -> Result<Option<usize>> {
    match unsafe { WaitForSingleObject((*overlapped).hEvent, timeout_ms) } {
        WAIT_OBJECT_0 => unsafe { get_overlapped_result(handle, overlapped, operation) }.map(Some),
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
            Err(OtpuacError::InvalidIpc(format!(
                "{operation} wait failed with {wait}"
            )))
        }
    }
}

unsafe fn get_overlapped_result(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    operation: &str,
) -> Result<usize> {
    let mut transferred = 0_u32;
    let ok = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 0) };
    if ok == 0 {
        return Err(OtpuacError::InvalidIpc(format!(
            "{operation} completion failed with {}",
            unsafe { GetLastError() }
        )));
    }
    Ok(transferred as usize)
}
