use crate::build_unlock_request;
use otpuac_core::{
    decode_frame, encode_frame, ProviderUnlockResponse, UnlockDecision, MAX_IPC_MESSAGE_BYTES,
    PIPE_NAME,
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

use super::wide::wide_null;

const PIPE_CONNECT_ATTEMPTS: u32 = 5;
const PIPE_CONNECT_WAIT_MS: u32 = 1_000;
const PIPE_IO_TIMEOUT_MS: u32 = 5_000;
const IPC_FRAME_LENGTH_BYTES: usize = size_of::<u32>();

pub(super) fn request_unlock(code: &str) -> Result<UnlockDecision, String> {
    let request_id = format!(
        "provider-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    );
    let request = build_unlock_request(request_id, code.to_string());
    let mut frame = encode_frame(&request).map_err(|err| err.to_string())?;
    let response_frame = unsafe { pipe_round_trip(&frame) };
    frame.zeroize();
    let mut response_frame = response_frame?;
    let response =
        decode_frame::<ProviderUnlockResponse>(&response_frame).map_err(|err| err.to_string());
    response_frame.zeroize();
    let response = response?;
    Ok(response.into_decision())
}

unsafe fn pipe_round_trip(request: &[u8]) -> Result<Vec<u8>, String> {
    let handle = connect_pipe()?;

    let result = (|| {
        write_all(handle.0, request)?;
        read_frame(handle.0)
    })();
    result
}

unsafe fn connect_pipe() -> Result<PipeHandle, String> {
    let pipe_name = wide_null(PIPE_NAME);
    let mut attempts = 0;
    let handle = loop {
        let handle = CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            ptr::null_mut(),
        );
        if handle != INVALID_HANDLE_VALUE {
            break handle;
        }
        let err = GetLastError();
        if err != ERROR_PIPE_BUSY || attempts >= PIPE_CONNECT_ATTEMPTS {
            return Err(format!("Could not connect to OTPUAC service pipe: {err}"));
        }
        attempts += 1;
        if WaitNamedPipeW(pipe_name.as_ptr(), PIPE_CONNECT_WAIT_MS) == 0 {
            return Err(format!(
                "Timed out waiting for OTPUAC service pipe: {}",
                GetLastError()
            ));
        }
    };
    Ok(PipeHandle(handle))
}

unsafe fn read_frame(handle: HANDLE) -> Result<Vec<u8>, String> {
    let mut len_buf = [0_u8; IPC_FRAME_LENGTH_BYTES];
    read_exact(handle, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_MESSAGE_BYTES {
        return Err(format!("service response too large: {len}"));
    }
    let mut frame = Vec::with_capacity(IPC_FRAME_LENGTH_BYTES + len);
    frame.extend_from_slice(&len_buf);
    let mut payload = vec![0_u8; len];
    read_exact(handle, &mut payload)?;
    frame.extend_from_slice(&payload);
    Ok(frame)
}

struct PipeHandle(HANDLE);

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

unsafe fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < buf.len() {
        let read = read_once(handle, &mut buf[offset..])?;
        if read == 0 {
            return Err("ReadFile returned end-of-stream".to_string());
        }
        offset += read;
    }
    Ok(())
}

unsafe fn write_all(handle: HANDLE, buf: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < buf.len() {
        let written = write_once(handle, &buf[offset..])?;
        if written == 0 {
            return Err("WriteFile returned zero bytes written".to_string());
        }
        offset += written;
    }
    Ok(())
}

unsafe fn read_once(handle: HANDLE, buf: &mut [u8]) -> Result<usize, String> {
    let mut operation = OverlappedOperation::new()?;
    let ok = ReadFile(
        handle,
        buf.as_mut_ptr().cast(),
        buf.len() as u32,
        ptr::null_mut(),
        &mut operation.overlapped,
    );
    complete_overlapped(handle, &mut operation.overlapped, ok, "ReadFile")
}

unsafe fn write_once(handle: HANDLE, buf: &[u8]) -> Result<usize, String> {
    let mut operation = OverlappedOperation::new()?;
    let ok = WriteFile(
        handle,
        buf.as_ptr().cast(),
        buf.len() as u32,
        ptr::null_mut(),
        &mut operation.overlapped,
    );
    complete_overlapped(handle, &mut operation.overlapped, ok, "WriteFile")
}

unsafe fn complete_overlapped(
    handle: HANDLE,
    overlapped: *mut OVERLAPPED,
    immediate_ok: i32,
    operation: &str,
) -> Result<usize, String> {
    if immediate_ok == 0 {
        let err = GetLastError();
        if err != ERROR_IO_PENDING {
            return Err(format!("{operation} failed: {err}"));
        }

        match WaitForSingleObject((*overlapped).hEvent, PIPE_IO_TIMEOUT_MS) {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                CancelIoEx(handle, overlapped);
                WaitForSingleObject((*overlapped).hEvent, INFINITE);
                return Err(format!(
                    "{operation} timed out after {PIPE_IO_TIMEOUT_MS} ms"
                ));
            }
            wait => {
                CancelIoEx(handle, overlapped);
                WaitForSingleObject((*overlapped).hEvent, INFINITE);
                return Err(format!("{operation} wait failed: {wait}"));
            }
        }
    }

    let mut transferred = 0_u32;
    let ok = GetOverlappedResult(handle, overlapped, &mut transferred, 0);
    if ok == 0 {
        return Err(format!("{operation} completion failed: {}", GetLastError()));
    }
    Ok(transferred as usize)
}

struct OverlappedOperation {
    event: HANDLE,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    unsafe fn new() -> Result<Self, String> {
        let event = CreateEventW(ptr::null(), 1, 0, ptr::null());
        if event.is_null() {
            return Err(format!("CreateEventW failed: {}", GetLastError()));
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
