use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::{E_OUTOFMEMORY, S_OK};
use windows_sys::Win32::System::Com::CoTaskMemAlloc;
use zeroize::Zeroize;

/// # Safety
///
/// `out` must be a valid writable pointer to receive a COM-allocated UTF-16
/// string pointer. The caller becomes responsible for the COM allocation.
pub unsafe fn duplicate_wide_to_com(value: &[u16], out: *mut *mut u16) -> HRESULT {
    let bytes = value.len() * 2;
    let allocated = unsafe { CoTaskMemAlloc(bytes) as *mut u16 };
    if allocated.is_null() {
        return E_OUTOFMEMORY;
    }
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), allocated, value.len());
        *out = allocated;
    }
    S_OK
}

pub fn secure_zero_u16(value: &mut [u16]) {
    value.zeroize();
}

pub fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

pub fn wide_null_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(once(0)).collect()
}

/// # Safety
///
/// `value` must point to readable UTF-16 memory for at least `max_chars`
/// elements, or to a nul-terminated string before that bound.
pub unsafe fn wide_ptr_to_vec(value: *const u16, max_chars: usize) -> Vec<u16> {
    let mut len = 0;
    while len < max_chars && unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    unsafe { std::slice::from_raw_parts(value, len).to_vec() }
}

pub fn wide_vec_to_string(value: &[u16]) -> String {
    String::from_utf16_lossy(value)
}

/// # Safety
///
/// `ptr` must point to a readable nul-terminated UTF-16 string.
pub unsafe fn string_from_wide_ptr(ptr: *const u16) -> String {
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}
