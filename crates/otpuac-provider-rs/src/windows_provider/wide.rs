use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::E_OUTOFMEMORY;
use windows_sys::Win32::System::Com::CoTaskMemAlloc;
use zeroize::Zeroize;

pub(super) unsafe fn duplicate_wide_to_com(value: &[u16], out: *mut *mut u16) -> HRESULT {
    let bytes = value.len() * 2;
    let allocated = CoTaskMemAlloc(bytes) as *mut u16;
    if allocated.is_null() {
        return E_OUTOFMEMORY;
    }
    ptr::copy_nonoverlapping(value.as_ptr(), allocated, value.len());
    *out = allocated;
    windows_sys::Win32::Foundation::S_OK
}

pub(super) unsafe fn secure_zero_u16(value: &mut [u16]) {
    value.zeroize();
}

pub(super) fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

pub(super) unsafe fn wide_ptr_to_vec(value: *const u16, max_chars: usize) -> Vec<u16> {
    let mut len = 0;
    while len < max_chars && *value.add(len) != 0 {
        len += 1;
    }
    std::slice::from_raw_parts(value, len).to_vec()
}

pub(super) fn wide_vec_to_string(value: &[u16]) -> String {
    String::from_utf16_lossy(value)
}
