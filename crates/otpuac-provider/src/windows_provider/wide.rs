use std::ptr;
use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::{E_OUTOFMEMORY, S_OK};
use windows_sys::Win32::System::Com::CoTaskMemAlloc;

/// # Safety
///
/// `out` must be a valid writable pointer to receive a COM-allocated UTF-16
/// string pointer. The caller becomes responsible for the COM allocation.
pub(super) unsafe fn duplicate_wide_to_com(value: &[u16], out: *mut *mut u16) -> HRESULT {
    let allocated = CoTaskMemAlloc(value.len() * 2) as *mut u16;
    if allocated.is_null() {
        return E_OUTOFMEMORY;
    }
    ptr::copy_nonoverlapping(value.as_ptr(), allocated, value.len());
    *out = allocated;
    S_OK
}

/// # Safety
///
/// `value` must point to readable UTF-16 memory for at least `max_chars`
/// elements, or to a nul-terminated string before that bound.
pub(super) unsafe fn wide_ptr_to_vec(value: *const u16, max_chars: usize) -> Vec<u16> {
    let mut len = 0;
    while len < max_chars && *value.add(len) != 0 {
        len += 1;
    }
    std::slice::from_raw_parts(value, len).to_vec()
}
