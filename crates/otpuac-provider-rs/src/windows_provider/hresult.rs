use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::{GetLastError, E_FAIL};

pub(super) const E_NOINTERFACE: HRESULT = 0x80004002_u32 as HRESULT;

pub(super) unsafe fn hresult_from_last_error() -> HRESULT {
    hresult_from_win32(GetLastError())
}

pub(super) fn hresult_from_win32(error: u32) -> HRESULT {
    if error == 0 {
        E_FAIL
    } else {
        (0x80070000_u32 | (error & 0xffff)) as HRESULT
    }
}
