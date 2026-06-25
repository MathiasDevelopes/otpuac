use super::error::win_error;
use otpuac_core::Result;
use otpuac_windows::wide::wide_null;
use std::mem::size_of;
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, KEY_WRITE, REG_DWORD,
    REG_OPTION_NON_VOLATILE,
};

pub(super) struct RegistryKey(pub(super) HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

pub(super) fn create_registry_key(root: HKEY, key_path: &str) -> Result<RegistryKey> {
    let mut key: HKEY = ptr::null_mut();
    let key_path = wide_null(key_path);
    let status = unsafe {
        RegCreateKeyExW(
            root,
            key_path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(win_error("RegCreateKeyExW", status));
    }
    Ok(RegistryKey(key))
}

pub(super) fn delete_registry_tree(root: HKEY, key_path: &str) -> Result<()> {
    let key_path = wide_null(key_path);
    let status = unsafe { RegDeleteTreeW(root, key_path.as_ptr()) };
    if status != 0 && status != ERROR_FILE_NOT_FOUND {
        return Err(win_error("RegDeleteTreeW", status));
    }
    Ok(())
}

pub(super) fn set_registry_string(
    key: HKEY,
    name: &str,
    value: &str,
    value_type: u32,
) -> Result<()> {
    let name_w = wide_null(name);
    let value_w = wide_null(value);
    let bytes =
        unsafe { std::slice::from_raw_parts(value_w.as_ptr().cast::<u8>(), value_w.len() * 2) };
    let status = unsafe {
        RegSetValueExW(
            key,
            name_w.as_ptr(),
            0,
            value_type,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if status != 0 {
        return Err(win_error("RegSetValueExW", status));
    }
    Ok(())
}

pub(super) fn set_registry_dword(key: HKEY, name: &str, value: u32) -> Result<()> {
    let name_w = wide_null(name);
    let bytes = unsafe {
        std::slice::from_raw_parts((&value as *const u32).cast::<u8>(), size_of::<u32>())
    };
    let status = unsafe {
        RegSetValueExW(
            key,
            name_w.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if status != 0 {
        return Err(win_error("RegSetValueExW", status));
    }
    Ok(())
}
