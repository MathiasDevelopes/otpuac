use crate::OTPUAC_PROVIDER_CLSID;
use std::ptr;
use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CLASSES_ROOT,
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

use super::hresult::{hresult_from_last_error, hresult_from_win32};
use super::wide::wide_null;

const PROVIDER_NAME: &str = "OTPUAC Credential Provider";
const THREADING_MODEL_VALUE: &str = "Apartment";

pub(super) unsafe fn register_server() -> Result<(), HRESULT> {
    let module_path = module_path()?;
    let clsid = OTPUAC_PROVIDER_CLSID;
    let clsid_key = clsid_key(clsid);
    let inproc_key = inproc_server_key(clsid);
    set_registry_string(HKEY_CLASSES_ROOT, &clsid_key, None, PROVIDER_NAME)?;
    set_registry_string(HKEY_CLASSES_ROOT, &inproc_key, None, &module_path)?;
    set_registry_string(
        HKEY_CLASSES_ROOT,
        &inproc_key,
        Some("ThreadingModel"),
        THREADING_MODEL_VALUE,
    )?;

    let provider_key = credential_provider_key(clsid);
    set_registry_string(HKEY_LOCAL_MACHINE, &provider_key, None, PROVIDER_NAME)?;
    Ok(())
}

pub(super) unsafe fn unregister_server() -> Result<(), HRESULT> {
    let clsid = OTPUAC_PROVIDER_CLSID;
    let clsid_key = wide_null(&clsid_key(clsid));
    RegDeleteTreeW(HKEY_CLASSES_ROOT, clsid_key.as_ptr());
    let provider_key = wide_null(&credential_provider_key(clsid));
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, provider_key.as_ptr());
    Ok(())
}

fn clsid_key(clsid: &str) -> String {
    format!(r"CLSID\{clsid}")
}

fn inproc_server_key(clsid: &str) -> String {
    format!(r"{}\InprocServer32", clsid_key(clsid))
}

fn credential_provider_key(clsid: &str) -> String {
    format!(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{clsid}"
    )
}

unsafe fn set_registry_string(
    root: HKEY,
    key_path: &str,
    value_name: Option<&str>,
    value: &str,
) -> Result<(), HRESULT> {
    let mut key: HKEY = ptr::null_mut();
    let path = wide_null(key_path);
    let status = RegCreateKeyExW(
        root,
        path.as_ptr(),
        0,
        ptr::null(),
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        ptr::null(),
        &mut key,
        ptr::null_mut(),
    );
    if status != 0 {
        return Err(hresult_from_win32(status));
    }

    let name = value_name.map(wide_null);
    let value_w = wide_null(value);
    let name_ptr = name.as_ref().map(|v| v.as_ptr()).unwrap_or(ptr::null());
    let bytes = std::slice::from_raw_parts(value_w.as_ptr().cast::<u8>(), value_w.len() * 2);
    let status = RegSetValueExW(key, name_ptr, 0, REG_SZ, bytes.as_ptr(), bytes.len() as u32);
    RegCloseKey(key);
    if status != 0 {
        Err(hresult_from_win32(status))
    } else {
        Ok(())
    }
}

unsafe fn module_path() -> Result<String, HRESULT> {
    let mut module_handle: HMODULE = ptr::null_mut();
    let ok = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        register_server as *const () as *const u16,
        &mut module_handle,
    );
    if ok == 0 {
        return Err(hresult_from_last_error());
    }

    let mut buf = vec![0_u16; 32768];
    let len = GetModuleFileNameW(module_handle, buf.as_mut_ptr(), buf.len() as u32);
    if len == 0 {
        return Err(hresult_from_last_error());
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}
