mod class_factory;
mod credential;
mod credential_pack;
mod fields;
mod hresult;
mod ids;
mod ipc;
mod provider;
mod registry;

use registry::{register_server, unregister_server};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicIsize, Ordering};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{
    BOOL, CLASS_E_CLASSNOTAVAILABLE, E_INVALIDARG, HINSTANCE, S_FALSE, S_OK,
};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;

const DLL_PROCESS_ATTACH: u32 = 1;

static DLL_REF_COUNT: AtomicIsize = AtomicIsize::new(0);

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinst);
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() {
        return E_INVALIDARG;
    }
    *ppv = ptr::null_mut();

    if rclsid.is_null() || !ids::guid_eq(&*rclsid, &ids::CLSID_OTPUAC) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    class_factory::create_class_object(riid, ppv)
}

#[no_mangle]
pub unsafe extern "system" fn DllCanUnloadNow() -> HRESULT {
    if DLL_REF_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllRegisterServer() -> HRESULT {
    match register_server() {
        Ok(()) => S_OK,
        Err(hr) => hr,
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllUnregisterServer() -> HRESULT {
    match unregister_server() {
        Ok(()) => S_OK,
        Err(hr) => hr,
    }
}

pub(super) fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub(super) fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}
