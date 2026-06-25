use super::hresult::E_NOINTERFACE;
use super::ids::{guid_eq, IID_ICLASS_FACTORY, IID_IUNKNOWN};
use super::provider;
use super::{dll_add_ref, dll_release};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{BOOL, CLASS_E_NOAGGREGATION, E_INVALIDARG, S_OK};

#[repr(C)]
struct ClassFactory {
    vtbl: *const ClassFactoryVtbl,
    ref_count: AtomicU32,
}

#[repr(C)]
struct ClassFactoryVtbl {
    query_interface:
        unsafe extern "system" fn(*mut ClassFactory, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut ClassFactory) -> u32,
    release: unsafe extern "system" fn(*mut ClassFactory) -> u32,
    create_instance: unsafe extern "system" fn(
        *mut ClassFactory,
        *mut c_void,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    lock_server: unsafe extern "system" fn(*mut ClassFactory, BOOL) -> HRESULT,
}

static CLASS_FACTORY_VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
    query_interface: class_factory_query_interface,
    add_ref: class_factory_add_ref,
    release: class_factory_release,
    create_instance: class_factory_create_instance,
    lock_server: class_factory_lock_server,
};

pub(super) unsafe fn create_class_object(riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
    let factory = Box::into_raw(Box::new(ClassFactory {
        vtbl: &CLASS_FACTORY_VTBL,
        ref_count: AtomicU32::new(1),
    }));
    dll_add_ref();
    let hr = class_factory_query_interface(factory, riid, ppv);
    class_factory_release(factory);
    hr
}

unsafe extern "system" fn class_factory_query_interface(
    this: *mut ClassFactory,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() {
        return E_INVALIDARG;
    }
    *ppv = ptr::null_mut();
    if riid.is_null() {
        return E_INVALIDARG;
    }
    if guid_eq(&*riid, &IID_IUNKNOWN) || guid_eq(&*riid, &IID_ICLASS_FACTORY) {
        class_factory_add_ref(this);
        *ppv = this.cast();
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "system" fn class_factory_add_ref(this: *mut ClassFactory) -> u32 {
    (*this).ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn class_factory_release(this: *mut ClassFactory) -> u32 {
    let count = (*this).ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        drop(Box::from_raw(this));
        dll_release();
    }
    count
}

unsafe extern "system" fn class_factory_create_instance(
    _this: *mut ClassFactory,
    outer: *mut c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() {
        return E_INVALIDARG;
    }
    *ppv = ptr::null_mut();
    if !outer.is_null() {
        return CLASS_E_NOAGGREGATION;
    }

    provider::create_provider(riid, ppv)
}

unsafe extern "system" fn class_factory_lock_server(
    _this: *mut ClassFactory,
    lock: BOOL,
) -> HRESULT {
    if lock != 0 {
        dll_add_ref();
    } else {
        dll_release();
    }
    S_OK
}
