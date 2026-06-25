use super::credential::{self, Credential};
use super::fields::{allocate_field_descriptor, FIELD_COUNT};
use super::hresult::E_NOINTERFACE;
use super::ids::{
    guid_eq, IID_ICREDENTIAL_PROVIDER, IID_ICREDENTIAL_PROVIDER_SET_USER_ARRAY, IID_IUNKNOWN,
};
use super::{dll_add_ref, dll_release};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{BOOL, E_INVALIDARG, E_NOTIMPL, S_OK};
use windows_sys::Win32::UI::Shell::{
    CPUS_CREDUI,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION as CredentialProviderCredentialSerialization,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR as CredentialProviderFieldDescriptor,
    CREDENTIAL_PROVIDER_NO_DEFAULT, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

#[repr(C)]
struct Provider {
    vtbl: *const ProviderVtbl,
    user_array_interface: ProviderSetUserArrayInterface,
    ref_count: AtomicU32,
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    cred_ui_flags: u32,
    credential: *mut Credential,
}

#[repr(C)]
struct ProviderVtbl {
    query_interface:
        unsafe extern "system" fn(*mut Provider, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut Provider) -> u32,
    release: unsafe extern "system" fn(*mut Provider) -> u32,
    set_usage_scenario: unsafe extern "system" fn(
        *mut Provider,
        CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        u32,
    ) -> HRESULT,
    set_serialization: unsafe extern "system" fn(
        *mut Provider,
        *const CredentialProviderCredentialSerialization,
    ) -> HRESULT,
    advise: unsafe extern "system" fn(*mut Provider, *mut c_void, usize) -> HRESULT,
    unadvise: unsafe extern "system" fn(*mut Provider) -> HRESULT,
    get_field_descriptor_count: unsafe extern "system" fn(*mut Provider, *mut u32) -> HRESULT,
    get_field_descriptor_at: unsafe extern "system" fn(
        *mut Provider,
        u32,
        *mut *mut CredentialProviderFieldDescriptor,
    ) -> HRESULT,
    get_credential_count:
        unsafe extern "system" fn(*mut Provider, *mut u32, *mut u32, *mut BOOL) -> HRESULT,
    get_credential_at: unsafe extern "system" fn(*mut Provider, u32, *mut *mut c_void) -> HRESULT,
}

#[repr(C)]
struct ProviderSetUserArrayInterface {
    vtbl: *const ProviderSetUserArrayVtbl,
    provider: *mut Provider,
}

#[repr(C)]
struct ProviderSetUserArrayVtbl {
    query_interface: unsafe extern "system" fn(
        *mut ProviderSetUserArrayInterface,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut ProviderSetUserArrayInterface) -> u32,
    release: unsafe extern "system" fn(*mut ProviderSetUserArrayInterface) -> u32,
    set_user_array:
        unsafe extern "system" fn(*mut ProviderSetUserArrayInterface, *mut c_void) -> HRESULT,
}

static PROVIDER_VTBL: ProviderVtbl = ProviderVtbl {
    query_interface: provider_query_interface,
    add_ref: provider_add_ref,
    release: provider_release,
    set_usage_scenario: provider_set_usage_scenario,
    set_serialization: provider_set_serialization,
    advise: provider_advise,
    unadvise: provider_unadvise,
    get_field_descriptor_count: provider_get_field_descriptor_count,
    get_field_descriptor_at: provider_get_field_descriptor_at,
    get_credential_count: provider_get_credential_count,
    get_credential_at: provider_get_credential_at,
};

static PROVIDER_SET_USER_ARRAY_VTBL: ProviderSetUserArrayVtbl = ProviderSetUserArrayVtbl {
    query_interface: provider_set_user_array_query_interface,
    add_ref: provider_set_user_array_add_ref,
    release: provider_set_user_array_release,
    set_user_array: provider_set_user_array,
};

pub(super) unsafe fn create_provider(riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
    let provider = Box::into_raw(Box::new(Provider {
        vtbl: &PROVIDER_VTBL,
        user_array_interface: ProviderSetUserArrayInterface {
            vtbl: &PROVIDER_SET_USER_ARRAY_VTBL,
            provider: ptr::null_mut(),
        },
        ref_count: AtomicU32::new(1),
        usage_scenario: 0,
        cred_ui_flags: 0,
        credential: ptr::null_mut(),
    }));
    (*provider).user_array_interface.provider = provider;
    dll_add_ref();
    let hr = provider_query_interface(provider, riid, ppv);
    provider_release(provider);
    hr
}

unsafe extern "system" fn provider_query_interface(
    this: *mut Provider,
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
    if guid_eq(&*riid, &IID_IUNKNOWN) || guid_eq(&*riid, &IID_ICREDENTIAL_PROVIDER) {
        provider_add_ref(this);
        *ppv = this.cast();
        S_OK
    } else if guid_eq(&*riid, &IID_ICREDENTIAL_PROVIDER_SET_USER_ARRAY) {
        provider_add_ref(this);
        *ppv = (&mut (*this).user_array_interface as *mut ProviderSetUserArrayInterface).cast();
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "system" fn provider_add_ref(this: *mut Provider) -> u32 {
    (*this).ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn provider_release(this: *mut Provider) -> u32 {
    let count = (*this).ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        if !(*this).credential.is_null() {
            credential::credential_release((*this).credential);
        }
        drop(Box::from_raw(this));
        dll_release();
    }
    count
}

unsafe extern "system" fn provider_set_user_array_query_interface(
    this: *mut ProviderSetUserArrayInterface,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    provider_query_interface((*this).provider, riid, ppv)
}

unsafe extern "system" fn provider_set_user_array_add_ref(
    this: *mut ProviderSetUserArrayInterface,
) -> u32 {
    provider_add_ref((*this).provider)
}

unsafe extern "system" fn provider_set_user_array_release(
    this: *mut ProviderSetUserArrayInterface,
) -> u32 {
    provider_release((*this).provider)
}

unsafe extern "system" fn provider_set_user_array(
    _this: *mut ProviderSetUserArrayInterface,
    _users: *mut c_void,
) -> HRESULT {
    S_OK
}

unsafe extern "system" fn provider_set_usage_scenario(
    this: *mut Provider,
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    flags: u32,
) -> HRESULT {
    if cpus != CPUS_CREDUI {
        return E_NOTIMPL;
    }
    (*this).usage_scenario = cpus;
    (*this).cred_ui_flags = flags;
    if !(*this).credential.is_null() {
        credential::set_usage_scenario((*this).credential, cpus, flags);
    }
    ensure_credential(this)
}

unsafe extern "system" fn provider_set_serialization(
    _this: *mut Provider,
    _serialization: *const CredentialProviderCredentialSerialization,
) -> HRESULT {
    S_OK
}

unsafe extern "system" fn provider_advise(
    _this: *mut Provider,
    _events: *mut c_void,
    _context: usize,
) -> HRESULT {
    S_OK
}

unsafe extern "system" fn provider_unadvise(_this: *mut Provider) -> HRESULT {
    S_OK
}

unsafe extern "system" fn provider_get_field_descriptor_count(
    _this: *mut Provider,
    count: *mut u32,
) -> HRESULT {
    if count.is_null() {
        return E_INVALIDARG;
    }
    *count = FIELD_COUNT;
    S_OK
}

unsafe extern "system" fn provider_get_field_descriptor_at(
    _this: *mut Provider,
    index: u32,
    descriptor: *mut *mut CredentialProviderFieldDescriptor,
) -> HRESULT {
    if descriptor.is_null() {
        return E_INVALIDARG;
    }
    *descriptor = ptr::null_mut();
    match allocate_field_descriptor(index) {
        Ok(allocated) => {
            *descriptor = allocated;
            S_OK
        }
        Err(hr) => hr,
    }
}

unsafe extern "system" fn provider_get_credential_count(
    this: *mut Provider,
    count: *mut u32,
    default: *mut u32,
    auto_logon: *mut BOOL,
) -> HRESULT {
    if count.is_null() || default.is_null() || auto_logon.is_null() {
        return E_INVALIDARG;
    }
    if (*this).usage_scenario != CPUS_CREDUI {
        *count = 0;
        *default = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *auto_logon = 0;
        return S_OK;
    }
    let hr = ensure_credential(this);
    if hr != S_OK {
        return hr;
    }
    *count = 1;
    *default = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *auto_logon = 0;
    S_OK
}

unsafe extern "system" fn provider_get_credential_at(
    this: *mut Provider,
    index: u32,
    credential: *mut *mut c_void,
) -> HRESULT {
    if credential.is_null() {
        return E_INVALIDARG;
    }
    *credential = ptr::null_mut();
    if index != 0 {
        return E_INVALIDARG;
    }
    if (*this).usage_scenario != CPUS_CREDUI {
        return E_NOTIMPL;
    }
    let hr = ensure_credential(this);
    if hr != S_OK {
        return hr;
    }
    credential::credential_add_ref((*this).credential);
    *credential = (*this).credential.cast();
    S_OK
}

unsafe fn ensure_credential(provider: *mut Provider) -> HRESULT {
    if !(*provider).credential.is_null() {
        return S_OK;
    }
    (*provider).credential =
        credential::new_credential((*provider).usage_scenario, (*provider).cred_ui_flags);
    S_OK
}
