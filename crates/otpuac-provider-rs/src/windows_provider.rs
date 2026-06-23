mod credential_pack;
mod hresult;
mod ipc;
mod registry;
mod wide;

use credential_pack::pack_credential;
use hresult::E_NOINTERFACE;
use ipc::request_unlock;
use otpuac_core::UnlockDecision;
use registry::{register_server, unregister_server};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr;
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use wide::{
    duplicate_wide_to_com, secure_zero_u16, wide_null, wide_ptr_to_vec, wide_vec_to_string,
};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{
    BOOL, CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOTIMPL, E_OUTOFMEMORY,
    HINSTANCE, S_FALSE, S_OK,
};
use windows_sys::Win32::Security::Credentials::CREDUIWIN_PACK_32_WOW;
use windows_sys::Win32::System::Com::CoTaskMemAlloc;
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::UI::Shell::{
    CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN,
    CPFT_LARGE_TEXT, CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT, CPFT_SUBMIT_BUTTON,
    CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CPSI_NONE,
    CPUS_CREDUI,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION as CredentialProviderCredentialSerialization,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR as CredentialProviderFieldDescriptor,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_FIELD_TYPE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_NO_DEFAULT, CREDENTIAL_PROVIDER_STATUS_ICON,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};
use zeroize::Zeroize;

const FIELD_LABEL: u32 = 0;
const FIELD_TITLE: u32 = 1;
const FIELD_TOTP: u32 = 2;
const FIELD_SUBMIT: u32 = 3;
const FIELD_COUNT: u32 = 4;
const DLL_PROCESS_ATTACH: u32 = 1;
const TITLE_PROMPT: &str = "Enter authenticator code for admin elevation";
const STATUS_ENTER_CODE: &str = "Enter the current authenticator code";
const STATUS_CODE_ACCEPTED: &str = "Code accepted";
const STATUS_PACK_FAILED: &str = "Could not pack the managed credential";

static DLL_REF_COUNT: AtomicIsize = AtomicIsize::new(0);

const CLSID_OTPUAC: GUID = GUID {
    data1: 0xB6B6F0C2,
    data2: 0x4CCB,
    data3: 0x487E,
    data4: [0x9B, 0x58, 0x68, 0x10, 0x99, 0x86, 0x5B, 0x10],
};
const IID_IUNKNOWN: GUID = GUID {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};
const IID_ICLASS_FACTORY: GUID = GUID {
    data1: 0x00000001,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};
const IID_ICREDENTIAL_PROVIDER: GUID = GUID {
    data1: 0xD27C3481,
    data2: 0x5A1C,
    data3: 0x45B2,
    data4: [0x8A, 0xAA, 0xC2, 0x0E, 0xBB, 0xE8, 0x22, 0x9E],
};
const IID_ICREDENTIAL_PROVIDER_SET_USER_ARRAY: GUID = GUID {
    data1: 0x095C1484,
    data2: 0x1C0C,
    data3: 0x4388,
    data4: [0x9C, 0x6D, 0x50, 0x0E, 0x61, 0xBF, 0x84, 0xBD],
};
const IID_ICREDENTIAL_PROVIDER_CREDENTIAL: GUID = GUID {
    data1: 0x63913A93,
    data2: 0x40C1,
    data3: 0x481A,
    data4: [0x81, 0x8D, 0x40, 0x72, 0xFF, 0x8C, 0x70, 0xCC],
};
const IID_ICREDENTIAL_PROVIDER_CREDENTIAL2: GUID = GUID {
    data1: 0xFD672C54,
    data2: 0x40EA,
    data3: 0x4D6E,
    data4: [0x9B, 0x49, 0xCF, 0xB1, 0xA7, 0x50, 0x7B, 0xD7],
};

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

#[repr(C)]
struct Credential {
    vtbl: *const CredentialVtbl,
    ref_count: AtomicU32,
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    cred_ui_flags: u32,
    totp_code: Vec<u16>,
    status: Vec<u16>,
}

#[repr(C)]
struct CredentialVtbl {
    // Keep this order byte-for-byte compatible with ICredentialProviderCredential.
    // The Windows host dispatches through slot positions, not Rust function names.
    query_interface:
        unsafe extern "system" fn(*mut Credential, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut Credential) -> u32,
    release: unsafe extern "system" fn(*mut Credential) -> u32,
    advise: unsafe extern "system" fn(*mut Credential, *mut c_void) -> HRESULT,
    unadvise: unsafe extern "system" fn(*mut Credential) -> HRESULT,
    set_selected: unsafe extern "system" fn(*mut Credential, *mut BOOL) -> HRESULT,
    set_deselected: unsafe extern "system" fn(*mut Credential) -> HRESULT,
    get_field_state: unsafe extern "system" fn(
        *mut Credential,
        u32,
        *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> HRESULT,
    get_string_value: unsafe extern "system" fn(*mut Credential, u32, *mut *mut u16) -> HRESULT,
    get_bitmap_value: unsafe extern "system" fn(*mut Credential, u32, *mut *mut c_void) -> HRESULT,
    get_checkbox_value:
        unsafe extern "system" fn(*mut Credential, u32, *mut BOOL, *mut *mut u16) -> HRESULT,
    get_submit_button_value: unsafe extern "system" fn(*mut Credential, u32, *mut u32) -> HRESULT,
    get_combo_box_value_count:
        unsafe extern "system" fn(*mut Credential, u32, *mut u32, *mut u32) -> HRESULT,
    get_combo_box_value_at:
        unsafe extern "system" fn(*mut Credential, u32, u32, *mut *mut u16) -> HRESULT,
    set_string_value: unsafe extern "system" fn(*mut Credential, u32, *const u16) -> HRESULT,
    set_checkbox_value: unsafe extern "system" fn(*mut Credential, u32, BOOL) -> HRESULT,
    set_combo_box_selected_value: unsafe extern "system" fn(*mut Credential, u32, u32) -> HRESULT,
    command_link_clicked: unsafe extern "system" fn(*mut Credential, u32) -> HRESULT,
    get_serialization: unsafe extern "system" fn(
        *mut Credential,
        *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        *mut CredentialProviderCredentialSerialization,
        *mut *mut u16,
        *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> HRESULT,
    report_result: unsafe extern "system" fn(
        *mut Credential,
        i32,
        i32,
        *mut *mut u16,
        *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> HRESULT,
    get_user_sid: unsafe extern "system" fn(*mut Credential, *mut *mut u16) -> HRESULT,
}

static CLASS_FACTORY_VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
    query_interface: class_factory_query_interface,
    add_ref: class_factory_add_ref,
    release: class_factory_release,
    create_instance: class_factory_create_instance,
    lock_server: class_factory_lock_server,
};

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

static CREDENTIAL_VTBL: CredentialVtbl = CredentialVtbl {
    query_interface: credential_query_interface,
    add_ref: credential_add_ref,
    release: credential_release,
    advise: credential_advise,
    unadvise: credential_unadvise,
    set_selected: credential_set_selected,
    set_deselected: credential_set_deselected,
    get_field_state: credential_get_field_state,
    get_string_value: credential_get_string_value,
    get_bitmap_value: credential_get_bitmap_value,
    get_checkbox_value: credential_get_checkbox_value,
    get_submit_button_value: credential_get_submit_button_value,
    get_combo_box_value_count: credential_get_combo_box_value_count,
    get_combo_box_value_at: credential_get_combo_box_value_at,
    set_string_value: credential_set_string_value,
    set_checkbox_value: credential_set_checkbox_value,
    set_combo_box_selected_value: credential_set_combo_box_selected_value,
    command_link_clicked: credential_command_link_clicked,
    get_serialization: credential_get_serialization,
    report_result: credential_report_result,
    get_user_sid: credential_get_user_sid,
};

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

    if rclsid.is_null() || !guid_eq(&*rclsid, &CLSID_OTPUAC) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    let factory = Box::into_raw(Box::new(ClassFactory {
        vtbl: &CLASS_FACTORY_VTBL,
        ref_count: AtomicU32::new(1),
    }));
    dll_add_ref();
    let hr = class_factory_query_interface(factory, riid, ppv);
    class_factory_release(factory);
    hr
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
            credential_release((*this).credential);
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
        (*(*this).credential).usage_scenario = cpus;
        (*(*this).credential).cred_ui_flags = flags;
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
    let Some(field) = field_descriptor(index) else {
        return E_INVALIDARG;
    };

    let allocated = CoTaskMemAlloc(size_of::<CredentialProviderFieldDescriptor>())
        as *mut CredentialProviderFieldDescriptor;
    if allocated.is_null() {
        return E_OUTOFMEMORY;
    }
    *allocated = field;
    *descriptor = allocated;
    S_OK
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
    credential_add_ref((*this).credential);
    *credential = (*this).credential.cast();
    S_OK
}

unsafe extern "system" fn credential_query_interface(
    this: *mut Credential,
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
    if guid_eq(&*riid, &IID_IUNKNOWN)
        || guid_eq(&*riid, &IID_ICREDENTIAL_PROVIDER_CREDENTIAL)
        || guid_eq(&*riid, &IID_ICREDENTIAL_PROVIDER_CREDENTIAL2)
    {
        credential_add_ref(this);
        *ppv = this.cast();
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "system" fn credential_add_ref(this: *mut Credential) -> u32 {
    (*this).ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn credential_release(this: *mut Credential) -> u32 {
    let count = (*this).ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        secure_zero_u16(&mut (*this).totp_code);
        drop(Box::from_raw(this));
        dll_release();
    }
    count
}

unsafe extern "system" fn credential_advise(
    _this: *mut Credential,
    _events: *mut c_void,
) -> HRESULT {
    S_OK
}

unsafe extern "system" fn credential_unadvise(_this: *mut Credential) -> HRESULT {
    S_OK
}

unsafe extern "system" fn credential_set_selected(
    _this: *mut Credential,
    auto_logon: *mut BOOL,
) -> HRESULT {
    if auto_logon.is_null() {
        return E_INVALIDARG;
    }
    *auto_logon = 0;
    S_OK
}

unsafe extern "system" fn credential_set_deselected(this: *mut Credential) -> HRESULT {
    clear_totp_code(this);
    S_OK
}

unsafe extern "system" fn credential_get_field_state(
    _this: *mut Credential,
    field_id: u32,
    state: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
    interactive_state: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
) -> HRESULT {
    if state.is_null() || interactive_state.is_null() {
        return E_INVALIDARG;
    }

    let Some((field_state, field_interactive_state)) = credential_field_state(field_id) else {
        return E_INVALIDARG;
    };
    *state = field_state;
    *interactive_state = field_interactive_state;
    S_OK
}

unsafe extern "system" fn credential_get_string_value(
    this: *mut Credential,
    field_id: u32,
    value: *mut *mut u16,
) -> HRESULT {
    if value.is_null() {
        return E_INVALIDARG;
    }
    *value = ptr::null_mut();
    let Some(text) = credential_field_text(this, field_id) else {
        return E_INVALIDARG;
    };
    duplicate_wide_to_com(&text, value)
}

unsafe extern "system" fn credential_get_bitmap_value(
    _this: *mut Credential,
    _field_id: u32,
    bitmap: *mut *mut c_void,
) -> HRESULT {
    if bitmap.is_null() {
        return E_INVALIDARG;
    }
    *bitmap = ptr::null_mut();
    E_NOTIMPL
}

unsafe extern "system" fn credential_get_checkbox_value(
    _this: *mut Credential,
    _field_id: u32,
    checked: *mut BOOL,
    label: *mut *mut u16,
) -> HRESULT {
    if checked.is_null() || label.is_null() {
        return E_INVALIDARG;
    }
    *checked = 0;
    *label = ptr::null_mut();
    E_NOTIMPL
}

unsafe extern "system" fn credential_get_combo_box_value_count(
    _this: *mut Credential,
    _field_id: u32,
    count: *mut u32,
    selected: *mut u32,
) -> HRESULT {
    if count.is_null() || selected.is_null() {
        return E_INVALIDARG;
    }
    *count = 0;
    *selected = 0;
    E_NOTIMPL
}

unsafe extern "system" fn credential_get_combo_box_value_at(
    _this: *mut Credential,
    _field_id: u32,
    _item: u32,
    value: *mut *mut u16,
) -> HRESULT {
    if value.is_null() {
        return E_INVALIDARG;
    }
    *value = ptr::null_mut();
    E_NOTIMPL
}

unsafe extern "system" fn credential_get_submit_button_value(
    _this: *mut Credential,
    field_id: u32,
    adjacent_to: *mut u32,
) -> HRESULT {
    if adjacent_to.is_null() {
        return E_INVALIDARG;
    }
    if field_id != FIELD_SUBMIT {
        return E_INVALIDARG;
    }
    *adjacent_to = FIELD_TOTP;
    S_OK
}

unsafe extern "system" fn credential_set_string_value(
    this: *mut Credential,
    field_id: u32,
    value: *const u16,
) -> HRESULT {
    if field_id != FIELD_TOTP || value.is_null() {
        return E_INVALIDARG;
    }
    secure_zero_u16(&mut (*this).totp_code);
    (*this).totp_code = wide_ptr_to_vec(value, 16);
    S_OK
}

unsafe extern "system" fn credential_set_checkbox_value(
    _this: *mut Credential,
    _field_id: u32,
    _checked: BOOL,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn credential_set_combo_box_selected_value(
    _this: *mut Credential,
    _field_id: u32,
    _selected: u32,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn credential_command_link_clicked(
    _this: *mut Credential,
    _field_id: u32,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn credential_get_serialization(
    this: *mut Credential,
    response: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    serialization: *mut CredentialProviderCredentialSerialization,
    status_text: *mut *mut u16,
    status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
) -> HRESULT {
    if response.is_null()
        || serialization.is_null()
        || status_text.is_null()
        || status_icon.is_null()
    {
        return E_INVALIDARG;
    }

    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *status_text = ptr::null_mut();
    *status_icon = CPSI_NONE;
    *serialization = zeroed();

    let code = wide_vec_to_string(&(*this).totp_code);
    if code.trim().is_empty() {
        set_error_status(this, STATUS_ENTER_CODE, status_text, status_icon);
        return S_OK;
    }

    match request_unlock(&code) {
        Ok(UnlockDecision::Approved {
            username,
            domain,
            mut password,
        }) => {
            let qualified = qualified_username(&username, domain.as_deref());
            let hr = pack_credential(
                &qualified,
                &mut password,
                (*this).cred_ui_flags & CREDUIWIN_PACK_32_WOW != 0,
                serialization,
            );
            password.zeroize();
            clear_totp_code(this);
            if hr == S_OK {
                *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
                set_status(this, STATUS_CODE_ACCEPTED);
            } else {
                set_error_status(this, STATUS_PACK_FAILED, status_text, status_icon);
            }
            hr
        }
        Ok(UnlockDecision::Denied { message, .. }) => {
            set_error_status(this, &message, status_text, status_icon);
            S_OK
        }
        Ok(UnlockDecision::Error { message }) | Err(message) => {
            set_error_status(this, &message, status_text, status_icon);
            S_OK
        }
    }
}

unsafe extern "system" fn credential_report_result(
    _this: *mut Credential,
    _status: i32,
    _substatus: i32,
    status_text: *mut *mut u16,
    status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
) -> HRESULT {
    if status_text.is_null() || status_icon.is_null() {
        return E_INVALIDARG;
    }
    *status_text = ptr::null_mut();
    *status_icon = CPSI_NONE;
    S_OK
}

unsafe extern "system" fn credential_get_user_sid(
    _this: *mut Credential,
    sid: *mut *mut u16,
) -> HRESULT {
    if sid.is_null() {
        return E_INVALIDARG;
    }
    *sid = ptr::null_mut();
    S_FALSE
}

unsafe fn ensure_credential(provider: *mut Provider) -> HRESULT {
    if !(*provider).credential.is_null() {
        return S_OK;
    }
    let credential = Box::into_raw(Box::new(Credential {
        vtbl: &CREDENTIAL_VTBL,
        ref_count: AtomicU32::new(1),
        usage_scenario: (*provider).usage_scenario,
        cred_ui_flags: (*provider).cred_ui_flags,
        totp_code: Vec::new(),
        status: Vec::new(),
    }));
    dll_add_ref();
    (*provider).credential = credential;
    S_OK
}

unsafe fn field_descriptor(index: u32) -> Option<CredentialProviderFieldDescriptor> {
    let metadata = field_metadata(index)?;

    let mut label_ptr = ptr::null_mut();
    if duplicate_wide_to_com(&wide_null(metadata.label), &mut label_ptr) != S_OK {
        return None;
    }

    Some(CredentialProviderFieldDescriptor {
        dwFieldID: index,
        cpft: metadata.field_type,
        pszLabel: label_ptr,
        guidFieldType: zeroed(),
    })
}

struct FieldMetadata {
    field_type: CREDENTIAL_PROVIDER_FIELD_TYPE,
    label: &'static str,
}

fn field_metadata(index: u32) -> Option<FieldMetadata> {
    match index {
        FIELD_LABEL => Some(FieldMetadata {
            field_type: CPFT_SMALL_TEXT,
            label: "OTPUAC",
        }),
        FIELD_TITLE => Some(FieldMetadata {
            field_type: CPFT_LARGE_TEXT,
            label: "OTPUAC admin elevation",
        }),
        FIELD_TOTP => Some(FieldMetadata {
            field_type: CPFT_PASSWORD_TEXT,
            label: "Authenticator code",
        }),
        FIELD_SUBMIT => Some(FieldMetadata {
            field_type: CPFT_SUBMIT_BUTTON,
            label: "Submit",
        }),
        _ => None,
    }
}

fn credential_field_state(
    field_id: u32,
) -> Option<(
    CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
)> {
    match field_id {
        FIELD_LABEL => Some((CPFS_HIDDEN, CPFIS_NONE)),
        FIELD_TITLE => Some((CPFS_DISPLAY_IN_BOTH, CPFIS_NONE)),
        FIELD_TOTP => Some((CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED)),
        FIELD_SUBMIT => Some((CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE)),
        _ => None,
    }
}

unsafe fn credential_field_text(credential: *mut Credential, field_id: u32) -> Option<Vec<u16>> {
    match field_id {
        FIELD_LABEL => Some(wide_null("OTPUAC")),
        FIELD_TITLE if (*credential).status.is_empty() => Some(wide_null(TITLE_PROMPT)),
        FIELD_TITLE => Some((*credential).status.clone()),
        FIELD_TOTP => {
            let mut cloned = (*credential).totp_code.clone();
            cloned.push(0);
            Some(cloned)
        }
        FIELD_SUBMIT => Some(wide_null("Submit")),
        _ => None,
    }
}

unsafe fn duplicate_status(
    message: &str,
    status_text: *mut *mut u16,
    status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
) {
    let _ = duplicate_wide_to_com(&wide_null(message), status_text);
    *status_icon = CPSI_ERROR;
}

unsafe fn set_error_status(
    credential: *mut Credential,
    message: &str,
    status_text: *mut *mut u16,
    status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
) {
    set_status(credential, message);
    duplicate_status(message, status_text, status_icon);
}

unsafe fn set_status(credential: *mut Credential, message: &str) {
    (*credential).status = wide_null(message);
}

unsafe fn clear_totp_code(credential: *mut Credential) {
    secure_zero_u16(&mut (*credential).totp_code);
    (*credential).totp_code.clear();
}

fn qualified_username(username: &str, domain: Option<&str>) -> String {
    match domain {
        Some(domain) if !domain.trim().is_empty() => format!("{domain}\\{username}"),
        _ => username.to_string(),
    }
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}
