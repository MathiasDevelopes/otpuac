use super::credential_pack::pack_credential;
use super::fields::{credential_field_state, credential_field_text, FIELD_SUBMIT, FIELD_TOTP};
use super::hresult::E_NOINTERFACE;
use super::ids::{
    guid_eq, IID_ICREDENTIAL_PROVIDER_CREDENTIAL, IID_ICREDENTIAL_PROVIDER_CREDENTIAL2,
    IID_IUNKNOWN,
};
use super::ipc::request_unlock;
use super::{dll_add_ref, dll_release};
use otpuac_core::{ManagedAccount, UnlockDecision};
use otpuac_windows::wide::{
    duplicate_wide_to_com, secure_zero_u16, wide_null, wide_ptr_to_vec, wide_vec_to_string,
};
use std::ffi::c_void;
use std::mem::zeroed;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{BOOL, E_INVALIDARG, E_NOTIMPL, S_FALSE, S_OK};
use windows_sys::Win32::Security::Credentials::CREDUIWIN_PACK_32_WOW;
use windows_sys::Win32::UI::Shell::{
    CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CPSI_NONE,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION as CredentialProviderCredentialSerialization,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};
use zeroize::{Zeroize, Zeroizing};

const STATUS_ENTER_CODE: &str = "Enter the current authenticator code";
const STATUS_CODE_ACCEPTED: &str = "Code accepted";
const STATUS_PACK_FAILED: &str = "Could not pack the managed credential";

#[repr(C)]
pub(super) struct Credential {
    vtbl: *const CredentialVtbl,
    ref_count: AtomicU32,
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    cred_ui_flags: u32,
    totp_code: Vec<u16>,
    status: Vec<u16>,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.totp_code.zeroize();
    }
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

pub(super) unsafe fn new_credential(
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    cred_ui_flags: u32,
) -> *mut Credential {
    let credential = Box::into_raw(Box::new(Credential {
        vtbl: &CREDENTIAL_VTBL,
        ref_count: AtomicU32::new(1),
        usage_scenario,
        cred_ui_flags,
        totp_code: Vec::new(),
        status: Vec::new(),
    }));
    dll_add_ref();
    credential
}

pub(super) unsafe fn set_usage_scenario(
    this: *mut Credential,
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    cred_ui_flags: u32,
) {
    (*this).usage_scenario = usage_scenario;
    (*this).cred_ui_flags = cred_ui_flags;
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

pub(super) unsafe extern "system" fn credential_add_ref(this: *mut Credential) -> u32 {
    (*this).ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

pub(super) unsafe extern "system" fn credential_release(this: *mut Credential) -> u32 {
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
    let Some(text) = credential_field_text(field_id, &(*this).status, &(*this).totp_code) else {
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

    let code = Zeroizing::new(wide_vec_to_string(&(*this).totp_code));
    if code.trim().is_empty() {
        set_error_status(this, STATUS_ENTER_CODE, status_text, status_icon);
        return S_OK;
    }

    let unlock_result = request_unlock(code.as_str());
    clear_totp_code(this);

    match unlock_result {
        Ok(UnlockDecision::Approved {
            username,
            domain,
            mut password,
        }) => {
            let qualified = ManagedAccount { username, domain }.label();
            let hr = pack_credential(
                &qualified,
                &mut password,
                (*this).cred_ui_flags & CREDUIWIN_PACK_32_WOW != 0,
                serialization,
            );
            password.zeroize();
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
