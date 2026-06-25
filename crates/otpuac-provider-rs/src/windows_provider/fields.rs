use otpuac_windows_support::wide::{duplicate_wide_to_com, wide_null};
use std::mem::{size_of, zeroed};
use std::ptr;
use windows_sys::Win32::Foundation::{E_OUTOFMEMORY, S_OK};
use windows_sys::Win32::System::Com::CoTaskMemAlloc;
use windows_sys::Win32::UI::Shell::{
    CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN,
    CPFT_LARGE_TEXT, CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT, CPFT_SUBMIT_BUTTON,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR as CredentialProviderFieldDescriptor,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_FIELD_TYPE,
};

pub(super) const FIELD_LABEL: u32 = 0;
pub(super) const FIELD_TITLE: u32 = 1;
pub(super) const FIELD_TOTP: u32 = 2;
pub(super) const FIELD_SUBMIT: u32 = 3;
pub(super) const FIELD_COUNT: u32 = 4;

const TITLE_PROMPT: &str = "Enter authenticator code for admin elevation";

pub(super) unsafe fn field_descriptor(
    index: u32,
) -> Result<CredentialProviderFieldDescriptor, i32> {
    let Some(metadata) = field_metadata(index) else {
        return Err(windows_sys::Win32::Foundation::E_INVALIDARG);
    };

    let mut label_ptr = ptr::null_mut();
    if duplicate_wide_to_com(&wide_null(metadata.label), &mut label_ptr) != S_OK {
        return Err(E_OUTOFMEMORY);
    }

    Ok(CredentialProviderFieldDescriptor {
        dwFieldID: index,
        cpft: metadata.field_type,
        pszLabel: label_ptr,
        guidFieldType: zeroed(),
    })
}

pub(super) unsafe fn allocate_field_descriptor(
    index: u32,
) -> Result<*mut CredentialProviderFieldDescriptor, i32> {
    let field = field_descriptor(index)?;
    let allocated = CoTaskMemAlloc(size_of::<CredentialProviderFieldDescriptor>())
        as *mut CredentialProviderFieldDescriptor;
    if allocated.is_null() {
        return Err(E_OUTOFMEMORY);
    }
    *allocated = field;
    Ok(allocated)
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

pub(super) fn credential_field_state(
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

pub(super) fn credential_field_text(
    field_id: u32,
    status: &[u16],
    totp_code: &[u16],
) -> Option<Vec<u16>> {
    match field_id {
        FIELD_LABEL => Some(wide_null("OTPUAC")),
        FIELD_TITLE if status.is_empty() => Some(wide_null(TITLE_PROMPT)),
        FIELD_TITLE => Some(status.to_vec()),
        FIELD_TOTP => {
            let mut cloned = totp_code.to_vec();
            cloned.push(0);
            Some(cloned)
        }
        FIELD_SUBMIT => Some(wide_null("Submit")),
        _ => None,
    }
}
