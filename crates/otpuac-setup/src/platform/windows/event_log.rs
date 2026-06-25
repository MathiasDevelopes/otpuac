use super::registry::{
    create_registry_key, delete_registry_tree, set_registry_dword, set_registry_string,
};
use otpuac_core::Result;
use otpuac_runtime::paths::SERVICE_NAME;
use std::path::Path;
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_EXPAND_SZ};

pub(crate) fn register_event_log_source(message_file: &Path) -> Result<()> {
    let key_path =
        format!(r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{SERVICE_NAME}");
    let key = create_registry_key(HKEY_LOCAL_MACHINE, &key_path)?;
    let message_file = message_file.as_os_str().to_string_lossy();

    set_registry_string(key.0, "EventMessageFile", &message_file, REG_EXPAND_SZ)?;
    set_registry_dword(
        key.0,
        "TypesSupported",
        (EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE) as u32,
    )?;
    Ok(())
}

pub(crate) fn unregister_event_log_source() -> Result<()> {
    delete_registry_tree(
        HKEY_LOCAL_MACHINE,
        &format!(r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{SERVICE_NAME}"),
    )
}
