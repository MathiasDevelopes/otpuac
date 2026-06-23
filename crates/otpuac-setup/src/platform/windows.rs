use otpuac_core::{paths::SERVICE_NAME, Result};
use std::ffi::OsStr;
use std::iter::once;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_MEMBER_IN_ALIAS, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SERVICE_REQUEST_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserExists, NERR_UserNotFound, NetLocalGroupAddMembers, NetUserAdd,
    NetUserDel, LOCALGROUP_MEMBERS_INFO_0, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
    USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetSecurityDescriptorDacl, LookupAccountNameW, LookupAccountSidW,
    WinBuiltinAdministratorsSid, ACL, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE,
    SID_NAME_USE,
};
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, StartServiceW, SC_HANDLE,
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_STATUS,
    SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

const SERVICE_DISPLAY_NAME: &str = "OTPUAC Service";
const SERVICE_DESCRIPTION: &str = "OTPUAC managed-admin TOTP unlock service";
const MANAGED_ACCOUNT_COMMENT: &str = "OTPUAC managed local administrator account";
const SERVICE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(250);
const SERVICE_STOP_POLL_ATTEMPTS: usize = 20;

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

struct LocalAllocPtr(*mut core::ffi::c_void);

impl Drop for LocalAllocPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub(crate) fn create_local_admin_account(username: &str, password: &str) -> Result<String> {
    create_local_user(username, password)?;
    let mut sid = lookup_account_sid(username)?;
    let sid_string = sid_to_string(sid.as_mut_ptr().cast())?;
    add_sid_to_local_administrators(sid.as_mut_ptr().cast())?;
    Ok(sid_string)
}

pub(crate) fn delete_local_account(username: &str) -> Result<()> {
    let username_w = wide_null(username);
    let status = unsafe { NetUserDel(ptr::null(), username_w.as_ptr()) };
    if status != NERR_Success && status != NERR_UserNotFound {
        return Err(win_error("NetUserDel", status));
    }
    Ok(())
}

pub(crate) fn hide_local_account_from_sign_in(username: &str) -> Result<()> {
    set_sign_in_hidden_state(username, true)
}

pub(crate) fn unhide_local_account_from_sign_in(username: &str) -> Result<()> {
    set_sign_in_hidden_state(username, false)
}

pub(crate) fn secure_program_data_dir(path: &Path) -> Result<()> {
    let path_w = wide_null_os(path.as_os_str());
    let sddl = wide_null("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    let _descriptor = LocalAllocPtr(descriptor);

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if ok == 0 || dacl_present == 0 || dacl.is_null() {
        return Err(last_error("GetSecurityDescriptorDacl"));
    }

    let status = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(win_error("SetNamedSecurityInfoW", status));
    }
    Ok(())
}

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
    let key_path = wide_null(&format!(
        r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{SERVICE_NAME}"
    ));
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, key_path.as_ptr()) };
    if status != 0 && status != ERROR_FILE_NOT_FOUND {
        return Err(win_error("RegDeleteTreeW", status));
    }
    Ok(())
}

pub(crate) fn install_or_replace_service(service_exe: &Path) -> Result<()> {
    stop_and_delete_service()?;

    let manager = open_service_manager()?;
    let service_name = wide_null(SERVICE_NAME);
    let display_name = wide_null(SERVICE_DISPLAY_NAME);
    let binary_path = wide_null(&format!("\"{}\" run", service_exe.display()));

    let service = unsafe {
        CreateServiceW(
            manager.0,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary_path.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if service.is_null() {
        return Err(last_error("CreateServiceW"));
    }
    let service = ServiceHandle(service);

    let mut description_text = wide_null(SERVICE_DESCRIPTION);
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: description_text.as_mut_ptr(),
    };
    unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&description as *const SERVICE_DESCRIPTIONW).cast(),
        );
    }

    let ok = unsafe { StartServiceW(service.0, 0, ptr::null()) };
    if ok == 0 {
        return Err(last_error("StartServiceW"));
    }
    Ok(())
}

pub(crate) fn stop_and_delete_service() -> Result<()> {
    let manager = open_service_manager()?;
    let service_name = wide_null(SERVICE_NAME);
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_ALL_ACCESS) };
    if service.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(());
        }
        return Err(last_error("OpenServiceW"));
    }
    let service = ServiceHandle(service);

    let mut status: SERVICE_STATUS = unsafe { zeroed() };
    let ok = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_NOT_ACTIVE {
            return Err(last_error("ControlService"));
        }
    } else {
        wait_for_service_stop(service.0)?;
    }

    let ok = unsafe { DeleteService(service.0) };
    if ok == 0 {
        return Err(last_error("DeleteService"));
    }
    Ok(())
}

pub(crate) fn register_provider(provider_dll: &Path) -> Result<()> {
    run_regsvr32(provider_dll, false)
}

pub(crate) fn unregister_provider(provider_dll: &Path) -> Result<()> {
    run_regsvr32(provider_dll, true)
}

fn create_local_user(username: &str, password: &str) -> Result<()> {
    let mut username_w = wide_null(username);
    let mut password_w = wide_null(password);
    let mut comment_w = wide_null(MANAGED_ACCOUNT_COMMENT);
    let mut parm_err = 0_u32;
    let mut info = USER_INFO_1 {
        usri1_name: username_w.as_mut_ptr(),
        usri1_password: password_w.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: ptr::null_mut(),
        usri1_comment: comment_w.as_mut_ptr(),
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
        usri1_script_path: ptr::null_mut(),
    };

    let status = unsafe {
        NetUserAdd(
            ptr::null(),
            1,
            (&mut info as *mut USER_INFO_1).cast(),
            &mut parm_err,
        )
    };
    if status == NERR_UserExists {
        return Err(otpuac_core::OtpuacError::InvalidVault(format!(
            "local account {username} already exists; choose a different OTPUAC managed account name"
        )));
    }
    if status != NERR_Success {
        return Err(win_error("NetUserAdd", status));
    }
    Ok(())
}

fn add_sid_to_local_administrators(sid: PSID) -> Result<()> {
    let admins = builtin_administrators_name()?;
    let admins_w = wide_null(&admins);
    let member = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: sid };
    let status = unsafe {
        NetLocalGroupAddMembers(
            ptr::null(),
            admins_w.as_ptr(),
            0,
            (&member as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
            1,
        )
    };
    if status != NERR_Success && status != ERROR_MEMBER_IN_ALIAS {
        return Err(win_error("NetLocalGroupAddMembers", status));
    }
    Ok(())
}

fn set_sign_in_hidden_state(username: &str, hidden: bool) -> Result<()> {
    let key = create_registry_key(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
    )?;

    let username_w = wide_null(username);
    let status = if hidden {
        set_registry_dword(key.0, username, 0)?;
        0
    } else {
        unsafe { RegDeleteValueW(key.0, username_w.as_ptr()) }
    };

    if status != 0 && !(status == ERROR_FILE_NOT_FOUND && !hidden) {
        return Err(win_error(
            "managed account sign-in visibility registry update",
            status,
        ));
    }
    Ok(())
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

fn create_registry_key(root: HKEY, key_path: &str) -> Result<RegistryKey> {
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

fn set_registry_string(key: HKEY, name: &str, value: &str, value_type: u32) -> Result<()> {
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

fn set_registry_dword(key: HKEY, name: &str, value: u32) -> Result<()> {
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

fn lookup_account_sid(account: &str) -> Result<Vec<u8>> {
    let account_w = wide_null(account);
    let mut sid_len = 0_u32;
    let mut domain_len = 0_u32;
    let mut sid_type: SID_NAME_USE = 0;
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account_w.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
    }
    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER || sid_len == 0 {
        return Err(last_error("LookupAccountNameW"));
    }

    let mut sid = vec![0_u8; sid_len as usize];
    let mut domain = vec![0_u16; domain_len as usize];
    let ok = unsafe {
        LookupAccountNameW(
            ptr::null(),
            account_w.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if ok == 0 {
        return Err(last_error("LookupAccountNameW"));
    }
    Ok(sid)
}

fn builtin_administrators_name() -> Result<String> {
    let mut sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = sid.len() as u32;
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateWellKnownSid"));
    }

    let mut name_len = 0_u32;
    let mut domain_len = 0_u32;
    let mut sid_type: SID_NAME_USE = 0;
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid.as_mut_ptr().cast(),
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
    }
    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER || name_len == 0 {
        return Err(last_error("LookupAccountSidW"));
    }

    let mut name = vec![0_u16; name_len as usize];
    let mut domain = vec![0_u16; domain_len as usize];
    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid.as_mut_ptr().cast(),
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if ok == 0 {
        return Err(last_error("LookupAccountSidW"));
    }
    let mut actual_len = name_len as usize;
    while actual_len > 0 && name[actual_len - 1] == 0 {
        actual_len -= 1;
    }
    Ok(String::from_utf16_lossy(&name[..actual_len]))
}

fn sid_to_string(sid: PSID) -> Result<String> {
    let mut sid_string: *mut u16 = ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut sid_string) };
    if ok == 0 {
        return Err(last_error("ConvertSidToStringSidW"));
    }
    let _sid_string = LocalAllocPtr(sid_string.cast());
    Ok(unsafe { string_from_wide_ptr(sid_string) })
}

fn open_service_manager() -> Result<ServiceHandle> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if manager.is_null() {
        return Err(last_error("OpenSCManagerW"));
    }
    Ok(ServiceHandle(manager))
}

fn wait_for_service_stop(service: SC_HANDLE) -> Result<()> {
    for _ in 0..SERVICE_STOP_POLL_ATTEMPTS {
        let mut status: SERVICE_STATUS = unsafe { zeroed() };
        let ok = unsafe { QueryServiceStatus(service, &mut status) };
        if ok == 0 {
            return Err(last_error("QueryServiceStatus"));
        }
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        thread::sleep(SERVICE_STOP_POLL_INTERVAL);
    }
    Err(win_error(
        "service stop timed out before reaching SERVICE_STOPPED",
        ERROR_SERVICE_REQUEST_TIMEOUT,
    ))
}

fn run_regsvr32(provider_dll: &Path, unregister: bool) -> Result<()> {
    let mut command = Command::new("regsvr32.exe");
    if unregister {
        command.arg("/u");
    }
    let status = command.arg("/s").arg(provider_dll).status()?;
    if !status.success() {
        return Err(otpuac_core::OtpuacError::InvalidVault(format!(
            "regsvr32 failed for {} with {status}",
            provider_dll.display()
        )));
    }
    Ok(())
}

fn win_error(function: &str, code: u32) -> otpuac_core::OtpuacError {
    otpuac_core::OtpuacError::InvalidVault(format!("{function} failed with {code}"))
}

fn last_error(function: &str) -> otpuac_core::OtpuacError {
    win_error(function, unsafe { GetLastError() })
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

fn wide_null_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(once(0)).collect()
}

unsafe fn string_from_wide_ptr(ptr: *const u16) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}
