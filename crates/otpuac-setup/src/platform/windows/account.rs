use super::error::{last_error, win_error};
use super::local_alloc::LocalAllocPtr;
use super::registry::{create_registry_key, set_registry_dword};
use otpuac_core::Result;
use otpuac_windows::wide::{string_from_wide_ptr, wide_null};
use std::ptr;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MEMBER_IN_ALIAS,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserExists, NERR_UserNotFound, NetLocalGroupAddMembers, NetUserAdd,
    NetUserDel, LOCALGROUP_MEMBERS_INFO_0, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
    USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, LookupAccountNameW, LookupAccountSidW, WinBuiltinAdministratorsSid, PSID,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE,
};
use windows_sys::Win32::System::Registry::{RegDeleteValueW, HKEY_LOCAL_MACHINE};
use zeroize::Zeroize;

const MANAGED_ACCOUNT_COMMENT: &str = "OTPUAC managed local administrator account";

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
    password_w.zeroize();
    if status == NERR_UserExists {
        return Err(otpuac_core::OtpuacError::InvalidConfig(format!(
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
