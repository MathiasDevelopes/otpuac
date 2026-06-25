use super::error::{last_error, win_error};
use otpuac_core::Result;
use otpuac_runtime::paths::SERVICE_NAME;
use otpuac_windows::wide::wide_null;
use std::mem::zeroed;
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SERVICE_REQUEST_TIMEOUT,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS,
};

const SERVICE_DISPLAY_NAME: &str = "OTPUAC Service";
const SERVICE_DESCRIPTION: &str = "OTPUAC managed-admin TOTP unlock service";
const SERVICE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(250);
const SERVICE_STOP_POLL_ATTEMPTS: usize = 20;
const STANDARD_DELETE_ACCESS: u32 = 0x0001_0000;
const SERVICE_INSTALL_ACCESS: u32 = SERVICE_START | SERVICE_CHANGE_CONFIG;
const SERVICE_DELETE_ACCESS: u32 = SERVICE_STOP | SERVICE_QUERY_STATUS | STANDARD_DELETE_ACCESS;

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

pub(crate) fn install_or_replace_service(service_exe: &Path) -> Result<()> {
    stop_and_delete_service()?;

    let manager = open_service_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let service_name = wide_null(SERVICE_NAME);
    let display_name = wide_null(SERVICE_DISPLAY_NAME);
    let binary_path = wide_null(&format!("\"{}\" run", service_exe.display()));

    let service = unsafe {
        CreateServiceW(
            manager.0,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_INSTALL_ACCESS,
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
    let manager = open_service_manager(SC_MANAGER_CONNECT)?;
    let service_name = wide_null(SERVICE_NAME);
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_DELETE_ACCESS) };
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

fn open_service_manager(desired_access: u32) -> Result<ServiceHandle> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), desired_access) };
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
