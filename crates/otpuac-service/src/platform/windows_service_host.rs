use crate::audit;
use crate::platform::windows_ipc;
use otpuac_core::Result;
use otpuac_runtime::paths::{default_vault_path, SERVICE_NAME};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

define_windows_service!(ffi_service_main, service_main);

pub(crate) fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|err| otpuac_core::OtpuacError::Platform(err.to_string()))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_inner() {
        audit::service_failed(err.to_string());
        tracing::error!("service failed: {err}");
    }
}

fn run_inner() -> Result<()> {
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_for_handler = Arc::clone(&stopped);

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                if matches!(control, ServiceControl::Stop) {
                    stopped_for_handler.store(true, Ordering::SeqCst);
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|err| otpuac_core::OtpuacError::Platform(err.to_string()))?;

    set_status(&status_handle, ServiceState::Running)?;
    audit::service_started();
    let vault_path = default_vault_path();
    let result = windows_ipc::serve_pipe(
        &vault_path,
        || stopped.load(Ordering::SeqCst),
        windows_ipc::ClientPolicy::CredentialUiHostsOnly,
    );
    if let Err(err) = &result {
        audit::service_failed(err.to_string());
    }
    set_status(&status_handle, ServiceState::Stopped)?;
    audit::service_stopped();
    result
}

fn set_status(handle: &ServiceStatusHandle, state: ServiceState) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
        .map_err(|err| otpuac_core::OtpuacError::Platform(err.to_string()))
}
