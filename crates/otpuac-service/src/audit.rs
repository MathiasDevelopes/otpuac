#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(any(windows, debug_assertions)), allow(dead_code))]
pub(crate) enum AuditKind {
    Information,
    Warning,
    Error,
}

#[cfg(any(windows, debug_assertions))]
const MAX_AUDIT_FIELD_CHARS: usize = 160;

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn service_started() {
    write(AuditKind::Information, "OTPUAC service started");
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn service_stopped() {
    write(AuditKind::Information, "OTPUAC service stopped");
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn service_failed(message: impl AsRef<str>) {
    write(
        AuditKind::Error,
        format!("OTPUAC service failed: {}", message.as_ref()),
    );
}

#[cfg(any(windows, debug_assertions))]
pub(crate) fn unlock_accepted(request_id: &str, account_label: &str) {
    let request_id = audit_field(request_id);
    let account_label = audit_field(account_label);
    write(
        AuditKind::Information,
        format!("Unlock accepted for request {request_id}; account {account_label}"),
    );
}

#[cfg(any(windows, debug_assertions))]
pub(crate) fn unlock_rejected(request_id: &str, reason: &str) {
    let request_id = audit_field(request_id);
    let reason = audit_field(reason);
    write(
        AuditKind::Warning,
        format!("Unlock rejected for request {request_id}; reason {reason}"),
    );
}

#[cfg(any(windows, debug_assertions))]
pub(crate) fn unlock_rate_limited(request_id: &str) {
    let request_id = audit_field(request_id);
    write(
        AuditKind::Warning,
        format!("Unlock rate limited for request {request_id}"),
    );
}

#[cfg(any(windows, debug_assertions))]
pub(crate) fn vault_error(request_id: &str, message: impl AsRef<str>) {
    let request_id = audit_field(request_id);
    let message = audit_field(message.as_ref());
    write(
        AuditKind::Error,
        format!("Vault or credential unlock error for request {request_id}: {message}"),
    );
}

#[cfg(windows)]
pub(crate) fn ipc_error(message: impl AsRef<str>) {
    let message = audit_field(message.as_ref());
    write(
        AuditKind::Warning,
        format!("Named-pipe client error: {message}"),
    );
}

pub(crate) fn write(kind: AuditKind, message: impl AsRef<str>) {
    let message = message.as_ref();
    match kind {
        AuditKind::Information => tracing::info!("{message}"),
        AuditKind::Warning => tracing::warn!("{message}"),
        AuditKind::Error => tracing::error!("{message}"),
    }
    platform_write(kind, message);
}

#[cfg(windows)]
fn platform_write(kind: AuditKind, message: &str) {
    use otpuac_runtime::paths::SERVICE_NAME;
    use otpuac_windows::wide::wide_null;
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
        EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    };

    struct EventSource(HANDLE);

    impl Drop for EventSource {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DeregisterEventSource(self.0);
                }
            }
        }
    }

    let source_name = wide_null(SERVICE_NAME);
    let source = unsafe { RegisterEventSourceW(ptr::null(), source_name.as_ptr()) };
    if source.is_null() {
        tracing::warn!(
            "RegisterEventSourceW failed while writing audit event: {}",
            unsafe { GetLastError() }
        );
        return;
    }
    let _source = EventSource(source);

    let event_type = match kind {
        AuditKind::Information => EVENTLOG_INFORMATION_TYPE,
        AuditKind::Warning => EVENTLOG_WARNING_TYPE,
        AuditKind::Error => EVENTLOG_ERROR_TYPE,
    };
    let message_w = wide_null(message);
    let strings = [message_w.as_ptr()];
    let ok = unsafe {
        ReportEventW(
            source,
            event_type,
            0,
            1,
            ptr::null_mut(),
            strings.len() as u16,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    if ok == 0 {
        tracing::warn!(
            "ReportEventW failed while writing audit event: {}",
            unsafe { GetLastError() }
        );
    }
}

#[cfg(not(windows))]
fn platform_write(_kind: AuditKind, _message: &str) {}

#[cfg(any(windows, debug_assertions))]
fn audit_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(MAX_AUDIT_FIELD_CHARS));
    let mut truncated = false;
    for (idx, ch) in value.chars().enumerate() {
        if idx == MAX_AUDIT_FIELD_CHARS {
            truncated = true;
            break;
        }
        out.push(audit_char(ch));
    }
    if truncated {
        out.push_str("...");
    }
    out
}

#[cfg(any(windows, debug_assertions))]
fn audit_char(ch: char) -> char {
    if ch.is_control() {
        ' '
    } else {
        ch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_field_replaces_controls_and_truncates() {
        let value = format!("abc\n{}", "x".repeat(MAX_AUDIT_FIELD_CHARS + 10));
        let sanitized = audit_field(&value);

        assert!(!sanitized.contains('\n'));
        assert!(sanitized.ends_with("..."));
        assert!(sanitized.len() <= MAX_AUDIT_FIELD_CHARS + 3);
    }
}
