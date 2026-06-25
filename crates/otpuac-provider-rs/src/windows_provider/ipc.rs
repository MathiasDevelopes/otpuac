use crate::build_unlock_request;
use otpuac_core::{ProviderUnlockResponse, UnlockDecision};
use otpuac_windows_support::pipe::{
    connect_default_client_pipe, read_framed_message, write_framed_message,
};

pub(super) fn request_unlock(code: &str) -> Result<UnlockDecision, String> {
    let request_id = format!(
        "provider-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    );
    let request = build_unlock_request(request_id, code.to_string());
    let pipe = connect_default_client_pipe().map_err(|err| err.to_string())?;
    write_framed_message(pipe.raw(), &request).map_err(|err| err.to_string())?;
    let response =
        read_framed_message::<ProviderUnlockResponse>(pipe.raw()).map_err(|err| err.to_string())?;
    Ok(response.into_decision())
}
