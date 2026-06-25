mod account;
mod error;
mod event_log;
mod local_alloc;
mod provider;
mod registry;
mod security;
mod service;

pub(crate) use account::{
    create_local_admin_account, delete_local_account, hide_local_account_from_sign_in,
    unhide_local_account_from_sign_in,
};
pub(crate) use event_log::{register_event_log_source, unregister_event_log_source};
pub(crate) use provider::{register_provider, unregister_provider};
pub(crate) use security::secure_program_data_dir;
pub(crate) use service::{install_or_replace_service, stop_and_delete_service};
