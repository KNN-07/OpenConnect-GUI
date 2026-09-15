pub mod auth;
pub mod browser;
pub mod browser_bootstrap;
pub mod browser_os;
pub mod browser_transport;
mod configuration;
pub mod connect;
pub mod credentials;
pub mod daemon;
pub mod globalprotect;
pub mod installation;
mod licenses;
pub(crate) mod private_fs;
pub mod profiles;
pub mod proxy;
pub use configuration::{remove_profile, save_settings};
pub use licenses::licenses;

use ocvpn_model::{Capabilities, Result};

/// Blocking native discovery. Async and GUI callers must dispatch off their event loop.
pub fn capabilities() -> Result<Capabilities> {
    ocvpn_engine::Engine::load()?.capabilities()
}

/// Read-only user settings plus an explicit stale auto-connect selection diagnostic.
pub fn settings_read() -> Result<ocvpn_model::SettingsRead> {
    let store = profiles::ProfileStore::open()?;
    let document = store.settings()?;
    let auto_connect_error = if let Some(id) = document.settings.auto_connect_profile_id {
        if store
            .list()?
            .profiles
            .iter()
            .any(|profile| profile.id == id)
        {
            None
        } else {
            Some(ocvpn_model::Error::new(
                ocvpn_model::ErrorCode::NotFound,
                "The selected auto-connect profile no longer exists. Choose another profile or disable auto-connect.",
            ))
        }
    } else {
        None
    };
    Ok(ocvpn_model::SettingsRead {
        document,
        auto_connect_error,
    })
}

/// Atomic private export for caller-constructed, sanitized documents.
pub fn export_file(path: &std::path::Path, bytes: &[u8], force: bool) -> Result<()> {
    private_fs::atomic_write(path, bytes, force)
}
