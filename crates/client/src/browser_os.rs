//! User-session activation and opt-in URL association; no privileged browser process.
use ocvpn_model::{Error, ErrorCode, Result};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
#[path = "browser_os/linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "browser_os/macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "browser_os/windows.rs"]
mod platform;

pub async fn callback_available() -> Result<bool> {
    Ok(association()
        .await?
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(platform::HANDLER)))
}
pub async fn association() -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        platform::association().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        tokio::task::spawn_blocking(platform::association)
            .await
            .map_err(|_| failed())?
    }
}
/// Explicit user consent only. Replacement never occurs as an authentication side effect.
pub async fn register(replace_existing: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        platform::register(replace_existing).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        tokio::task::spawn_blocking(move || platform::register(replace_existing))
            .await
            .map_err(|_| failed())?
    }
}
pub(crate) async fn launch(uri: &str) -> Result<()> {
    let parsed = url::Url::parse(uri).map_err(|_| failed())?;
    if parsed.scheme() != "http"
        || parsed.host_str() != Some("127.0.0.1")
        || parsed.port().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path().len() != 65
        || !parsed.path()[1..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::invalid(
            "Only an owned browser bootstrap can be activated",
        ));
    }
    platform::launch(uri).await
}
#[cfg(target_os = "macos")]
pub fn run_callback_receiver() -> Result<()> {
    platform::run_callback_receiver()
}
fn failed() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "Browser activation is unavailable; use manual authentication or repair the desktop installation",
    )
}

pub fn installed_callback() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    let path = PathBuf::from("/usr/bin/ocvpn-auth-callback");
    #[cfg(target_os = "macos")]
    let path = PathBuf::from(
        "/Applications/OpenConnect GUI.app/Contents/Helpers/OpenConnect Callback.app/Contents/MacOS/ocvpn-auth-callback",
    );
    #[cfg(windows)]
    let path = ocvpn_engine::installed_native_directory()?
        .parent()
        .ok_or_else(failed)?
        .join("ocvpn-auth-callback.exe");
    protected_binary(&path)?;
    Ok(path)
}
pub fn installed_gui() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    let path = PathBuf::from("/usr/bin/ocvpn-gui");
    #[cfg(target_os = "macos")]
    let path = PathBuf::from("/Applications/OpenConnect GUI.app/Contents/MacOS/ocvpn-gui");
    #[cfg(windows)]
    let path = ocvpn_engine::installed_native_directory()?
        .parent()
        .ok_or_else(failed)?
        .join("ocvpn-gui.exe");
    protected_binary(&path)?;
    Ok(path)
}
fn protected_binary(path: &Path) -> Result<()> {
    ocvpn_engine::validate_installed_file(path).map_err(|_| failed())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)
            .map_err(|_| failed())?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err(failed());
        }
    }
    Ok(())
}
