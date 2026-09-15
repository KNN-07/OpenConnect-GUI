//! Fixed installed entrypoint. No caller-selected executable, script, unit, or path.
use ocvpn_model::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
#[path = "installation/linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "installation/macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "installation/windows.rs"]
mod platform;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum InstallerCommand {
    Status,
    Install,
    Uninstall,
    Repair,
    LoginEnable,
    LoginDisable,
    OpenApproval,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub registered: bool,
    pub approval_required: bool,
    pub login_registered: bool,
}

pub fn installer_path() -> Result<PathBuf> {
    let worker = crate::worker::installed_worker()?;
    Ok(worker
        .parent()
        .ok_or_else(unavailable)?
        .join(if cfg!(windows) {
            "ocvpn-installer.exe"
        } else {
            "ocvpn-installer"
        }))
}
pub(crate) fn unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "Native service management is unavailable. Install the native package or check the OS service manager, then retry service repair.",
    )
}
pub(crate) fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "This operation requires the fixed protected installer and native OS authorization.",
    )
}
pub(crate) fn cli_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    let path = PathBuf::from("/usr/bin/ocvpn");
    #[cfg(not(target_os = "linux"))]
    let path = installer_path()?
        .parent()
        .ok_or_else(unavailable)?
        .join(if cfg!(windows) { "ocvpn.exe" } else { "ocvpn" });
    crate::trust::installed_file(&path)?;
    Ok(path)
}
pub fn execute(command: InstallerCommand) -> Result<Registration> {
    let expected = installer_path()?;
    crate::trust::installed_file(&expected)?;
    if std::env::current_exe()
        .map_err(|_| denied())?
        .canonicalize()
        .map_err(|_| denied())?
        != expected.canonicalize().map_err(|_| denied())?
    {
        return Err(denied());
    }
    platform::execute(command)
}

#[cfg(target_os = "macos")]
pub(crate) fn authorize_quiesce(token: &ocvpn_model::SecretText) -> Result<()> {
    platform::authorize_quiesce(token)
}
