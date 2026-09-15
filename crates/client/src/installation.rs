use ocvpn_model::{DoctorReport, Error, ErrorCode, Result, ServiceAction, ServiceStatus};
use ocvpn_service::installation::{Registration, installer_path};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};
#[cfg(windows)]
mod windows;
fn failed() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "Native service management failed; install or repair the native package and check the OS service manager",
    )
}

async fn invoke(path: &Path, action: &'static str, elevate: bool) -> Result<Registration> {
    ocvpn_engine::validate_installed_file(path)?;
    #[cfg(target_os = "linux")]
    let mut command = if elevate {
        let pkexec = Path::new("/usr/bin/pkexec");
        ocvpn_engine::validate_installed_file(pkexec)?;
        let mut command = Command::new(pkexec);
        command.arg(path);
        command
    } else {
        Command::new(path)
    };
    #[cfg(not(target_os = "linux"))]
    let mut command = {
        let _ = elevate;
        Command::new(path)
    };
    command
        .arg(action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    // Mutating service-manager operations must not be killed midway through teardown.
    command.kill_on_drop(!elevate && action == "status");
    let mut child = command.spawn().map_err(|_| failed())?;
    let stdout = child.stdout.take().ok_or_else(failed)?;
    let stderr = child.stderr.take().ok_or_else(failed)?;
    let operation = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stdout = stdout.take(65537);
        let mut stderr = stderr.take(65537);
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )
        .map_err(|_| failed())?;
        if out.len() > 65536 || err.len() > 65536 {
            return Err(failed());
        }
        if !status.success() {
            if let Ok(error) = serde_json::from_slice::<Error>(&err) {
                return Err(error);
            }
            return Err(Error::new(
                if matches!(status.code(), Some(126 | 127)) {
                    ErrorCode::AuthorizationDenied
                } else {
                    ErrorCode::ServiceUnavailable
                },
                "OS authorization was denied or native service management failed; check service status before retrying",
            ));
        }
        serde_json::from_slice(&out).map_err(|_| failed())
    };
    tokio::time::timeout(Duration::from_secs(if action == "status" { 15 } else { 240 }), operation).await
        .map_err(|_| Error::new(ErrorCode::ServiceUnavailable, "Native management did not finish in time. Its outcome is unknown; check OS service status before retrying."))?
}

pub async fn status() -> Result<ServiceStatus> {
    let installer = installer_path()?;
    let packaged = match std::fs::symlink_metadata(&installer) {
        Ok(_) => {
            ocvpn_engine::validate_installed_file(&installer)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(failed()),
    };
    let registration = if packaged {
        invoke(&installer, "status", false).await?
    } else {
        Registration {
            registered: false,
            approval_required: false,
            login_registered: false,
        }
    };
    let running = match crate::daemon::Connection::open().await {
        Ok(_) => true,
        Err(error) if error.code == ErrorCode::ServiceUnavailable => false,
        Err(error) => return Err(error),
    };
    Ok(ServiceStatus {
        packaged,
        registered: registration.registered,
        running,
        approval_required: registration.approval_required,
        login_registered: registration.login_registered,
    })
}

pub async fn manage(action: ServiceAction) -> Result<ServiceStatus> {
    let installer = installer_path()?;
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || windows::elevate(&installer, action))
            .await
            .map_err(|_| failed())??;
    }
    #[cfg(not(windows))]
    {
        let name = match action {
            ServiceAction::Install => "install",
            ServiceAction::Uninstall => "uninstall",
            ServiceAction::Repair => "repair",
        };
        invoke(&installer, name, cfg!(target_os = "linux")).await?;
    }
    let observed = status().await?;
    if action == ServiceAction::Uninstall && observed.registered && !observed.approval_required {
        return Err(failed());
    }
    if matches!(action, ServiceAction::Install | ServiceAction::Repair)
        && !observed.approval_required
        && (!observed.registered || !observed.running)
    {
        return Err(failed());
    }
    Ok(observed)
}
pub async fn set_login_enabled(enabled: bool) -> Result<()> {
    let result = invoke(
        &installer_path()?,
        if enabled {
            "login-enable"
        } else {
            "login-disable"
        },
        false,
    )
    .await?;
    if result.login_registered != enabled {
        return Err(failed());
    }
    Ok(())
}
pub async fn open_approval_settings() -> Result<()> {
    invoke(&installer_path()?, "open-approval", false)
        .await
        .map(|_| ())
}
pub async fn launch_gui() -> Result<()> {
    let path = crate::browser_os::installed_gui().map_err(|_| Error::new(ErrorCode::ServiceUnavailable, "The desktop package is not installed. Install OpenConnect GUI; CLI and TUI remain independent."))?;
    let mut command = Command::new(path);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().map_err(|_| failed())?;
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(())
}
pub async fn doctor() -> DoctorReport {
    let capabilities = tokio::task::spawn_blocking(crate::capabilities)
        .await
        .unwrap_or_else(|_| Err(failed()));
    let service = status().await;
    let driver = tokio::task::spawn_blocking(driver_ready)
        .await
        .unwrap_or_else(|_| Err(failed()));
    let (capabilities, engine_error) = match capabilities {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    let (service, service_error) = match service {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    DoctorReport {
        capabilities,
        engine_error,
        service,
        service_error,
        driver_ready: driver.is_ok(),
        driver_error: driver.err(),
    }
}
fn driver_ready() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = std::fs::metadata("/dev/net/tun").map_err(|_| Error::new(ErrorCode::ServiceUnavailable, "Linux TUN device is unavailable; enable the kernel tun module and expose /dev/net/tun to the service"))?;
        if !metadata.file_type().is_char_device() || metadata.rdev() != libc::makedev(10, 200) {
            return Err(failed());
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(Error::new(
                ErrorCode::ServiceUnavailable,
                "macOS kernel-control sockets are unavailable",
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        for (target, byte) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
            *target = *byte as libc::c_char;
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } != 0 {
            return Err(Error::new(
                ErrorCode::ServiceUnavailable,
                "macOS utun kernel control is unavailable",
            ));
        }
    }
    #[cfg(windows)]
    {
        use sha2::{Digest, Sha256};
        let root = ocvpn_engine::installed_native_directory()?;
        let bundled = root.join("lib/wintun.dll");
        let installed = root.parent().ok_or_else(failed)?.join("wintun.dll");
        ocvpn_engine::validate_installed_file(&bundled)?;
        ocvpn_engine::validate_installed_file(&installed)?;
        let a = std::fs::read(bundled).map_err(|_| failed())?;
        let b = std::fs::read(installed).map_err(|_| failed())?;
        if a.is_empty() || Sha256::digest(&a) != Sha256::digest(&b) {
            return Err(Error::new(
                ErrorCode::ServiceUnavailable,
                "Installed Wintun differs from the bundled signed distribution; repair the native package",
            ));
        }
    }
    Ok(())
}
