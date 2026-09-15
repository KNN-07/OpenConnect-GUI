use super::{InstallerCommand, Registration, denied, unavailable};
use fs2::FileExt;
use ocvpn_model::{Error, ErrorCode, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const UNIT: &str = "ocvpnd.service";
const SOCKET: &str = "ocvpnd.socket";
const LOGIN: &str = "[Desktop Entry]\nType=Application\nName=OpenConnect GUI auto-connect\nExec=/usr/bin/ocvpn autoconnect\nTryExec=/usr/bin/ocvpn\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n";

fn systemctl(args: &[&str]) -> Result<(bool, String)> {
    crate::trust::installed_file(Path::new(SYSTEMCTL))?;
    let mut child = Command::new(SYSTEMCTL)
        .args(["--no-pager", "--no-ask-password"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| unavailable())?;
    let stdout = child.stdout.take().ok_or_else(unavailable)?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(16385).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        match child.try_wait().map_err(|_| unavailable())? {
            Some(status) => break status,
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(Error::new(
                    ErrorCode::ServiceUnavailable,
                    "The systemd operation timed out; its outcome is unknown. Check the unit state before retrying.",
                ));
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    if bytes.len() > 16384 {
        return Err(unavailable());
    }
    Ok((
        status.success(),
        String::from_utf8(bytes)
            .map_err(|_| unavailable())?
            .trim()
            .to_owned(),
    ))
}
fn checked(args: &[&str]) -> Result<()> {
    if systemctl(args)?.0 {
        Ok(())
    } else {
        Err(unavailable())
    }
}
fn property(name: &str) -> Result<String> {
    let (success, value) = systemctl(&["show", UNIT, "--property", name, "--value"])?;
    if !success {
        return Err(unavailable());
    }
    Ok(value)
}
fn state() -> Result<Registration> {
    let manager_running = match fs::metadata("/run/systemd/system") {
        Ok(metadata) if metadata.is_dir() => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        _ => return Err(unavailable()),
    };
    let registered = if manager_running {
        let loaded = property("LoadState")?;
        if !matches!(loaded.as_str(), "loaded" | "not-found" | "masked") {
            return Err(unavailable());
        }
        loaded == "loaded"
    } else {
        false
    };
    // Foreground/external supervisors have no systemd registration. The client
    // separately authenticates the actual daemon to determine running state.
    Ok(Registration {
        registered,
        approval_required: false,
        login_registered: login_value()?.is_some(),
    })
}
fn trusted_units() -> Result<()> {
    for (name, expected) in [
        (
            UNIT,
            include_bytes!("../../../../packaging/linux/ocvpnd.service").as_slice(),
        ),
        (
            SOCKET,
            include_bytes!("../../../../packaging/linux/ocvpnd.socket").as_slice(),
        ),
    ] {
        let path = Path::new("/usr/lib/systemd/system").join(name);
        ocvpn_engine::validate_installed_file(&path)?;
        if fs::read(path).map_err(|_| unavailable())? != expected {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Installed systemd unit differs from this package; reconcile it before repair",
            ));
        }
    }
    crate::trust::installed_file(&crate::worker::installed_worker()?)?;
    crate::trust::installed_file(&ocvpn_engine::tunnel::installed_helper()?)?;
    Ok(())
}
fn management_lock() -> Result<File> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(denied());
    }
    let root = Path::new("/var/lib/openconnect-gui");
    if !root.try_exists().map_err(|_| denied())? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root)
            .map_err(|_| denied())?;
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| denied())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(denied());
    }
    let path = root.join("installer.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| denied())?;
    ocvpn_engine::validate_installed_file(&path)?;
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(denied());
    }
    file.try_lock_exclusive().map_err(|_| {
        Error::new(
            ErrorCode::Busy,
            "Another native installer operation is active",
        )
    })?;
    // Repair may run before tmpfiles or the service has ever created /run state.
    // Initialize only an absent directory; never chmod an existing untrusted one.
    let runtime = Path::new(crate::CONTROL_ENDPOINT)
        .parent()
        .ok_or_else(denied)?;
    match fs::create_dir(runtime) {
        Ok(()) => {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(runtime, fs::Permissions::from_mode(0o755))
                .map_err(|_| denied())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(denied()),
    }
    crate::unix::validate_control_directory().map_err(|_| denied())?;
    Ok(file)
}
fn stop_and_recover() -> Result<()> {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err(Error::new(
            ErrorCode::ServiceUnavailable,
            "Safe systemd management requires cgroup v2. Use the documented foreground supervisor on other Linux configurations.",
        ));
    }
    let group = property("ControlGroup")?;
    if group.is_empty() && Path::new(crate::CONTROL_ENDPOINT).exists() {
        return Err(Error::new(
            ErrorCode::RecoveryRequired,
            "An unmanaged or stale control endpoint exists. Stop the foreground supervisor and establish worker quiescence before native service repair.",
        ));
    }
    checked(&["stop", SOCKET, UNIT])?;
    if !group.is_empty() {
        if !group.starts_with('/')
            || Path::new(&group)
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(unavailable());
        }
        let directory = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match fs::read_to_string(directory.join("cgroup.events")) {
                Ok(events) if events.lines().any(|line| line == "populated 0") => break,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && !directory.exists() =>
                {
                    break;
                }
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
                _ => {
                    return Err(Error::new(
                        ErrorCode::RecoveryRequired,
                        "Owned service processes are not proven quiescent; files and journals retained",
                    ));
                }
            }
        }
    }
    let warnings = crate::lifetime::offline_recover_all()?;
    if !warnings.is_empty() {
        return Err(crate::worker::recovery_warning(warnings));
    }
    Ok(())
}
fn login_path() -> Result<PathBuf> {
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(denied());
    }
    for parent in root.ancestors().filter(|parent| parent.exists()) {
        if fs::symlink_metadata(parent)
            .map_err(|_| denied())?
            .file_type()
            .is_symlink()
        {
            return Err(denied());
        }
    }
    Ok(root.join("autostart/org.openconnectgui.autoconnect.desktop"))
}
fn login_value() -> Result<Option<String>> {
    let path = login_path()?;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(denied()),
    };
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 8192
    {
        return Err(denied());
    }
    let mut value = String::new();
    file.take(8193)
        .read_to_string(&mut value)
        .map_err(|_| denied())?;
    if value != LOGIN {
        return Err(Error::new(
            ErrorCode::Conflict,
            "The auto-connect desktop entry was changed outside this application; preserve and reconcile it before changing login behavior",
        ));
    }
    Ok(Some(value))
}
fn login(enabled: bool) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(Error::new(
            ErrorCode::AuthorizationDenied,
            "Configure auto-connect in the ordinary logged-in user session, not as root",
        ));
    }
    let old = login_value()?;
    if enabled == old.is_some() {
        return Ok(());
    }
    let path = login_path()?;
    if !enabled {
        fs::remove_file(&path).map_err(|_| denied())?;
        File::open(path.parent().ok_or_else(denied)?)
            .and_then(|file| file.sync_all())
            .map_err(|_| denied())?;
        return Ok(());
    }
    super::cli_path()?;
    let directory = path.parent().ok_or_else(denied)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|_| denied())?;
    for parent in directory.ancestors() {
        let metadata = fs::symlink_metadata(parent).map_err(|_| denied())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(denied());
        }
    }
    let temporary = directory.join(format!(".ocvpn-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| denied())?;
        file.write_all(LOGIN.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| denied())?;
        fs::hard_link(&temporary, &path).map_err(|_| {
            Error::new(
                ErrorCode::Conflict,
                "Login entry changed during registration",
            )
        })?;
        fs::remove_file(&temporary).map_err(|_| denied())?;
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| denied())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
pub(super) fn execute(command: InstallerCommand) -> Result<Registration> {
    match command {
        InstallerCommand::Status => return state(),
        InstallerCommand::LoginEnable | InstallerCommand::LoginDisable => {
            login(matches!(command, InstallerCommand::LoginEnable))?
        }
        InstallerCommand::OpenApproval => {
            return Err(Error::new(
                ErrorCode::AuthorizationDenied,
                "Linux authorization is requested through the desktop polkit agent during service management; no separate approval settings page is required",
            ));
        }
        InstallerCommand::Install | InstallerCommand::Uninstall | InstallerCommand::Repair => {
            let _lock = management_lock()?;
            trusted_units()?;
            checked(&["daemon-reload"])?;
            stop_and_recover()?;
            if matches!(command, InstallerCommand::Uninstall) {
                checked(&["disable", SOCKET, UNIT])?;
                // Assets remain package-owned; explicit service install may re-enable them.
                checked(&["mask", SOCKET, UNIT])?;
            } else {
                checked(&["unmask", SOCKET, UNIT])?;
                checked(&["enable", SOCKET, UNIT])?;
                checked(&["start", UNIT])?;
            }
        }
    }
    state()
}
