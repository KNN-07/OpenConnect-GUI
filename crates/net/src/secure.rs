use ocvpn_model::{Error, ErrorCode, Result};
use std::{fs::File, path::Path};
#[cfg(unix)]
use std::{fs::OpenOptions, path::PathBuf};
fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "Network operation requires protected administrator-owned resources",
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn root() -> PathBuf {
    PathBuf::from("/run/openconnect-gui/network")
}
#[cfg(target_os = "macos")]
pub(crate) fn root() -> PathBuf {
    PathBuf::from("/private/var/db/org.openconnectgui/network")
}
#[cfg(target_os = "linux")]
pub(crate) fn journal_root() -> PathBuf {
    PathBuf::from("/var/lib/openconnect-gui/network")
}
#[cfg(target_os = "macos")]
pub(crate) fn journal_root() -> PathBuf {
    PathBuf::from("/Library/Application Support/OpenConnectGUI/network")
}

#[cfg(unix)]
pub(crate) fn privileged() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(denied())
    }
}
#[cfg(unix)]
pub(crate) fn check(path: &Path, private: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(|_| denied())?;
    if m.file_type().is_symlink()
        || m.uid() != 0
        || m.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        return Err(denied());
    }
    Ok(())
}
#[cfg(unix)]
pub(crate) fn directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    privileged()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && parent != path {
            directory_parent(parent)?;
        }
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(denied()),
    }
    check(path, true)?;
    if !path.is_dir() {
        return Err(denied());
    }
    Ok(())
}
#[cfg(unix)]
fn directory_parent(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if path.parent().is_none() {
        return check(path, false);
    }
    if let Some(parent) = path.parent() {
        directory_parent(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o755).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(denied()),
    }
    check(path, false)
}
#[cfg(unix)]
pub(crate) fn open(path: &Path, create: bool) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| denied())?;
    let m = f.metadata().map_err(|_| denied())?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 {
        return Err(denied());
    }
    Ok(f)
}
#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| crate::failure("Cannot durably commit network journal"))
}

#[cfg(windows)]
#[path = "secure_windows.rs"]
mod native;
#[cfg(windows)]
pub(crate) use native::{directory, open, privileged, sync_directory};

#[cfg(target_os = "linux")]
pub(crate) fn boot_id() -> Result<String> {
    use std::io::Read;
    let mut value = String::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .and_then(|f| f.take(64).read_to_string(&mut value))
        .map_err(|_| crate::failure("Cannot read OS boot identity"))?;
    let id: uuid::Uuid = value
        .trim()
        .parse()
        .map_err(|_| crate::failure("Invalid OS boot identity"))?;
    if id.is_nil() {
        return Err(crate::failure("Invalid OS boot identity"));
    }
    Ok(id.to_string())
}

#[cfg(target_os = "macos")]
pub(crate) fn boot_id() -> Result<String> {
    // XNU kern_sysctl.c exposes a read-only UUID unaffected by wall-clock changes.
    let mut value = [0u8; 64];
    let mut size = value.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            value.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
        || size > value.len()
    {
        return Err(crate::failure("Cannot read OS boot identity"));
    }
    let text = std::str::from_utf8(&value[..size])
        .map_err(|_| crate::failure("Invalid OS boot identity"))?;
    let id: uuid::Uuid = text
        .trim_end_matches('\0')
        .parse()
        .map_err(|_| crate::failure("Invalid OS boot identity"))?;
    if id.is_nil() {
        return Err(crate::failure("Invalid OS boot identity"));
    }
    Ok(id.to_string())
}

#[cfg(windows)]
pub(crate) fn boot_id() -> Result<String> {
    // SYSTEM_BOOT_ENVIRONMENT_INFORMATION (class90), Windows Vista and later.
    // Layout reference: winsiderss/phnt ntexapi.h; only the BootIdentifier is used.
    #[repr(C)]
    struct BootEnvironment {
        identifier: [u8; 16],
        firmware: u32,
        flags: u64,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: i32,
            buffer: *mut std::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut value: BootEnvironment = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    let length = std::mem::size_of::<BootEnvironment>() as u32;
    if unsafe {
        NtQuerySystemInformation(
            90,
            (&mut value as *mut BootEnvironment).cast(),
            length,
            &mut returned,
        )
    } < 0
        || returned != length
    {
        return Err(crate::failure("Cannot read OS boot identity"));
    }
    let id = uuid::Uuid::from_bytes(value.identifier);
    if id.is_nil() {
        return Err(crate::failure("Invalid OS boot identity"));
    }
    Ok(id.to_string())
}
