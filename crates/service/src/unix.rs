use crate::{CONTROL_ENDPOINT, PeerIdentity, denied};
use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
};
use tokio::net::{UnixListener, UnixStream};

static ACTIVATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Check the installed parent and its resolved ancestors. macOS /var itself is
/// an OS-managed symlink; the application's own directory must not be one.
/// Installation, not the runtime, creates this root-owned 0755 directory.
pub fn validate_control_directory() -> io::Result<()> {
    let parent = Path::new(CONTROL_ENDPOINT)
        .parent()
        .expect("fixed absolute endpoint");
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o755 {
        return Err(denied(
            "Control directory must be a root-owned, non-symlink 0755 directory",
        ));
    }
    let canonical = fs::canonicalize(parent)?;
    for ancestor in canonical.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(denied(
                "Control endpoint ancestor is not protected by root ownership",
            ));
        }
    }
    Ok(())
}

/// Check filesystem provenance, not service liveness. Does not follow a socket
/// symlink, create directories, or remove a potentially live/stale endpoint.
pub fn validate_control_endpoint() -> io::Result<()> {
    validate_control_directory()?;
    let metadata = fs::symlink_metadata(CONTROL_ENDPOINT)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o666
    {
        return Err(denied(
            "Control endpoint must be a root-owned, non-symlink 0666 socket",
        ));
    }
    Ok(())
}

/// Bind the fixed endpoint while holding the machine-wide service lock.
/// A stale socket is removed only under that lock and after a refused connect.
pub fn bind_control_listener() -> io::Result<UnixListener> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(denied("Only root may bind the control endpoint"));
    }
    validate_control_directory()?;
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    static LOCK: std::sync::OnceLock<fs::File> = std::sync::OnceLock::new();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(CONTROL_ENDPOINT).with_file_name("service.lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(denied("Unsafe service lock"));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    LOCK.set(lock)
        .map_err(|_| denied("Control listener already initialized"))?;
    #[cfg(target_os = "linux")]
    if std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(std::process::id())
    {
        use std::os::fd::FromRawFd;
        if std::env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
            return Err(denied("Expected exactly one systemd activation socket"));
        }
        validate_control_endpoint()?;
        let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
        if listener.local_addr()?.as_pathname() != Some(Path::new(CONTROL_ENDPOINT)) {
            return Err(denied("Activation socket has an unexpected address"));
        }
        let mut accepting: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&accepting) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut size,
            )
        } != 0
            || accepting != 1
        {
            return Err(denied("Activation descriptor is not a listening socket"));
        }
        let flags = unsafe { libc::fcntl(3, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(3, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        listener.set_nonblocking(true)?;
        ACTIVATED.store(true, std::sync::atomic::Ordering::Release);
        return UnixListener::from_std(listener);
    }
    if fs::symlink_metadata(CONTROL_ENDPOINT).is_ok() {
        validate_control_endpoint()?;
        match std::os::unix::net::UnixStream::connect(CONTROL_ENDPOINT) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(CONTROL_ENDPOINT)?
            }
            _ => return Err(denied("Control endpoint may still be live")),
        }
    }
    let listener = UnixListener::bind(CONTROL_ENDPOINT)?;
    fs::set_permissions(CONTROL_ENDPOINT, fs::Permissions::from_mode(0o666))?;
    validate_control_endpoint()?;
    Ok(listener)
}

/// Credentials come from the kernel, not fields supplied by the client.
pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    Ok(PeerIdentity {
        uid: stream.peer_cred()?.uid(),
    })
}

/// Return only an authenticated stream; the future dispatcher owns framing and
/// hello/version validation before any method is authorized.
pub async fn accept_authenticated(
    listener: &UnixListener,
) -> io::Result<(UnixStream, PeerIdentity)> {
    let (stream, _) = listener.accept().await?;
    let identity = peer_identity(&stream)?;
    Ok((stream, identity))
}

/// Clients must perform both the filesystem check and kernel identity check
/// before sending credentials. A trusted endpoint alone does not prove liveness.
pub async fn connect_control() -> io::Result<UnixStream> {
    validate_control_endpoint()?;
    let stream = UnixStream::connect(CONTROL_ENDPOINT).await?;
    if peer_identity(&stream)?.uid() != 0 {
        return Err(denied("Control service peer is not root"));
    }
    Ok(stream)
}

pub(crate) struct EndpointGuard {
    device: u64,
    inode: u64,
}
impl EndpointGuard {
    pub(crate) fn capture() -> io::Result<Self> {
        let metadata = fs::symlink_metadata(CONTROL_ENDPOINT)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if ACTIVATED.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        if fs::symlink_metadata(CONTROL_ENDPOINT)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = fs::remove_file(CONTROL_ENDPOINT);
        }
    }
}
