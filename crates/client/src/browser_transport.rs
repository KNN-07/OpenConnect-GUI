//! Same-user browser IPC. Authentication happens before callers can exchange frames.
use ocvpn_model::{Error, ErrorCode, Result};
use std::{fs::File, path::PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait BrowserIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BrowserIo for T {}
pub struct UserConnection {
    pub stream: Box<dyn BrowserIo>,
    pub pid: Option<u32>,
}
pub struct UserListener {
    inner: platform::Listener,
    _lock: File,
}
fn unavailable() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "Browser IPC is unavailable; use manual authentication or install the desktop component",
    )
}
fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "Browser IPC ownership could not be verified",
    )
}

/// Deliberately independent of OCVPN_CONFIG_DIR and privileged service endpoints.
pub fn runtime_directory() -> Result<PathBuf> {
    // Unix socket addresses are only 104/108 bytes. Application-support paths
    // (especially on macOS) can exceed that even with an ordinary user name.
    #[cfg(target_os = "linux")]
    let path = {
        let uid = unsafe { libc::geteuid() };
        let session = PathBuf::from(format!("/run/user/{uid}"));
        if session.exists() {
            crate::private_fs::ensure_private_directory(&session).map_err(|_| denied())?;
            session.join("ocvpn")
        } else {
            std::fs::canonicalize("/tmp")
                .map_err(|_| unavailable())?
                .join(format!("ocvpn-browser-{uid}"))
        }
    };
    #[cfg(target_os = "macos")]
    let path = {
        use std::os::unix::ffi::OsStringExt;
        let length =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
        if length == 0 || length > 4096 {
            return Err(unavailable());
        }
        let mut bytes = vec![0u8; length];
        if unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                bytes.as_mut_ptr().cast(),
                length,
            )
        } != length
            || bytes.pop() != Some(0)
        {
            return Err(unavailable());
        }
        let base = std::fs::canonicalize(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
            .map_err(|_| unavailable())?;
        crate::private_fs::ensure_private_directory(&base).map_err(|_| denied())?;
        base.join("ocvpn")
    };
    #[cfg(windows)]
    let path = replay_directory()?.join("runtime");
    crate::private_fs::ensure_private_directory(&path).map_err(|_| denied())?;
    Ok(path)
}

/// One-way replay records survive a reboot; browser profiles and sockets do not.
pub(crate) fn replay_directory() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("org", "OpenConnectGUI", "OpenConnectGUI")
        .ok_or_else(unavailable)?;
    let path = dirs.data_local_dir().join("browser-policy");
    crate::private_fs::ensure_private_directory(&path).map_err(|_| denied())?;
    Ok(path)
}
impl UserListener {
    pub async fn bind() -> Result<Self> {
        let directory = runtime_directory()?;
        let lock = crate::private_fs::open_private_lock(&directory.join("browser.lock"))
            .map_err(|_| denied())?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Error::new(
                    ErrorCode::Busy,
                    "Another browser authentication transaction is active",
                )
            } else {
                unavailable()
            }
        })?;
        let inner = platform::Listener::bind(directory)?;
        Ok(Self { inner, _lock: lock })
    }
    pub async fn accept(&mut self) -> Result<UserConnection> {
        self.inner.accept().await
    }
}
pub async fn connect() -> Result<UserConnection> {
    platform::connect(runtime_directory()?).await
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        path::Path,
    };
    use tokio::net::{UnixListener, UnixStream};
    pub struct Listener {
        socket: UnixListener,
        path: PathBuf,
        device: u64,
        inode: u64,
    }
    fn inspect(path: &Path) -> Result<fs::Metadata> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                unavailable()
            } else {
                denied()
            }
        })?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
        {
            return Err(denied());
        }
        Ok(metadata)
    }
    fn authenticate(stream: UnixStream) -> Result<UserConnection> {
        let credentials = stream.peer_cred().map_err(|_| denied())?;
        if credentials.uid() != unsafe { libc::geteuid() } {
            return Err(denied());
        }
        let pid = credentials.pid().and_then(|pid| u32::try_from(pid).ok());
        Ok(UserConnection {
            stream: Box::new(stream),
            pid,
        })
    }
    impl Listener {
        pub fn bind(directory: PathBuf) -> Result<Self> {
            let path = directory.join("browser.sock");
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    inspect(&path)?;
                    fs::remove_file(&path).map_err(|_| unavailable())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(denied()),
            }
            // Tokio/mio create close-on-exec descriptors. The owner-only parent
            // protects the endpoint even before its mode is tightened.
            let socket = UnixListener::bind(&path).map_err(|_| unavailable())?;
            let metadata = inspect(&path)?;
            let listener = Self {
                socket,
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            fs::set_permissions(&listener.path, fs::Permissions::from_mode(0o600))
                .map_err(|_| unavailable())?;
            Ok(listener)
        }
        pub async fn accept(&mut self) -> Result<UserConnection> {
            let (stream, _) = self.socket.accept().await.map_err(|_| unavailable())?;
            authenticate(stream)
        }
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            if let Ok(metadata) = inspect(&self.path) {
                if metadata.dev() == self.device && metadata.ino() == self.inode {
                    let _ = fs::remove_file(&self.path);
                }
            }
        }
    }
    pub async fn connect(directory: PathBuf) -> Result<UserConnection> {
        let path = directory.join("browser.sock");
        let metadata = inspect(&path)?;
        if metadata.mode() & 0o077 != 0 {
            return Err(denied());
        }
        authenticate(UnixStream::connect(path).await.map_err(|_| unavailable())?)
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        marker::PhantomData,
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
        ptr,
        rc::Rc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            CopySid, GetLengthSid, GetTokenInformation, IsValidSid, RevertToSelf,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
            SECURITY_SQOS_PRESENT,
        },
        System::{
            Pipes::{
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                ImpersonateNamedPipeClient,
            },
            Threading::{
                GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
                OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };
    const HELLO: u8 = 1;
    const CLIENT_ACCESS: u32 = 0x0012_019b;
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct Revert(PhantomData<Rc<()>>);
    impl Drop for Revert {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    fn token_sid(token: HANDLE) -> Result<Vec<u8>> {
        let mut required = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required);
        }
        if required < size_of::<TOKEN_USER>() as u32 || required > 65536 {
            return Err(denied());
        }
        let mut storage = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(denied());
        }
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        if unsafe { IsValidSid(user.User.Sid) } == 0 {
            return Err(denied());
        }
        let length = unsafe { GetLengthSid(user.User.Sid) };
        let mut sid = vec![0u8; length as usize];
        if unsafe { CopySid(length, sid.as_mut_ptr().cast(), user.User.Sid) } == 0 {
            return Err(denied());
        }
        Ok(sid)
    }
    fn process_sid(process: HANDLE) -> Result<Vec<u8>> {
        let mut raw = ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
            return Err(denied());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        token_sid(token.as_raw_handle())
    }
    fn identity() -> Result<(Vec<u8>, String)> {
        let sid = process_sid(unsafe { GetCurrentProcess() })?;
        let mut raw = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut raw) } == 0 {
            return Err(denied());
        }
        let _text = Local(raw.cast());
        let mut length = 0;
        while length < 256 && unsafe { *raw.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(denied());
        }
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
            .map_err(|_| denied())?;
        Ok((sid, text))
    }
    fn name(sid: &str) -> String {
        format!(r"\\.\pipe\OpenConnectGUI.auth.{sid}.v1")
    }
    fn create(sid: &str, first: bool) -> Result<NamedPipeServer> {
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut raw = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(denied());
        }
        let descriptor = Local(raw);
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name(sid),
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                )
        }
        .map_err(|_| unavailable())
    }
    fn client_identity(pipe: &NamedPipeServer, expected: &[u8]) -> Result<Option<u32>> {
        if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
            return Err(denied());
        }
        let revert = Revert(PhantomData);
        let mut raw = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
            return Err(denied());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        if token_sid(token.as_raw_handle())? != expected {
            return Err(denied());
        }
        drop(token);
        drop(revert); // Revert on this thread, before returning to any async code.
        let mut pid = 0;
        Ok(
            (unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } != 0)
                .then_some(pid),
        )
    }
    pub struct Listener {
        pending: NamedPipeServer,
        sid: Vec<u8>,
        text: String,
    }
    impl Listener {
        pub fn bind(_: PathBuf) -> Result<Self> {
            let (sid, text) = identity()?;
            Ok(Self {
                pending: create(&text, true)?,
                sid,
                text,
            })
        }
        pub async fn accept(&mut self) -> Result<UserConnection> {
            self.pending.connect().await.map_err(|_| unavailable())?;
            // Preserve a live instance throughout replacement, even on failure.
            let next = match create(&self.text, false) {
                Ok(next) => next,
                Err(error) => {
                    let _ = self.pending.disconnect();
                    return Err(error);
                }
            };
            let mut pipe = std::mem::replace(&mut self.pending, next);
            // Only this fixed nonsecret byte precedes impersonation. Keeping the
            // accepted pipe local makes cancellation close it, not strand pending.
            if pipe.read_u8().await.map_err(|_| unavailable())? != HELLO {
                return Err(denied());
            }
            let pid = client_identity(&pipe, &self.sid)?;
            pipe.write_u8(HELLO).await.map_err(|_| unavailable())?;
            Ok(UserConnection {
                stream: Box::new(pipe),
                pid,
            })
        }
    }
    pub async fn connect(_: PathBuf) -> Result<UserConnection> {
        let (sid, text) = identity()?;
        let name: Vec<u16> = name(&text).encode_utf16().chain(Some(0)).collect();
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(unavailable());
        }
        let owned = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut pipe = unsafe { NamedPipeClient::from_raw_handle(owned.into_raw_handle()) }
            .map_err(|_| unavailable())?;
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(denied());
        }
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return Err(denied());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        if process_sid(process.as_raw_handle())? != sid {
            return Err(denied());
        }
        pipe.write_u8(HELLO).await.map_err(|_| unavailable())?;
        if pipe.read_u8().await.map_err(|_| unavailable())? != HELLO {
            return Err(denied());
        }
        Ok(UserConnection {
            stream: Box::new(pipe),
            pid: Some(pid),
        })
    }
}
