use crate::{CONTROL_ENDPOINT, PeerIdentity, denied};
use std::{
    io,
    marker::PhantomData,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, CopySid, GetLengthSid,
        GetTokenInformation, IsValidSid, IsWellKnownSid, RevertToSelf, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{GetNamedPipeServerProcessId, ImpersonateNamedPipeClient},
        Threading::{
            GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

// Read/write data and attributes, READ_CONTROL and SYNCHRONIZE, but never
// FILE_CREATE_PIPE_INSTANCE (0x4). GENERIC_WRITE would grant that dangerous bit.
const CLIENT_ACCESS: u32 = 0x0012_019b;
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)";

struct SecurityDescriptor(*mut std::ffi::c_void);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn create_instance(first: bool) -> io::Result<NamedPipeServer> {
    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(Some(0)).collect();
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
        return Err(io::Error::last_os_error());
    }
    let descriptor = SecurityDescriptor(raw);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // CreateNamedPipe copies the security descriptor during this call.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                CONTROL_ENDPOINT,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
}

/// Keeps one pipe instance alive continuously to preserve ownership of the name.
/// Authenticated users cannot create competing instances through this DACL.
pub struct ControlListener {
    pending: NamedPipeServer,
}
impl ControlListener {
    /// Requires a Tokio I/O runtime. A preexisting pipe name fails closed.
    pub fn bind() -> io::Result<Self> {
        Ok(Self {
            pending: create_instance(true)?,
        })
    }

    /// Returns an UNAUTHENTICATED connection. Read only the bounded Hello frame,
    /// then call peer_identity synchronously before dispatching any request.
    /// Replenish before handing out the connection, so the name has no gap.
    pub async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        self.pending.connect().await?;
        let next = create_instance(false)?;
        Ok(std::mem::replace(&mut self.pending, next))
    }
}

/// Neither Send nor Sync: Windows impersonation is strictly thread-local.
/// This guard never crosses an await or leaves the synchronous capture function.
struct ImpersonationGuard(PhantomData<Rc<()>>);
impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // Continuing a privileged runtime with a leaked impersonation is unsafe.
        // Microsoft requires process termination if RevertToSelf fails.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn token_identity(token: HANDLE) -> io::Result<(PeerIdentity, bool)> {
    let mut required = 0;
    let result =
        unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required) };
    if result != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(denied("Cannot determine native token user size"));
    }
    if required < size_of::<TOKEN_USER>() as u32 || required > 65536 {
        return Err(denied("Native token user size is outside bounds"));
    }
    // TOKEN_USER includes pointers and must not live in a byte-aligned buffer.
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
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(denied("Invalid native user SID"));
    }
    let length = unsafe { GetLengthSid(user.User.Sid) };
    let mut sid = vec![0u8; length as usize];
    if unsafe { CopySid(length, sid.as_mut_ptr().cast(), user.User.Sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let system = unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) } != 0;
    Ok((PeerIdentity { sid }, system))
}

/// Capture the SID of the last message read on this server pipe. The dispatcher
/// must first read the bounded, nonsecret Hello; no JSON identity is accepted.
/// Every error denies access, and reversion happens before this function returns.
pub fn peer_identity(pipe: &NamedPipeServer) -> io::Result<PeerIdentity> {
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = ImpersonationGuard(PhantomData);
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    token_identity(token.as_raw_handle()).map(|(identity, _)| identity)
}

/// Verify the actual named-pipe server process runs as LocalSystem. Deployment
/// must use this identity; a same-name per-user process is never trusted.
pub fn validate_control_peer(pipe: &NamedPipeClient) -> io::Result<()> {
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !token_identity(token.as_raw_handle())?.1 {
        return Err(denied("Control service is not running as LocalSystem"));
    }
    Ok(())
}

/// Open only the fixed endpoint with identification-only impersonation rights.
/// Uses specific file rights because Tokio's GENERIC_WRITE client default would
/// require FILE_CREATE_PIPE_INSTANCE. No secret is sent before server validation.
/// Requires a Tokio I/O runtime; busy/unavailable pipes are returned as errors.
pub fn connect_control() -> io::Result<NamedPipeClient> {
    let name: Vec<u16> = CONTROL_ENDPOINT.encode_utf16().chain(Some(0)).collect();
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
        return Err(io::Error::last_os_error());
    }
    // Tokio assumes ownership even when registration fails.
    let owned = unsafe { OwnedHandle::from_raw_handle(raw) };
    let pipe = unsafe { NamedPipeClient::from_raw_handle(owned.into_raw_handle()) }?;
    validate_control_peer(&pipe)?;
    Ok(pipe)
}
