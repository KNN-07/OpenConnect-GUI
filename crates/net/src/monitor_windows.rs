use super::*;
use std::{
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    ptr,
};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{INVALID_HANDLE_VALUE, LocalFree},
    Security::{Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, *},
    Storage::FileSystem::*,
    System::{
        Pipes::{GetNamedPipeServerProcessId, ImpersonateNamedPipeClient},
        Threading::{
            GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};
fn name(t: TransactionId) -> String {
    format!(
        r"\\.\pipe\OpenConnectGUI.network.{}.{}",
        t.service_instance_id, t.attempt_id
    )
}
fn instance(t: TransactionId, first: bool) -> Result<NamedPipeServer> {
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(denied());
    }
    let mut a = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name(t),
                (&mut a as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    unsafe {
        LocalFree(descriptor);
    }
    result.map_err(|_| unavailable())
}
fn system(token: &OwnedHandle) -> Result<()> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length < size_of::<TOKEN_USER>() as u32 || length > 65536 {
        return Err(denied());
    }
    let mut data = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(denied());
    }
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) } == 0 {
        return Err(denied());
    }
    Ok(())
}
fn client_identity(pipe: &NamedPipeServer) -> Result<()> {
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(denied());
    }
    let _revert = Revert;
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        return Err(denied());
    }
    system(&unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub struct Monitor {
    transaction: TransactionId,
    pending: NamedPipeServer,
}
impl Monitor {
    pub async fn bind(transaction: TransactionId) -> Result<Self> {
        secure::privileged()?;
        Ok(Self {
            transaction,
            pending: instance(transaction, true)?,
        })
    }
    pub fn environment(&self) -> Vec<(String, String)> {
        super::environment(self.transaction)
    }
    pub async fn recv(&mut self) -> Result<LifecycleReport> {
        self.pending.connect().await.map_err(|_| unavailable())?;
        let next = instance(self.transaction, false)?;
        let mut pipe = std::mem::replace(&mut self.pending, next);
        tokio::time::timeout(Duration::from_secs(180), async {
            let hello: Hello = read_frame(&mut pipe).await?;
            hello.validate()?;
            client_identity(&pipe)?;
            write_frame(&mut pipe, &Hello { version: VERSION }).await?;
            let report: LifecycleReport = read_frame(&mut pipe).await?;
            if report.transaction != self.transaction {
                return Err(denied());
            }
            write_frame(&mut pipe, &Hello { version: VERSION }).await?;
            Ok(report)
        })
        .await
        .map_err(|_| unavailable())?
    }
}
pub(crate) async fn connect(t: TransactionId) -> Result<NamedPipeClient> {
    secure::privileged()?;
    let name: Vec<u16> = name(t).encode_utf16().chain(Some(0)).collect();
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x0012019b,
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
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(denied());
    }
    system(&unsafe { OwnedHandle::from_raw_handle(raw) })?;
    write_frame(&mut pipe, &Hello { version: VERSION }).await?;
    let hello: Hello = read_frame(&mut pipe).await?;
    hello.validate()?;
    Ok(pipe)
}
