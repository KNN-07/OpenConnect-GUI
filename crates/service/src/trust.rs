use ocvpn_model::{Error, ErrorCode, Result};
use std::path::Path;
fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "Service executable or helper is not in its protected installation",
    )
}
pub(crate) fn installed_file(path: &Path) -> Result<()> {
    ocvpn_engine::validate_installed_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(path).map_err(|_| denied())?.mode() & 0o111 == 0 {
            return Err(denied());
        }
    }
    Ok(())
}
pub(crate) fn worker_process() -> Result<()> {
    let expected = crate::worker::installed_worker()?;
    installed_file(&expected)?;
    if std::env::current_exe()
        .map_err(|_| denied())?
        .canonicalize()
        .map_err(|_| denied())?
        != expected.canonicalize().map_err(|_| denied())?
    {
        return Err(denied());
    }
    #[cfg(unix)]
    unsafe {
        if libc::geteuid() != 0 || libc::getpgrp() != libc::getpid() {
            return Err(denied());
        }
        for fd in [0, 1] {
            let mut stat = std::mem::zeroed();
            if libc::fstat(fd, &mut stat) != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
                return Err(denied());
            }
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation},
            Security::{
                GetTokenInformation, IsWellKnownSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
                WinLocalSystemSid,
            },
            Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType},
            System::{
                Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        };
        unsafe {
            for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE] {
                let handle = GetStdHandle(which);
                if GetFileType(handle) != FILE_TYPE_PIPE
                    || SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) == 0
                {
                    return Err(denied());
                }
            }
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(denied());
            }
            let mut storage = [0usize; 128];
            let mut needed = 0;
            let ok = GetTokenInformation(
                token,
                TokenUser,
                storage.as_mut_ptr().cast(),
                std::mem::size_of_val(&storage) as u32,
                &mut needed,
            );
            let system = ok != 0
                && IsWellKnownSid(
                    (*(storage.as_ptr().cast::<TOKEN_USER>())).User.Sid,
                    WinLocalSystemSid,
                ) != 0;
            CloseHandle(token);
            if !system {
                return Err(denied());
            }
        }
    }
    Ok(())
}
