use ocvpn_model::{Error, ErrorCode, Result, ServiceAction};
use std::{
    ffi::OsStr,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_CANCELLED, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize},
        Threading::{GetExitCodeProcess, WaitForSingleObject},
    },
    UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NO_CONSOLE, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW, ShellExecuteExW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "Only the fixed, protected installed service installer can be elevated",
    )
}
fn unknown() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The privileged installer outcome is unknown. It was not terminated; check service status and allow any pending transaction to finish before retrying.",
    )
}
fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut result: Vec<u16> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(denied());
    }
    result.push(0);
    Ok(result)
}
struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

pub(super) fn elevate(installer: &Path, action: ServiceAction) -> Result<()> {
    let native = ocvpn_engine::installed_native_directory()?;
    let expected = native
        .parent()
        .ok_or_else(denied)?
        .join("ocvpn-installer.exe");
    // Lexical equality also prevents accepting a caller-selected alias/reparse path.
    if installer != expected {
        return Err(denied());
    }
    ocvpn_engine::validate_installed_file(&expected)?;
    let file = wide(expected.as_os_str())?;
    let directory = wide(expected.parent().ok_or_else(denied)?.as_os_str())?;
    let verb = wide(OsStr::new("runas"))?;
    let parameters = wide(OsStr::new(match action {
        ServiceAction::Install => "install",
        ServiceAction::Uninstall => "uninstall",
        ServiceAction::Repair => "repair",
    }))?;
    // This function runs on a dedicated blocking thread, never a UI apartment.
    let initialized = unsafe { CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    if initialized < 0 {
        return Err(Error::new(
            ErrorCode::RuntimeFailure,
            "Cannot initialize native Windows authorization on this thread",
        ));
    }
    let _apartment = Apartment;
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of_val(&info) as u32;
    info.fMask =
        SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_NO_CONSOLE;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.lpDirectory = directory.as_ptr();
    info.nShow = SW_HIDE;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(match unsafe { GetLastError() } {
            ERROR_CANCELLED => Error::new(
                ErrorCode::Cancelled,
                "Windows authorization was cancelled; the service installer was not started",
            ),
            ERROR_ACCESS_DENIED => Error::new(
                ErrorCode::AuthorizationDenied,
                "Windows denied service installation authorization. Ask an administrator or check system policy.",
            ),
            _ => Error::new(
                ErrorCode::ServiceUnavailable,
                "Windows could not launch the protected service installer. Reinstall the native package and retry.",
            ),
        });
    }
    if info.hProcess.is_null() {
        return Err(unknown());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    // Closing our handle on timeout does not kill the elevated process or its transaction.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 240_000) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Err(unknown()),
        _ => return Err(unknown()),
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit_code) } == 0 {
        return Err(unknown());
    }
    match exit_code {
        0 => Ok(()),
        4 => Err(Error::new(
            ErrorCode::AuthorizationDenied,
            "The installer could not access the protected service or native resources. Check administrator authorization and run doctor.",
        )),
        5 => Err(Error::new(
            ErrorCode::Conflict,
            "The service registration conflicts with existing native configuration. Inspect it before retrying; unrelated data was preserved.",
        )),
        130 => Err(Error::new(
            ErrorCode::Cancelled,
            "The privileged installer was cancelled. Check service status before retrying.",
        )),
        _ => Err(Error::new(
            ErrorCode::ServiceUnavailable,
            "The privileged installer failed. Run doctor and inspect service status; network recovery may require service repair.",
        )),
    }
}
