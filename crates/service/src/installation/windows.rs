use super::{InstallerCommand, Registration, cli_path, denied, unavailable};
use ocvpn_model::{Error, ErrorCode, Result};
use std::{
    ffi::{OsStr, OsString},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr, thread,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_MARKED_FOR_DELETE, WAIT_OBJECT_0,
    },
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::{
        Registry::*,
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        },
    },
};

const NAME: &str = "OpenConnectGUI";
const WAIT: Duration = Duration::from_secs(60);
fn conflict() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "The OpenConnectGUI registration was changed by another application or administrator. Restore the owned registration before retrying; unrelated data was preserved.",
    )
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn win_error(code: u32) -> Error {
    if code == ERROR_ACCESS_DENIED {
        denied()
    } else {
        unavailable()
    }
}
fn scm_error(error: windows_service::Error) -> Error {
    match error {
        windows_service::Error::Winapi(error) => {
            win_error(error.raw_os_error().unwrap_or(0) as u32)
        }
        _ => unavailable(),
    }
}
fn missing(error: &windows_service::Error) -> bool {
    matches!(error, windows_service::Error::Winapi(e) if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32))
}
fn elevated() -> Result<()> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(denied());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut size = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut size,
        )
    } == 0
        || elevation.TokenIsElevated == 0
    {
        return Err(denied());
    }
    Ok(())
}
fn quoted(path: &Path) -> Result<OsString> {
    if path
        .as_os_str()
        .encode_wide()
        .any(|c| c == 0 || c == b'"' as u16 || c < 32)
    {
        return Err(denied());
    }
    let mut value = OsString::from("\"");
    value.push(path);
    value.push("\"");
    Ok(value)
}
fn manager(write: bool) -> Result<ServiceManager> {
    ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT
            | if write {
                ServiceManagerAccess::CREATE_SERVICE
            } else {
                ServiceManagerAccess::empty()
            },
    )
    .map_err(scm_error)
}
fn open(manager: &ServiceManager, access: ServiceAccess) -> Result<Option<Service>> {
    match manager.open_service(NAME, access) {
        Ok(service) => Ok(Some(service)),
        Err(error) if missing(&error) => Ok(None),
        Err(error) => Err(scm_error(error)),
    }
}
fn owned(service: &Service, worker: &Path) -> Result<()> {
    let config = service.query_config().map_err(scm_error)?;
    let command = config.executable_path.as_os_str();
    let quoted = quoted(worker)?;
    let plain_safe = !worker.as_os_str().encode_wide().any(|c| c <= 32);
    if (command != quoted && !(plain_safe && command == worker.as_os_str()))
        || config.service_type != ServiceType::OWN_PROCESS
        || config.account_name.as_deref() != Some(OsStr::new("LocalSystem"))
    {
        return Err(conflict());
    }
    Ok(())
}
fn wait_state(service: &Service, target: ServiceState) -> Result<()> {
    let deadline = Instant::now() + WAIT;
    loop {
        let state = service.query_status().map_err(scm_error)?.current_state;
        if state == target {
            return Ok(());
        }
        if target == ServiceState::Running && state == ServiceState::Stopped {
            return Err(Error::new(
                ErrorCode::ServiceUnavailable,
                "The Windows service stopped during startup. Run doctor and inspect service diagnostics.",
            ));
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                ErrorCode::ServiceUnavailable,
                "The Windows service transition has not completed. No process was killed; check service status before retrying.",
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}
fn stop(service: &Service) -> Result<()> {
    let deadline = Instant::now() + WAIT;
    // A PID is reliable only outside start/stop-pending. Never attach to a stale stopped PID.
    loop {
        let status = service.query_status().map_err(scm_error)?;
        match status.current_state {
            ServiceState::Stopped => return Ok(()),
            ServiceState::StartPending | ServiceState::StopPending => {
                if Instant::now() >= deadline {
                    return Err(unavailable());
                }
                thread::sleep(Duration::from_millis(200));
            }
            _ => {
                let pid = status
                    .process_id
                    .filter(|pid| *pid != 0)
                    .ok_or_else(unavailable)?;
                let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
                if raw.is_null() {
                    return Err(unavailable());
                }
                let process = unsafe { OwnedHandle::from_raw_handle(raw) };
                service.stop().map_err(scm_error)?;
                wait_state(service, ServiceState::Stopped)?;
                if unsafe { WaitForSingleObject(process.as_raw_handle(), WAIT.as_millis() as u32) }
                    != WAIT_OBJECT_0
                {
                    return Err(Error::new(
                        ErrorCode::RecoveryRequired,
                        "Service process termination is not confirmed. Recovery and removal were not attempted; retry after it exits.",
                    ));
                }
                return Ok(());
            }
        }
    }
}
fn recover() -> Result<()> {
    match ocvpn_net::recover_all() {
        Ok(warnings) if warnings.is_empty() => Ok(()),
        _ => Err(Error::new(
            ErrorCode::RecoveryRequired,
            "Network recovery is incomplete. The service registration and transaction journal were retained; run doctor and retry service repair.",
        )),
    }
}
fn service_info(worker: &Path) -> ServiceInfo {
    ServiceInfo {
        name: NAME.into(),
        display_name: "OpenConnect GUI".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: worker.into(),
        launch_arguments: Vec::new(),
        dependencies: Vec::new(),
        account_name: Some("LocalSystem".into()),
        account_password: None,
    }
}

struct ManagementLock(OwnedHandle);
impl Drop for ManagementLock {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0.as_raw_handle());
        }
    }
}
fn management_lock() -> Result<ManagementLock> {
    use windows_sys::Win32::{
        Foundation::{LocalFree, WAIT_ABANDONED, WAIT_TIMEOUT},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        System::Threading::CreateMutexW,
    };
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows_sys::w!("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(denied());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateMutexW(
            &attributes,
            0,
            windows_sys::w!("Global\\OpenConnectGUI.Installation.v1"),
        )
    };
    unsafe {
        LocalFree(descriptor.cast());
    }
    if raw.is_null() {
        return Err(denied());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), WAIT.as_millis() as u32) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(ManagementLock(handle)),
        WAIT_TIMEOUT => Err(Error::new(
            ErrorCode::Busy,
            "Another service installation operation is still running. Wait for it to finish and retry.",
        )),
        _ => Err(unavailable()),
    }
}
fn mutate(command: InstallerCommand) -> Result<()> {
    elevated()?;
    let _management = management_lock()?;
    let worker = crate::worker::installed_worker()?;
    crate::trust::installed_file(&worker)?;
    let manager = manager(true)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::STOP
        | ServiceAccess::START
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::DELETE;
    let existing = open(&manager, access)?;
    if let Some(service) = &existing {
        owned(service, &worker)?;
        stop(service)?;
    }
    recover()?;
    if matches!(command, InstallerCommand::Uninstall) {
        if let Some(service) = existing {
            service.delete().map_err(scm_error)?;
            drop(service);
        }
        let deadline = Instant::now() + WAIT;
        loop {
            match manager.open_service(NAME, ServiceAccess::QUERY_STATUS) {
                Err(error) if missing(&error) => return Ok(()),
                Err(windows_service::Error::Winapi(error))
                    if error.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) => {}
                Err(error) => return Err(scm_error(error)),
                Ok(service) => drop(service),
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorCode::ServiceUnavailable,
                    "Service deletion is pending an open native handle. Close Services management windows and retry; do not remove helper files yet.",
                ));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
    let info = service_info(&worker);
    let service = if let Some(service) = existing {
        service.change_config(&info).map_err(scm_error)?;
        service
    } else {
        manager.create_service(&info, access).map_err(scm_error)?
    };
    service.start::<&str>(&[]).map_err(scm_error)?;
    wait_state(&service, ServiceState::Running)
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn login_key(write: bool) -> Result<Option<Key>> {
    let subkey = wide(OsStr::new(r"Software\Microsoft\Windows\CurrentVersion\Run"));
    let mut raw = ptr::null_mut();
    let access = KEY_QUERY_VALUE | KEY_WOW64_64KEY | if write { KEY_SET_VALUE } else { 0 };
    let code = if write {
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                ptr::null(),
                &mut raw,
                ptr::null_mut(),
            )
        }
    } else {
        unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut raw) }
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if code != 0 {
        return Err(win_error(code));
    }
    Ok(Some(Key(raw)))
}
fn login_command() -> Result<Vec<u16>> {
    let mut value = quoted(&cli_path()?)?;
    value.push(" autoconnect");
    let value = wide(&value);
    // Windows Run keys have a documented 260-character command limit.
    if value.len() > 260 {
        return Err(Error::invalid(
            "The installed CLI path exceeds the Windows login command limit",
        ));
    }
    Ok(value)
}
fn login_present(key: &Key, expected: &[u16]) -> Result<bool> {
    let name = wide(OsStr::new(NAME));
    let mut value = [0u16; 1024];
    let mut bytes = std::mem::size_of_val(&value) as u32;
    let mut kind = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if code == windows_sys::Win32::Foundation::ERROR_MORE_DATA {
        return Err(conflict());
    }
    if code != 0 {
        return Err(win_error(code));
    }
    if kind != REG_SZ
        || bytes as usize != expected.len() * 2
        || value.get(..expected.len()) != Some(expected)
    {
        return Err(conflict());
    }
    Ok(true)
}
fn login(change: Option<bool>) -> Result<bool> {
    let expected = login_command()?;
    let Some(key) = login_key(change.is_some())? else {
        return Ok(false);
    };
    let present = login_present(&key, &expected)?;
    if let Some(enable) = change {
        let name = wide(OsStr::new(NAME));
        let code = if enable && !present {
            unsafe {
                RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    expected.as_ptr().cast(),
                    (expected.len() * 2) as u32,
                )
            }
        } else if !enable && present {
            unsafe { RegDeleteValueW(key.0, name.as_ptr()) }
        } else {
            0
        };
        if code != 0 {
            return Err(win_error(code));
        }
    }
    login_present(&key, &expected)
}
pub(super) fn execute(command: InstallerCommand) -> Result<Registration> {
    match command {
        InstallerCommand::Install | InstallerCommand::Repair | InstallerCommand::Uninstall => {
            mutate(command)?
        }
        InstallerCommand::LoginEnable => {
            login(Some(true))?;
        }
        InstallerCommand::LoginDisable => {
            login(Some(false))?;
        }
        InstallerCommand::OpenApproval => {
            return Err(Error::new(
                ErrorCode::AuthorizationDenied,
                "Windows has no service approval settings page. Use service install or repair and approve the native UAC prompt.",
            ));
        }
        InstallerCommand::Status => {}
    }
    let manager = manager(false)?;
    let service = open(
        &manager,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
    )?;
    if let Some(service) = &service {
        owned(service, &crate::worker::installed_worker()?)?;
        service.query_status().map_err(scm_error)?;
    }
    Ok(Registration {
        registered: service.is_some(),
        approval_required: false,
        login_registered: login(None)?,
    })
}
