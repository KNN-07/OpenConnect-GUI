//! Windows owns default-browser dispatch and the user's effective protocol choice.
use ocvpn_model::{Error, ErrorCode, Result};
use std::{
    ptr::{null, null_mut},
    sync::mpsc,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_ASSOCIATION, ERROR_SUCCESS},
    System::{
        Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize},
        Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
            RegCreateKeyExW, RegSetValueExW,
        },
    },
    UI::{
        Shell::{
            ASSOCF_IS_PROTOCOL, ASSOCF_NOTRUNCATE, ASSOCSTR_PROGID, AssocQueryStringW,
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHCNE_ASSOCCHANGED, SHCNF_IDLIST,
            SHChangeNotify, SHELLEXECUTEINFOW, ShellExecuteExW,
        },
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

pub(super) const HANDLER: &str = "OpenConnectGUI.GlobalProtectCallback";
const SCHEME: &str = "globalprotectcallback";
const APP: &str = "OpenConnect GUI";
const CAPABILITIES: &str = r"Software\OpenConnectGUI\Capabilities";
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_WIDE: usize = 32_768;

fn unavailable() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "Windows browser activation or callback registration is unavailable; use manual authentication or embedded mode",
    )
}
fn choice_pending() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "Callback receiver registered, but not selected as the effective handler. In Windows Settings > Apps > Default apps, choose OpenConnect GUI for GLOBALPROTECTCALLBACK, then retry registration. Manual authentication or embedded mode is also available",
    )
}
fn wide(value: &str) -> Result<Vec<u16>> {
    if value.len() >= MAX_WIDE || value.contains('\0') {
        return Err(unavailable());
    }
    let mut value: Vec<u16> = value.encode_utf16().collect();
    value.push(0);
    Ok(value)
}

struct ComApartment;
impl ComApartment {
    fn initialize() -> Result<Self> {
        let status = unsafe {
            CoInitializeEx(
                null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if status < 0 {
            return Err(unavailable());
        }
        Ok(Self)
    }
}
impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn activation(uri: &str) -> Result<mpsc::Receiver<Result<()>>> {
    let uri = wide(uri)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    // A fresh STA avoids inheriting a caller's incompatible COM apartment. A
    // stuck third-party shell extension cannot hold up authentication forever.
    // Windows offers no safe cancellation of ShellExecuteEx; timeout detaches
    // this thread and the broker closes its short-lived bootstrap listener.
    std::thread::Builder::new()
        .name("ocvpn-os-activation".into())
        .spawn(move || {
            let result = (|| {
                let _com = ComApartment::initialize()?;
                let verb = wide("open")?;
                let mut info = SHELLEXECUTEINFOW {
                    cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                    fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
                    lpVerb: verb.as_ptr(),
                    lpFile: uri.as_ptr(),
                    nShow: SW_SHOWNORMAL,
                    ..Default::default()
                };
                // No executable, arguments, environment, or process handle is
                // constructed. The OS resolves the current default association.
                if unsafe { ShellExecuteExW(&mut info) } == 0 {
                    return Err(unavailable());
                }
                Ok(())
            })();
            let _ = sender.send(result);
        })
        .map_err(|_| unavailable())?;
    Ok(receiver)
}

pub(super) async fn launch(uri: &str) -> Result<()> {
    let receiver = activation(uri)?;
    tokio::time::timeout(
        ACTIVATION_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            receiver
                .recv_timeout(ACTIVATION_TIMEOUT)
                .map_err(|_| unavailable())?
        }),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?
}

pub(super) fn association() -> Result<Option<String>> {
    let scheme = wide(SCHEME)?;
    let mut buffer = vec![0u16; MAX_WIDE];
    let mut length = buffer.len() as u32;
    // IS_PROTOCOL expressly maps through current user defaults, including
    // protected UserChoice. Reading HKCU\Software\Classes alone is not enough.
    let status = unsafe {
        AssocQueryStringW(
            ASSOCF_IS_PROTOCOL | ASSOCF_NOTRUNCATE,
            ASSOCSTR_PROGID,
            scheme.as_ptr(),
            null(),
            buffer.as_mut_ptr(),
            &mut length,
        )
    };
    let missing = |code: u32| (0x8007_0000u32 | code) as i32;
    if status == missing(ERROR_NO_ASSOCIATION) || status == missing(ERROR_FILE_NOT_FOUND) {
        return Ok(None);
    }
    if status != 0 || length == 0 || length as usize > buffer.len() {
        return Err(unavailable());
    }
    let used = &buffer[..length as usize];
    let end = used
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(unavailable)?;
    if end == 0 {
        return Ok(None);
    }
    let identifier = String::from_utf16(&used[..end]).map_err(|_| unavailable())?;
    // Keep the effective identifier suitable for nonsecret status display.
    if identifier.chars().any(char::is_control) {
        return Err(unavailable());
    }
    Ok(Some(identifier))
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
fn set_string(path: &str, name: &str, value: &str) -> Result<()> {
    let path = wide(path)?;
    let name = wide(name)?;
    let value = wide(value)?;
    let mut key = null_mut();
    if unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            null(),
            &mut key,
            null_mut(),
        )
    } != ERROR_SUCCESS
    {
        return Err(unavailable());
    }
    let key = Key(key);
    if unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            (value.len() * std::mem::size_of::<u16>()) as u32,
        )
    } != ERROR_SUCCESS
    {
        return Err(unavailable());
    }
    Ok(())
}

pub(super) fn register(replace_existing: bool) -> Result<()> {
    let current = association()?;
    if current
        .as_deref()
        .is_some_and(|id| !id.eq_ignore_ascii_case(HANDLER))
        && !replace_existing
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Another application handles GlobalProtect callbacks; explicitly consent to replacement, or use manual authentication or embedded mode",
        ));
    }
    // Common validation resolves only the protected installed Program Files
    // binary, never PATH, an environment override, or a user-profile executable.
    let cli = super::installed_callback()?;
    let cli = cli.to_str().ok_or_else(unavailable)?;
    if cli.contains(['"', '\r', '\n']) {
        return Err(unavailable());
    }
    let command = format!("\"{cli}\" \"%1\"");
    let progid = format!(r"Software\Classes\{HANDLER}");
    set_string(&progid, "", "OpenConnect GUI GlobalProtect callback")?;
    set_string(&progid, "URL Protocol", "")?;
    // This is a static registration template, not a command we execute. Windows
    // custom-URL dispatch unavoidably places its callback in receiver argv.
    set_string(&format!(r"{progid}\shell\open\command"), "", &command)?;
    set_string(CAPABILITIES, "ApplicationName", APP)?;
    set_string(
        CAPABILITIES,
        "ApplicationDescription",
        "Receive GlobalProtect authentication callbacks for OpenConnect GUI",
    )?;
    set_string(&format!(r"{CAPABILITIES}\UrlAssociations"), SCHEME, HANDLER)?;
    set_string(r"Software\RegisteredApplications", APP, CAPABILITIES)?;
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED as i32, SHCNF_IDLIST, null(), null()) };
    if association()?
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(HANDLER))
    {
        return Ok(());
    }
    // Never forge UserChoice hashes or replace a generic scheme registration.
    // Supported Windows 10/11 UI performs the user's actual default selection.
    if let Ok(receiver) = activation("ms-settings:defaultapps") {
        let _ = receiver.recv_timeout(ACTIVATION_TIMEOUT);
    }
    if association()?
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(HANDLER))
    {
        Ok(())
    } else {
        Err(choice_pending())
    }
}
