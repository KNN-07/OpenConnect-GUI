//! SMAppService owns launch registration; never install a second launchctl job.
use std::{path::Path, sync::mpsc, time::Duration};

use block2::RcBlock;
use objc2::rc::{Retained, autoreleasepool};
use objc2_foundation::{NSBundle, NSError, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use ocvpn_model::{Error, ErrorCode, Result};

use super::{InstallerCommand, Registration, denied, unavailable};

const BUNDLE: &str = "/Applications/OpenConnect GUI.app";
const DAEMON_PLIST: &str = "org.openconnectgui.daemon.plist";
const LOGIN_PLIST: &str = "org.openconnectgui.autoconnect.plist";
const UNREGISTER_TIMEOUT: Duration = Duration::from_secs(45);

struct Services {
    daemon: Retained<SMAppService>,
    login: Retained<SMAppService>,
}

impl Services {
    fn installed() -> Result<Self> {
        // ServiceManagement resolves names against the calling process's main
        // bundle. A bundle constructed from a path would not change that context.
        let bundle = NSBundle::mainBundle();
        if bundle.bundlePath().to_string() != BUNDLE
            || bundle
                .bundleIdentifier()
                .is_none_or(|id| id.to_string() != "org.openconnectgui.app")
        {
            return Err(denied());
        }
        let installer = bundle
            .pathForAuxiliaryExecutable(&NSString::from_str("ocvpn-installer"))
            .ok_or_else(unavailable)?;
        if Path::new(&installer.to_string()) != super::installer_path()? {
            return Err(denied());
        }
        crate::trust::installed_file(&super::installer_path()?)?;
        crate::trust::installed_file(&crate::worker::installed_worker()?)?;
        super::cli_path()?;
        for resource in [
            "Contents/Info.plist".to_owned(),
            format!("Contents/Library/LaunchDaemons/{DAEMON_PLIST}"),
            format!("Contents/Library/LaunchAgents/{LOGIN_PLIST}"),
        ] {
            ocvpn_engine::validate_installed_file(&Path::new(BUNDLE).join(resource))?;
        }
        // All names are fixed package resources, not frontend-supplied paths.
        Ok(unsafe {
            Self {
                daemon: SMAppService::daemonServiceWithPlistName(&NSString::from_str(DAEMON_PLIST)),
                login: SMAppService::agentServiceWithPlistName(&NSString::from_str(LOGIN_PLIST)),
            }
        })
    }

    fn registration(&self) -> Result<Registration> {
        let daemon = status(&self.daemon)?;
        let login = status(&self.login)?;
        Ok(Registration {
            registered: registered(daemon),
            approval_required: daemon == SMAppServiceStatus::RequiresApproval
                || login == SMAppServiceStatus::RequiresApproval,
            login_registered: registered(login),
        })
    }
}

fn status(service: &SMAppService) -> Result<SMAppServiceStatus> {
    let status = unsafe { service.status() };
    match status {
        SMAppServiceStatus::NotRegistered
        | SMAppServiceStatus::Enabled
        | SMAppServiceStatus::RequiresApproval => Ok(status),
        // NotFound means a missing or invalid bundled resource, not success.
        _ => Err(unavailable()),
    }
}

fn registered(status: SMAppServiceStatus) -> bool {
    matches!(
        status,
        SMAppServiceStatus::Enabled | SMAppServiceStatus::RequiresApproval
    )
}

fn register(service: &SMAppService) -> Result<()> {
    if registered(status(service)?) {
        // Approval is an explicit user action, never an automatic retry loop.
        return Ok(());
    }
    let result = unsafe { service.registerAndReturnError() };
    // A successful registration may still need approval. A competing invocation
    // may also have registered it while the call was in progress.
    if registered(status(service)?) {
        return Ok(());
    }
    result.map_err(|_| registration_error())?;
    Err(unavailable())
}

fn registration_error() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "macOS did not register the bundled helper. Check Login Items approval and the package's code signature/notarization, then retry.",
    )
}

fn unregister(service: &SMAppService) -> Result<()> {
    if status(service)? == SMAppServiceStatus::NotRegistered {
        return Ok(());
    }
    let (send, receive) = mpsc::sync_channel(1);
    // The system copies this heap block and invokes it on a libdispatch queue.
    // Capture only a thread-safe sender, never an NSError or stack reference.
    let completion = RcBlock::new(move |error: *mut NSError| {
        let _ = send.try_send(error.is_null());
    });
    unsafe { service.unregisterWithCompletionHandler(&completion) };
    if !receive.recv_timeout(UNREGISTER_TIMEOUT).map_err(|_| Error::new(
        ErrorCode::ServiceUnavailable,
        "macOS has not completed helper removal. Do not remove the application bundle; retry after the system finishes unregistering it.",
    ))? {
        return Err(registration_error());
    }
    if status(service)? != SMAppServiceStatus::NotRegistered {
        return Err(unavailable());
    }
    Ok(())
}

// ABI declarations follow Apple's Security/Authorization.h. Authorization
// external forms are credentials: never log, persist, or put them in argv.
type AuthorizationRef = *const std::ffi::c_void;
#[repr(C)]
struct AuthorizationItem {
    name: *const std::ffi::c_char,
    value_length: usize,
    value: *mut std::ffi::c_void,
    flags: u32,
}
#[repr(C)]
struct AuthorizationRights {
    count: u32,
    items: *mut AuthorizationItem,
}
#[repr(C)]
struct ExternalForm {
    bytes: [u8; 32],
}
impl Drop for ExternalForm {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationRights,
        environment: *const AuthorizationRights,
        flags: u32,
        authorization: *mut AuthorizationRef,
    ) -> i32;
    fn AuthorizationFree(authorization: AuthorizationRef, flags: u32) -> i32;
    fn AuthorizationCopyRights(
        authorization: AuthorizationRef,
        rights: *const AuthorizationRights,
        environment: *const AuthorizationRights,
        flags: u32,
        result: *mut *mut AuthorizationRights,
    ) -> i32;
    fn AuthorizationMakeExternalForm(
        authorization: AuthorizationRef,
        external: *mut ExternalForm,
    ) -> i32;
    fn AuthorizationCreateFromExternalForm(
        external: *const ExternalForm,
        authorization: *mut AuthorizationRef,
    ) -> i32;
}

struct Authorization {
    raw: AuthorizationRef,
    destroy_rights: bool,
}
impl Drop for Authorization {
    fn drop(&mut self) {
        unsafe {
            AuthorizationFree(self.raw, if self.destroy_rights { 1 << 3 } else { 0 });
        }
    }
}

fn admin_right() -> AuthorizationItem {
    AuthorizationItem {
        name: c"system.privilege.admin".as_ptr(),
        value_length: 0,
        value: std::ptr::null_mut(),
        flags: 0,
    }
}

fn consent() -> Result<(Authorization, ocvpn_model::SecretText)> {
    use base64::Engine;
    let mut item = admin_right();
    let rights = AuthorizationRights {
        count: 1,
        items: &mut item,
    };
    let mut raw = std::ptr::null();
    // InteractionAllowed | ExtendRights. The native OS dialog, not our UI,
    // collects the administrator credentials.
    if unsafe { AuthorizationCreate(&rights, std::ptr::null(), 3, &mut raw) } != 0 || raw.is_null()
    {
        return Err(denied());
    }
    let authorization = Authorization {
        raw,
        destroy_rights: true,
    };
    let mut external = ExternalForm { bytes: [0; 32] };
    if unsafe { AuthorizationMakeExternalForm(raw, &mut external) } != 0 {
        return Err(denied());
    }
    let token = ocvpn_model::SecretText::new(
        base64::engine::general_purpose::STANDARD.encode(&external.bytes),
    );
    Ok((authorization, token))
}

/// Called inside the root daemon, never the user-consent process. Do not permit
/// Authorization Services to display UI or extend a supplied credential's rights.
pub(crate) fn authorize_quiesce(token: &ocvpn_model::SecretText) -> Result<()> {
    use base64::Engine;
    if token.as_str().len() != 44 {
        return Err(denied());
    }
    let mut external = ExternalForm { bytes: [0; 32] };
    if base64::engine::general_purpose::STANDARD
        .decode_slice(token.as_str(), &mut external.bytes)
        .map_err(|_| denied())?
        != 32
    {
        return Err(denied());
    }
    let mut raw = std::ptr::null();
    if unsafe { AuthorizationCreateFromExternalForm(&external, &mut raw) } != 0 || raw.is_null() {
        return Err(denied());
    }
    let authorization = Authorization {
        raw,
        destroy_rights: false,
    };
    let mut item = admin_right();
    let rights = AuthorizationRights {
        count: 1,
        items: &mut item,
    };
    if unsafe {
        AuthorizationCopyRights(
            authorization.raw,
            &rights,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(denied());
    }
    Ok(())
}

fn quiesce() -> Result<Authorization> {
    use ocvpn_model::ipc::{self, Hello, Method, Payload, Request, Response};
    let (authorization, token) = consent()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| unavailable())?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            // Existing transport checks the protected socket and root peer before
            // any authorization credential is transmitted.
            let mut stream = crate::unix::connect_control().await.map_err(|_| unavailable())?;
            ipc::write_frame(&mut stream, &Hello { version: ipc::VERSION }).await?;
            ipc::read_frame::<_, Hello>(&mut stream).await?.validate()?;
            let request_id = uuid::Uuid::new_v4();
            ipc::write_frame(&mut stream, &Request {
                request_id,
                method: Method::AdminQuiesce { authorization: Some(token) },
            }).await?;
            let response: Response = ipc::read_frame(&mut stream).await?;
            if response.request_id != request_id {
                return Err(unavailable());
            }
            match response.result? {
                Payload::Accepted => Ok(()),
                _ => Err(unavailable()),
            }
        }).await.map_err(|_| Error::new(
            ErrorCode::RecoveryRequired,
            "The daemon has not confirmed safe tunnel shutdown and network recovery. The service registration and application files have been preserved.",
        ))?
    })?;
    Ok(authorization)
}

pub(super) fn execute(command: InstallerCommand) -> Result<Registration> {
    autoreleasepool(|_| {
        let services = Services::installed()?;
        // Login agents and native consent belong to the actual logged-in user.
        // The package installer must invoke this helper in that context, not
        // launch an elevated GUI or register root's auto-connect entry.
        if unsafe { libc::geteuid() } == 0 && !matches!(command, InstallerCommand::Status) {
            return Err(Error::new(
                ErrorCode::AuthorizationDenied,
                "Run service management as the logged-in user. macOS will request administrator approval when needed; do not run the application as root.",
            ));
        }
        match command {
            InstallerCommand::Status => {}
            InstallerCommand::Install => register(&services.daemon)?,
            InstallerCommand::LoginEnable => register(&services.login)?,
            InstallerCommand::LoginDisable => unregister(&services.login)?,
            InstallerCommand::OpenApproval => unsafe {
                SMAppService::openSystemSettingsLoginItems();
            },
            InstallerCommand::Repair | InstallerCommand::Uninstall => {
                // Even an unregistered daemon can have an orphaned journal. Let
                // its privileged startup recovery run; socket absence is never
                // evidence that worker processes or network mutations are gone.
                register(&services.daemon)?;
                if status(&services.daemon)? == SMAppServiceStatus::RequiresApproval {
                    // The caller displays pending approval and asks the user to
                    // retry this command afterwards; this is NOT removal success.
                    return services.registration();
                }
                let _authorization = quiesce()?;
                // ACK means admission is closed, all owned descendants have
                // exited, and recover_all completed without warnings. The daemon
                // remains quiesced even after the IPC client disconnects.
                unregister(&services.daemon)?;
                if matches!(command, InstallerCommand::Repair) {
                    register(&services.daemon)?;
                }
            }
        }
        services.registration()
    })
}
