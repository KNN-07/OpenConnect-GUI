//! Single-owner native authentication. Only a duplicated command endpoint crosses threads.
use crate::{Engine, abi};
use ocvpn_model::{
    AuthChoice, AuthField, AuthFieldKind, AuthHandoff, AuthPrompt, AuthReply, CertificateDecision,
    CertificatePin, CertificatePrompt, Error, ErrorCode, Profile, Result, TokenMode, TunnelOptions,
};
use ocvpn_model::{
    BrowserMode, BrowserPhase, BrowserReply, BrowserRequest, BrowserTlsPolicy, MAX_BROWSER_BYTES,
    NativeBrowserKind, SecretText, https_origin,
};
use std::{
    collections::{BTreeMap, HashSet},
    ffi::{c_char, c_int, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub trait TokenCallbacks: Send + Sync {
    fn lock(&self) -> Result<Option<Zeroizing<String>>>;
    fn unlock(&self, token: Option<&str>) -> Result<()>;
}
#[derive(Default)]
pub struct AuthSecrets {
    pub password: Option<Zeroizing<String>>,
    pub key_passphrase: Option<Zeroizing<String>>,
    pub secondary_key_passphrase: Option<Zeroizing<String>>,
    pub token_seed: Option<Zeroizing<String>>,
    pub proxy_credentials: Option<Zeroizing<String>>,
    pub token_callbacks: Option<Arc<dyn TokenCallbacks>>,
}
pub enum AuthEvent {
    Prompt(AuthPrompt),
    Certificate(CertificatePrompt),
    Browser(BrowserRequest),
    BrowserFinished(Uuid),
    Authenticated(AuthHandoff),
    Failed(Error),
    Cancelled,
}
enum Response {
    Form(AuthReply),
    Certificate(Uuid, CertificateDecision),
    Browser(Uuid, BrowserReply),
    Cancel,
}
enum Pending {
    Form(AuthPrompt),
    Certificate(Uuid),
    Browser(Uuid, url::Url, NativeBrowserKind),
}
struct Shared {
    native: Arc<abi::OpenConnect>,
    cancelled: AtomicBool,
    command: Mutex<Option<isize>>,
    pending: Mutex<Option<Pending>>,
}
impl Drop for Shared {
    fn drop(&mut self) {
        if let Some(handle) = self
            .command
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            unsafe {
                self.native.ocgui_close_cmd_handle(handle);
            }
        }
    }
}
#[derive(Clone)]
pub struct AuthControl {
    attempt_id: Uuid,
    shared: Arc<Shared>,
    responses: SyncSender<Response>,
}
impl AuthControl {
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    fn send_response(&self, response: Response) -> Result<()> {
        self.responses
            .try_send(response)
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    Error::new(ErrorCode::Busy, "Authentication response queue is full")
                }
                TrySendError::Disconnected(_) => stale(),
            })
    }
    pub fn browser_reply(&self, transaction_id: Uuid, reply: BrowserReply) -> Result<()> {
        let pending = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        let Some(Pending::Browser(id, origin, kind)) = pending.as_ref() else {
            return Err(stale());
        };
        if *id != transaction_id {
            return Err(stale());
        }
        match &reply {
            BrowserReply::Page(page) if *kind == NativeBrowserKind::Webview => {
                page.validate(origin)?
            }
            BrowserReply::Opened if *kind == NativeBrowserKind::External => {}
            BrowserReply::Cancel | BrowserReply::Failed(_) => {}
            _ => return Err(Error::invalid("Unexpected native browser response kind")),
        }
        self.send_response(Response::Browser(transaction_id, reply))
    }
    pub fn reply(&self, reply: AuthReply) -> Result<()> {
        let mut pending = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        match pending.as_ref() {
            Some(Pending::Form(prompt)) => prompt.validate_reply(&reply)?,
            _ => return Err(stale()),
        }
        self.send_response(Response::Form(reply))?;
        *pending = None;
        Ok(())
    }
    pub fn certificate_reply(&self, prompt_id: Uuid, decision: CertificateDecision) -> Result<()> {
        let mut pending = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        if !matches!(pending.as_ref(), Some(Pending::Certificate(id)) if *id == prompt_id) {
            return Err(stale());
        }
        self.send_response(Response::Certificate(prompt_id, decision))?;
        *pending = None;
        Ok(())
    }
    pub fn cancel(&self) {
        if !self.shared.cancelled.swap(true, Ordering::AcqRel) {
            let _ = self.responses.try_send(Response::Cancel);
            if let Some(handle) = *self
                .shared
                .command
                .lock()
                .unwrap_or_else(|e| e.into_inner())
            {
                unsafe {
                    self.shared.native.ocgui_send_cmd(handle, b'x');
                }
            }
        }
        *self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}
pub struct AuthTask {
    events: Receiver<AuthEvent>,
    control: AuthControl,
}
impl AuthTask {
    pub fn attempt_id(&self) -> Uuid {
        self.control.attempt_id
    }
    pub fn control(&self) -> AuthControl {
        self.control.clone()
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<AuthEvent>> {
        match self.events.recv_timeout(timeout) {
            Ok(event) => Ok(Some(event)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(Error::new(
                ErrorCode::RuntimeFailure,
                "Authentication worker has finished",
            )),
        }
    }
}
impl Drop for AuthTask {
    fn drop(&mut self) {
        self.control.cancel();
    }
}
impl Engine {
    pub fn authenticate(
        &self,
        attempt_id: Uuid,
        profile: Profile,
        pins: Vec<CertificatePin>,
        secrets: AuthSecrets,
    ) -> Result<AuthTask> {
        profile.validate_for_connect(&self.capabilities.protocols)?;
        if attempt_id.is_nil() {
            return Err(Error::invalid("Authentication attempt ID is required"));
        }
        let pins = pins
            .into_iter()
            .map(|p| CertificatePin::new(&p.host, p.port, p.fingerprint))
            .collect::<Result<Vec<_>>>()?;
        let shared = Arc::new(Shared {
            native: self.native.clone(),
            cancelled: AtomicBool::new(false),
            command: Mutex::new(None),
            pending: Mutex::new(None),
        });
        let (tx, events) = mpsc::channel();
        let (responses, rx) = mpsc::sync_channel(8);
        let control = AuthControl {
            attempt_id,
            shared: shared.clone(),
            responses,
        };
        let engine = self.clone();
        std::thread::Builder::new()
            .name("ocvpn-auth".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut worker = Box::new(Worker {
                        progress: abi::ocgui_progress_context {
                            context: ptr::null_mut(),
                            callback: None,
                        },
                        native: engine.native.clone(),
                        vpn: ptr::null_mut(),
                        attempt_id,
                        profile,
                        pins,
                        accepted: Vec::new(),
                        secrets,
                        shared: shared.clone(),
                        events: tx.clone(),
                        responses: rx,
                        failure: None,
                        password_used: false,
                        group_selected: None,
                        empty_forms: 0,
                        gp_embedded_phases: 0,
                    });
                    worker.run(&engine)
                }))
                .unwrap_or_else(|_| {
                    Err(Error::new(
                        ErrorCode::RuntimeFailure,
                        "Authentication worker panicked",
                    ))
                });
                *shared.pending.lock().unwrap_or_else(|e| e.into_inner()) = None;
                // Stop cancellation writes before native teardown's duplicated read end disappears.
                if let Some(handle) = shared
                    .command
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    unsafe {
                        shared.native.ocgui_close_cmd_handle(handle);
                    }
                }
                let event = if shared.cancelled.load(Ordering::Acquire) {
                    AuthEvent::Cancelled
                } else {
                    match result {
                        Ok(h) => AuthEvent::Authenticated(h),
                        Err(e) if e.code == ErrorCode::Cancelled => AuthEvent::Cancelled,
                        Err(e) => AuthEvent::Failed(e),
                    }
                };
                let _ = tx.send(event);
            })
            .map_err(|_| {
                Error::new(
                    ErrorCode::RuntimeFailure,
                    "Cannot start authentication worker",
                )
            })?;
        Ok(AuthTask { events, control })
    }
}
#[repr(C)]
struct Worker {
    // C progress bridge requires this prefix. Raw native messages are intentionally discarded.
    progress: abi::ocgui_progress_context,
    native: Arc<abi::OpenConnect>,
    vpn: *mut abi::openconnect_info,
    attempt_id: Uuid,
    profile: Profile,
    pins: Vec<CertificatePin>,
    accepted: Vec<CertificatePin>,
    secrets: AuthSecrets,
    shared: Arc<Shared>,
    events: Sender<AuthEvent>,
    responses: Receiver<Response>,
    failure: Option<Error>,
    password_used: bool,
    group_selected: Option<String>,
    empty_forms: usize,
    gp_embedded_phases: u8,
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Serializes against cancel(): no command can target a recycled descriptor.
        if let Some(handle) = self
            .shared
            .command
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            unsafe {
                self.native.ocgui_close_cmd_handle(handle);
            }
        }
        if !self.vpn.is_null() {
            unsafe {
                self.native.openconnect_vpninfo_free(self.vpn);
            }
        }
    }
}
fn cancelled() -> Error {
    Error::new(ErrorCode::Cancelled, "Authentication cancelled")
}
fn stale() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "Authentication prompt is no longer current",
    )
}
fn check(code: c_int, operation: &str) -> Result<()> {
    if code < 0 {
        Err(Error::new(
            ErrorCode::RuntimeFailure,
            format!("OpenConnect could not {operation}"),
        ))
    } else {
        Ok(())
    }
}
fn cstring(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > 65536 || value.contains('\0') {
        return Err(Error::invalid("Native input is too long or contains a NUL"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    Ok(bytes)
}
unsafe fn text(p: *const c_char) -> Result<String> {
    unsafe { text_bounded(p, 65536) }
}
unsafe fn text_bounded(p: *const c_char, limit: usize) -> Result<String> {
    if p.is_null() {
        return Err(Error::new(
            ErrorCode::ProtocolViolation,
            "Missing native authentication data",
        ));
    }
    for length in 0..=limit {
        if unsafe { *p.add(length) } == 0 {
            let bytes = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), length) };
            return std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
                Error::new(
                    ErrorCode::ProtocolViolation,
                    "Native authentication data is not UTF-8",
                )
            });
        }
    }
    Err(Error::new(
        ErrorCode::ProtocolViolation,
        "Native authentication data exceeds its size limit",
    ))
}
unsafe fn optional_text(p: *const c_char) -> Result<Option<String>> {
    if p.is_null() {
        Ok(None)
    } else {
        unsafe { text(p).map(Some) }
    }
}
fn set_string(
    native: &abi::OpenConnect,
    vpn: *mut abi::openconnect_info,
    setter: unsafe extern "C" fn(*mut abi::openconnect_info, *const c_char) -> c_int,
    value: &str,
    operation: &str,
) -> Result<()> {
    let value = cstring(value)?;
    let _ = native;
    unsafe { check(setter(vpn, value.as_ptr().cast()), operation) }
}
struct SecretPart(Zeroizing<String>);
impl<'de> serde::Deserialize<'de> for SecretPart {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(deserializer).map(|s| Self(Zeroizing::new(s)))
    }
}
impl Worker {
    fn run(&mut self, engine: &Engine) -> Result<AuthHandoff> {
        let context = self as *mut Self as *mut c_void;
        unsafe {
            self.vpn = self.native.openconnect_vpninfo_new(
                c"OpenConnect GUI".as_ptr(),
                None,
                None,
                Some(form_callback),
                Some(self.native.ocgui_progress_bridge),
                context,
            );
            if self.vpn.is_null() {
                return Err(Error::new(
                    ErrorCode::EngineUnavailable,
                    "Cannot allocate OpenConnect session",
                ));
            }
            self.native
                .ocgui_set_peer_policy(self.vpn, Some(certificate_callback), context);
            self.native
                .openconnect_set_webview_callback(self.vpn, Some(webview_callback));
            self.native.openconnect_set_external_browser_callback(
                self.vpn,
                Some(external_browser_callback),
            );
            self.native.openconnect_setup_cmd_pipe(self.vpn);
            let handle = self.native.ocgui_duplicate_cmd_handle(self.vpn);
            if handle == -1 {
                return Err(Error::new(
                    ErrorCode::RuntimeFailure,
                    "Cannot create native cancellation endpoint",
                ));
            }
            *self
                .shared
                .command
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(handle);
        }
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        self.configure(context)?;
        let obtain = self.native.openconnect_obtain_cookie;
        let code = unsafe { obtain(self.vpn) };
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        if code != 0 {
            return Err(Error::new(
                ErrorCode::AuthenticationRejected,
                "OpenConnect authentication failed; verify credentials, server policy and connectivity",
            ));
        }
        let handoff = unsafe { self.handoff()? };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::new(ErrorCode::RuntimeFailure, "System clock is invalid"))?
            .as_secs() as i64;
        handoff.validate(&engine.capabilities.protocols, now)?;
        Ok(handoff)
    }
    fn configure(&mut self, context: *mut c_void) -> Result<()> {
        let n = &*self.native;
        let v = self.vpn;
        let p = &self.profile;
        set_string(
            n,
            v,
            n.openconnect_set_protocol,
            &p.protocol,
            "select protocol",
        )?;
        let mut server = p.server.clone();
        if p.protocol == "gp" && server.path() == "/" {
            server.set_path(if p.direct_gateway {
                "/gateway"
            } else {
                "/portal"
            });
        }
        set_string(
            n,
            v,
            n.openconnect_parse_url,
            server.as_str(),
            "parse server URL",
        )?;
        let host = server
            .host()
            .ok_or_else(|| Error::invalid("VPN server host is required"))?
            .to_string();
        let strict = self.pins.iter().any(|pin| {
            pin.host == host && pin.port == server.port_or_known_default().unwrap_or(443)
        });
        unsafe {
            n.openconnect_set_system_trust(v, if strict { 0 } else { 1 });
        }
        if !strict {
            if let Some(ca) = &p.ca_file {
                set_string(n, v, n.openconnect_set_cafile, ca, "configure CA file")?;
            }
        }
        for (cert, key, setter) in [
            (
                &p.client_certificate,
                &p.client_key,
                n.openconnect_set_client_cert,
            ),
            (
                &p.secondary_certificate,
                &p.secondary_key,
                n.openconnect_set_mca_cert,
            ),
        ] {
            if key.is_some() && cert.is_none() {
                return Err(Error::invalid("A private key requires a certificate"));
            }
            if let Some(cert) = cert {
                if [Some(cert), key.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|s| s.starts_with("pkcs11:"))
                    && unsafe { n.openconnect_has_pkcs11_support() } == 0
                {
                    return Err(Error::new(
                        ErrorCode::UnsupportedAuthentication,
                        "This native build lacks PKCS#11 support",
                    ));
                }
                let cert = cstring(cert)?;
                let key = key.as_deref().map(cstring).transpose()?;
                unsafe {
                    check(
                        setter(
                            v,
                            cert.as_ptr().cast(),
                            key.as_ref().map_or(ptr::null(), |k| k.as_ptr().cast()),
                        ),
                        "configure client certificate",
                    )?;
                }
            }
        }
        for (value, setter, name) in [
            (&p.user_agent, n.openconnect_set_useragent, "set user agent"),
            (
                &p.reported_os,
                n.openconnect_set_reported_os,
                "set reported OS",
            ),
            (&p.sni, n.openconnect_set_sni, "set SNI"),
        ] {
            if let Some(value) = value {
                set_string(n, v, setter, value, name)?;
            }
        }
        if p.protocol == "gp" {
            unsafe {
                check(
                    n.ocgui_set_gp_browser_mode(
                        v,
                        i32::from(p.browser_mode != BrowserMode::Embedded),
                    ),
                    "configure GP browser negotiation",
                )?;
            }
        }
        for (value, setter) in [
            (&self.secrets.key_passphrase, n.openconnect_set_key_password),
            (
                &self.secrets.secondary_key_passphrase,
                n.openconnect_set_mca_key_password,
            ),
        ] {
            if let Some(value) = value {
                set_string(n, v, setter, value, "set key passphrase")?;
            }
        }
        if let Some(proxy) = &p.proxy {
            let mut value = Zeroizing::new(proxy.as_str().to_owned());
            if let Some(credentials) = &self.secrets.proxy_credentials {
                let [user, password]: [SecretPart; 2] = serde_json::from_str(credentials)
                    .map_err(|_| Error::invalid("Invalid stored proxy credentials"))?;
                for part in [&user.0, &password.0] {
                    if part.contains(['@', '/', '?', '#', '\\'])
                        || part.chars().any(char::is_control)
                    {
                        return Err(Error::invalid("Invalid encoded proxy credentials"));
                    }
                }
                let position = value
                    .find("://")
                    .ok_or_else(|| Error::invalid("Invalid proxy URL"))?
                    + 3;
                value.insert_str(position, "@");
                value.insert_str(position, &password.0);
                value.insert_str(position, ":");
                value.insert_str(position, &user.0);
            }
            set_string(
                n,
                v,
                n.openconnect_set_http_proxy,
                &value,
                "configure proxy",
            )?;
        } else if self.secrets.proxy_credentials.is_some() {
            return Err(Error::invalid("Proxy credentials require a proxy endpoint"));
        }
        unsafe {
            if let Some(mtu) = p.mtu {
                n.openconnect_set_reqmtu(v, mtu.into());
            }
            if p.disable_dtls {
                check(n.openconnect_disable_dtls(v), "disable DTLS")?;
            }
            if p.disable_ipv6 {
                check(n.openconnect_disable_ipv6(v), "disable IPv6")?;
            }
            let mode = match p.token_mode {
                TokenMode::None => 0,
                TokenMode::Stoken => 1,
                TokenMode::Totp => 2,
                TokenMode::Hotp => 3,
                TokenMode::Yubioath => 4,
                TokenMode::Oidc => 5,
            };
            if p.token_mode == TokenMode::Oidc
                && self.secrets.token_seed.as_ref().is_none_or(|value| {
                    value.is_empty() || value.starts_with('@') || value.starts_with('/')
                })
            {
                return Err(Error::new(
                    ErrorCode::AuthenticationRequired,
                    "OIDC requires an inline bearer token supplied privately, not a file reference",
                ));
            }
            let supported = match p.token_mode {
                TokenMode::Stoken => n.openconnect_has_stoken_support() > 0,
                TokenMode::Totp => n.openconnect_has_oath_support() > 0,
                TokenMode::Hotp => n.openconnect_has_oath_support() >= 2,
                TokenMode::Yubioath => n.openconnect_has_yubioath_support() > 0,
                _ => true,
            };
            if !supported {
                return Err(Error::new(
                    ErrorCode::UnsupportedAuthentication,
                    "The selected token mode is unavailable in this native build",
                ));
            }
            if p.token_mode == TokenMode::Hotp {
                if self.secrets.token_callbacks.is_none() {
                    return Err(Error::new(
                        ErrorCode::KeyringUnavailable,
                        "HOTP requires locked counter storage",
                    ));
                }
                check(
                    n.openconnect_set_token_callbacks(
                        v,
                        context,
                        Some(token_lock),
                        Some(token_unlock),
                    ),
                    "configure token storage",
                )?;
            }
            if mode != 0 {
                let seed = self
                    .secrets
                    .token_seed
                    .as_deref()
                    .map(|s| cstring(s))
                    .transpose()?;
                check(
                    n.openconnect_set_token_mode(
                        v,
                        mode,
                        seed.as_ref().map_or(ptr::null(), |s| s.as_ptr().cast()),
                    ),
                    "configure token",
                )?;
            }
        }
        Ok(())
    }
    fn wait(&self) -> Result<Response> {
        self.wait_for(Duration::from_secs(300))
    }
    fn wait_for(&self, timeout: Duration) -> Result<Response> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.shared.cancelled.load(Ordering::Acquire) {
                return Err(cancelled());
            }
            match self
                .responses
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            {
                Ok(Response::Cancel) => return Err(cancelled()),
                Ok(reply) => {
                    if self.shared.cancelled.load(Ordering::Acquire) {
                        return Err(cancelled());
                    }
                    if let Response::Browser(id, _) = &reply {
                        if !matches!(*self.shared.pending.lock().unwrap_or_else(|error| error.into_inner()), Some(Pending::Browser(current, _, _)) if current == *id)
                        {
                            continue;
                        }
                    }
                    return Ok(reply);
                }
                Err(_) => {
                    return Err(Error::new(
                        ErrorCode::AuthenticationRequired,
                        "Authentication interaction expired or its owner closed",
                    ));
                }
            }
        }
    }
    unsafe fn browser(&mut self, uri: *const c_char, kind: NativeBrowserKind) -> Result<c_int> {
        if self.failure.is_some() {
            return Err(Error::new(
                ErrorCode::AuthenticationRejected,
                "A previous authentication callback failed",
            ));
        }
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        let mut mode = self.profile.browser_mode;
        let mut external_allowed = None;
        let phase = if self.profile.protocol == "gp" {
            if matches!(
                self.profile.reported_os.as_deref(),
                Some("apple-ios" | "android")
            ) {
                if mode == BrowserMode::System {
                    return Err(Error::new(
                        ErrorCode::UnsupportedAuthentication,
                        "External GP browser negotiation has no documented mapping for this reported OS; use embedded/manual mode or a desktop reported OS",
                    ));
                }
                if mode == BrowserMode::Auto {
                    mode = BrowserMode::Embedded;
                }
            }
            let phase = unsafe { self.native.ocgui_gp_auth_phase(self.vpn) };
            let (phase, bit) = match phase {
                1 => (BrowserPhase::Portal, 1),
                2 => (BrowserPhase::Gateway, 2),
                _ => {
                    return Err(Error::new(
                        ErrorCode::ProtocolViolation,
                        "Native GP browser phase is unavailable",
                    ));
                }
            };
            external_allowed = match unsafe { self.native.ocgui_gp_external_allowed(self.vpn) } {
                1 => Some(true),
                0 => Some(false),
                _ => None,
            };
            if mode == BrowserMode::Auto
                && external_allowed == Some(false)
                && self.gp_embedded_phases & bit == 0
            {
                if unsafe { self.native.ocgui_gp_retry_embedded(self.vpn) } != 0 {
                    return Err(Error::new(
                        ErrorCode::UnsupportedAuthentication,
                        "The server cannot retry browser negotiation; reconnect explicitly using embedded authentication",
                    ));
                }
                self.gp_embedded_phases |= bit;
                return Ok(abi::OC_GUI_EAGAIN);
            }
            if mode == BrowserMode::Auto
                && (self.gp_embedded_phases & bit != 0 || external_allowed.is_none())
            {
                mode = BrowserMode::Embedded;
            }
            if mode == BrowserMode::System && external_allowed != Some(true) {
                return Err(Error::new(
                    ErrorCode::UnsupportedAuthentication,
                    "This GP server does not advertise external completion; select embedded or manual authentication",
                ));
            }
            phase
        } else {
            BrowserPhase::Authentication
        };
        if kind == NativeBrowserKind::Webview
            && mode == BrowserMode::System
            && self.profile.protocol != "gp"
        {
            return Err(Error::new(
                ErrorCode::UnsupportedAuthentication,
                "The server requires embedded or manual browser authentication",
            ));
        }
        let transaction_id = Uuid::new_v4();
        let connect_url =
            Zeroizing::new(unsafe { text(self.native.openconnect_get_connect_url(self.vpn))? });
        let expected_origin = https_origin(&connect_url)?;
        let mut pins = self.pins.clone();
        for accepted in &self.accepted {
            if let Some(pin) = pins
                .iter_mut()
                .find(|pin| pin.host == accepted.host && pin.port == accepted.port)
            {
                *pin = accepted.clone();
            } else {
                pins.push(accepted.clone());
            }
        }
        let request = BrowserRequest {
            attempt_id: self.attempt_id,
            transaction_id,
            protocol: self.profile.protocol.clone(),
            expected_origin: expected_origin.clone(),
            phase,
            kind,
            mode,
            uri: SecretText::new(unsafe { text_bounded(uri, MAX_BROWSER_BYTES)? }),
            external_allowed,
            tls: BrowserTlsPolicy {
                ca_file: self.profile.ca_file.clone(),
                pins,
            },
        };
        request.validate()?;
        *self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Pending::Browser(
            transaction_id,
            expected_origin.clone(),
            kind,
        ));
        self.events
            .send(AuthEvent::Browser(request))
            .map_err(|_| cancelled())?;
        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        loop {
            let Response::Browser(id, reply) =
                self.wait_for(deadline.saturating_duration_since(std::time::Instant::now()))?
            else {
                return Err(stale());
            };
            if id != transaction_id {
                continue;
            }
            match reply {
                BrowserReply::Cancel => return Err(cancelled()),
                BrowserReply::Failed(error) => return Err(error),
                BrowserReply::Opened if kind == NativeBrowserKind::External => {
                    *self
                        .shared
                        .pending
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = None;
                    // The native HPKE listener now waits for its own callback.
                    return Ok(0);
                }
                BrowserReply::Page(page) if kind == NativeBrowserKind::Webview => {
                    let result = unsafe {
                        crate::browser::submit_page(&self.native, self.vpn, page, &expected_origin)?
                    };
                    if result == abi::OC_GUI_EAGAIN {
                        continue;
                    }
                    if result != 0 {
                        return Err(Error::new(
                            ErrorCode::AuthenticationRejected,
                            "Native browser completion was rejected",
                        ));
                    }
                    *self
                        .shared
                        .pending
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = None;
                    self.events
                        .send(AuthEvent::BrowserFinished(transaction_id))
                        .map_err(|_| cancelled())?;
                    return Ok(0);
                }
                _ => return Err(Error::invalid("Unexpected browser completion")),
            }
        }
    }
    unsafe fn handoff(&self) -> Result<AuthHandoff> {
        let n = &*self.native;
        let v = self.vpn;
        unsafe {
            let connect_url =
                url::Url::parse(&text(n.openconnect_get_connect_url(v))?).map_err(|_| {
                    Error::new(
                        ErrorCode::ProtocolViolation,
                        "Invalid negotiated connection URL",
                    )
                })?;
            let dns_name = text(n.openconnect_get_dnsname(v))?;
            let peer = text(n.openconnect_get_hostname(v))?;
            let expiry = n.openconnect_get_auth_expiration(v) as i64;
            Ok(AuthHandoff {
                protocol: self.profile.protocol.clone(),
                connect_url,
                dns_name,
                peer_address: peer
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse()
                    .ok(),
                peer_fingerprint: text(n.openconnect_get_peer_cert_hash(v))?,
                cookie: Zeroizing::new(text(n.openconnect_get_cookie(v))?),
                expires_at: (expiry > 0).then_some(expiry),
                proxy_credentials: self
                    .secrets
                    .proxy_credentials
                    .as_ref()
                    .map(|s| Zeroizing::new(s.to_string())),
                tunnel_options: TunnelOptions {
                    proxy: self.profile.proxy.clone(),
                    sni: self.profile.sni.clone(),
                    user_agent: self.profile.user_agent.clone(),
                    reported_os: self.profile.reported_os.clone(),
                    mtu: self.profile.mtu,
                    disable_dtls: self.profile.disable_dtls,
                    disable_ipv6: self.profile.disable_ipv6,
                    reconnect_timeout_secs: self.profile.reconnect_timeout_secs,
                },
            })
        }
    }
}

// Every C entrypoint contains both ordinary errors and panics. None exposes native logs.
unsafe fn callback(context: *mut c_void, f: impl FnOnce(&mut Worker) -> Result<c_int>) -> c_int {
    if context.is_null() {
        return -1;
    }
    let worker = unsafe { &mut *context.cast::<Worker>() };
    match catch_unwind(AssertUnwindSafe(|| f(worker))) {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            if worker.failure.is_none() {
                worker.failure = Some(error);
            }
            -1
        }
        Err(_) => {
            if worker.failure.is_none() {
                worker.failure = Some(Error::new(
                    ErrorCode::RuntimeFailure,
                    "Native authentication callback panicked",
                ));
            }
            -1
        }
    }
}
unsafe extern "C" fn form_callback(context: *mut c_void, form: *mut abi::oc_auth_form) -> c_int {
    unsafe { callback(context, |w| w.form(form)) }
}
unsafe extern "C" fn certificate_callback(context: *mut c_void, reason: *const c_char) -> c_int {
    unsafe { callback(context, |w| w.certificate(reason)) }
}
unsafe extern "C" fn webview_callback(
    _: *mut abi::openconnect_info,
    uri: *const c_char,
    context: *mut c_void,
) -> c_int {
    unsafe {
        callback(context, |worker| {
            worker.browser(uri, NativeBrowserKind::Webview)
        })
    }
}
unsafe extern "C" fn external_browser_callback(
    _: *mut abi::openconnect_info,
    uri: *const c_char,
    context: *mut c_void,
) -> c_int {
    unsafe {
        callback(context, |worker| {
            worker.browser(uri, NativeBrowserKind::External)
        })
    }
}
unsafe extern "C" fn token_lock(context: *mut c_void) -> c_int {
    unsafe {
        callback(context, |w| {
            let callbacks = w.secrets.token_callbacks.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorCode::KeyringUnavailable,
                    "Token storage is unavailable",
                )
            })?;
            if let Some(seed) = callbacks.lock()? {
                if let Err(e) = cstring(&seed).and_then(|s| {
                    check(
                        w.native
                            .openconnect_set_token_mode(w.vpn, 3, s.as_ptr().cast()),
                        "refresh HOTP counter",
                    )
                }) {
                    let _ = callbacks.unlock(None);
                    return Err(e);
                }
            }
            Ok(0)
        })
    }
}
unsafe extern "C" fn token_unlock(context: *mut c_void, token: *const c_char) -> c_int {
    unsafe {
        callback(context, |w| {
            let callbacks = w.secrets.token_callbacks.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorCode::KeyringUnavailable,
                    "Token storage is unavailable",
                )
            })?;
            let token = optional_text(token).map(|s| s.map(Zeroizing::new));
            match token {
                Ok(token) => callbacks.unlock(token.as_ref().map(|s| s.as_str()))?,
                Err(e) => {
                    let _ = callbacks.unlock(None);
                    return Err(e);
                }
            }
            Ok(0)
        })
    }
}
// Native values may repeat (GP gateways can share an address). Public IDs must not.
fn choice_ids(choices: &mut [AuthChoice]) -> Vec<String> {
    let native: Vec<String> = choices.iter().map(|c| c.id.clone()).collect();
    let mut reserved: HashSet<String> = native.iter().cloned().collect();
    for (index, choice) in choices.iter_mut().enumerate() {
        if native.iter().filter(|id| *id == &native[index]).count() == 1 {
            continue;
        }
        let base = format!("{}#{}", native[index], choice.label);
        let mut id = base.clone();
        let mut ordinal = 1;
        while reserved.contains(&id) {
            id = format!("{base}#{ordinal}");
            ordinal += 1;
        }
        reserved.insert(id.clone());
        choice.id = id;
    }
    native
}
fn saved_choice(field: &AuthField, native: &[String], saved: &str) -> Result<String> {
    let mut matches = field
        .choices
        .iter()
        .zip(native)
        .filter(|(choice, value)| value.as_str() == saved || choice.label == saved);
    let first = matches.next().ok_or_else(|| {
        Error::new(
            ErrorCode::AuthenticationRequired,
            "The saved gateway or group is no longer available",
        )
    })?;
    if matches.next().is_some() {
        return Err(Error::new(
            ErrorCode::AuthenticationRequired,
            "The saved gateway or group is ambiguous; select it explicitly",
        ));
    }
    Ok(first.0.id.clone())
}
impl Worker {
    unsafe fn form(&mut self, form: *mut abi::oc_auth_form) -> Result<c_int> {
        if self.failure.is_some() {
            return Err(Error::new(
                ErrorCode::AuthenticationRejected,
                "A previous authentication callback failed",
            ));
        }
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        let form = unsafe { form.as_mut() }.ok_or_else(|| {
            Error::new(
                ErrorCode::ProtocolViolation,
                "Missing native authentication form",
            )
        })?;
        let mut prompt = AuthPrompt {
            prompt_id: Uuid::new_v4(),
            attempt_id: self.attempt_id,
            auth_id: unsafe { text(form.auth_id)? },
            banner: unsafe { optional_text(form.banner)? },
            message: unsafe { optional_text(form.message)? },
            error: unsafe { optional_text(form.error)? },
            fields: Vec::new(),
        };
        if prompt.error.is_some() {
            self.password_used = true;
            self.secrets.password.take();
        }
        let mut options = Vec::new();
        let mut bindings = BTreeMap::new();
        let mut seen = HashSet::new();
        let mut option = form.opts;
        let mut native_generated = false;
        while !option.is_null() {
            if seen.len() >= 256 || !seen.insert(option as usize) {
                return Err(Error::new(
                    ErrorCode::ProtocolViolation,
                    "Authentication form is too large or cyclic",
                ));
            }
            let opt = unsafe { &*option };
            let next = opt.next;
            if opt.flags & 1 == 0 && opt.type_ != 4 {
                if matches!(opt.type_, 6 | 7) {
                    native_generated = true;
                    option = next;
                    continue;
                }
                let kind = match opt.type_ {
                    1 => AuthFieldKind::Text,
                    2 => AuthFieldKind::Password,
                    3 => AuthFieldKind::Select,
                    5 => AuthFieldKind::Token,
                    _ => {
                        return Err(Error::new(
                            ErrorCode::UnsupportedAuthentication,
                            "Unknown native authentication field kind",
                        ));
                    }
                };
                // Token and SSO values are produced by the library after this callback.
                if kind == AuthFieldKind::Token && self.profile.token_mode != TokenMode::None {
                    native_generated = true;
                    option = next;
                    continue;
                }
                let name = unsafe { text(opt.name)? };
                if prompt.fields.iter().any(|f| f.name == name) {
                    return Err(Error::new(
                        ErrorCode::ProtocolViolation,
                        "Duplicate authentication field name",
                    ));
                }
                let mut choices = Vec::new();
                if kind == AuthFieldKind::Select {
                    let select = unsafe { &*option.cast::<abi::oc_form_opt_select>() };
                    if select.nr_choices < 1 || select.nr_choices > 256 || select.choices.is_null()
                    {
                        return Err(Error::new(
                            ErrorCode::ProtocolViolation,
                            "Invalid authentication choices",
                        ));
                    }
                    for i in 0..select.nr_choices as usize {
                        let choice =
                            unsafe { (*select.choices.add(i)).as_ref() }.ok_or_else(|| {
                                Error::new(
                                    ErrorCode::ProtocolViolation,
                                    "Missing authentication choice",
                                )
                            })?;
                        choices.push(AuthChoice {
                            id: unsafe { text(choice.name)? },
                            label: unsafe { optional_text(choice.label)? }.unwrap_or_default(),
                        });
                    }
                    bindings.insert(name.clone(), choice_ids(&mut choices));
                }
                prompt.fields.push(AuthField {
                    name,
                    label: unsafe { optional_text(opt.label)? }.unwrap_or_default(),
                    kind,
                    required: true,
                    numeric: opt.flags & 2 != 0,
                    choices,
                });
                options.push(option);
            }
            option = next;
        }
        let group_index = options.iter().position(|o| *o == form.authgroup_opt.cast());
        // Group changes must precede other answers: the native library rebuilds dependent fields.
        if let Some(index) = group_index {
            let field = &prompt.fields[index];
            let desired = self
                .profile
                .auth_group
                .as_ref()
                .or(self.profile.gateway.as_ref());
            if self.group_selected.is_none() {
                if let Some(desired) = desired {
                    let native = &bindings[&field.name];
                    let id = saved_choice(field, native, desired)?;
                    let selection = field
                        .choices
                        .iter()
                        .position(|c| c.id == id)
                        .ok_or_else(stale)?;
                    let value = cstring(&native[selection])?;
                    unsafe {
                        check(
                            self.native.openconnect_set_option_value(
                                options[index],
                                value.as_ptr().cast(),
                            ),
                            "select authentication group",
                        )?;
                    }
                    form.authgroup_selection = selection as c_int;
                    self.group_selected = Some(id);
                    return Ok(2);
                }
                let group = prompt.fields[index].clone();
                prompt.fields = vec![group];
                options = vec![options[index]];
            }
        }
        let mut automatic = BTreeMap::new();
        for (field, option) in prompt.fields.iter().zip(&options) {
            let lower = field.name.to_ascii_lowercase();
            if field.kind == AuthFieldKind::Text
                && (lower.starts_with("user") || lower.starts_with("uname"))
                && !lower.contains("secondary")
                && unsafe { (**option).flags & 0x8000 == 0 }
            {
                if let Some(username) = &self.profile.username {
                    automatic.insert(field.name.clone(), Zeroizing::new(username.clone()));
                }
            } else if field.kind == AuthFieldKind::Text
                && self.profile.protocol == "array"
                && field.name == "method"
            {
                if let Some(group) = &self.profile.auth_group {
                    automatic.insert(field.name.clone(), Zeroizing::new(group.clone()));
                }
            } else if field.kind == AuthFieldKind::Select {
                let group = *option == form.authgroup_opt.cast();
                let saved = if group {
                    self.group_selected.as_ref()
                } else if lower.contains("gateway")
                    || (self.profile.protocol == "gp" && field.name == "_portal")
                {
                    self.profile.gateway.as_ref()
                } else {
                    None
                };
                if let Some(saved) = saved {
                    let id = if group {
                        field
                            .choices
                            .iter()
                            .find(|c| &c.id == saved)
                            .map(|c| c.id.clone())
                            .ok_or_else(stale)?
                    } else {
                        saved_choice(field, &bindings[&field.name], saved)?
                    };
                    automatic.insert(field.name.clone(), Zeroizing::new(id));
                }
            }
        }
        let mut passwords = prompt
            .fields
            .iter()
            .filter(|f| f.kind == AuthFieldKind::Password);
        if let Some(field) = passwords.next() {
            let initial_password = field.name.eq_ignore_ascii_case("password")
                || field.name.eq_ignore_ascii_case("passwd")
                || (self.profile.protocol == "fortinet"
                    && prompt.auth_id == "_login"
                    && field.name == "credential")
                || (self.profile.protocol == "array"
                    && prompt.auth_id == "form"
                    && field.name == "pwd");
            if !self.password_used
                && passwords.next().is_none()
                && prompt.auth_id != "_challenge"
                && initial_password
            {
                if let Some(password) = &self.secrets.password {
                    automatic.insert(field.name.clone(), Zeroizing::new(password.to_string()));
                }
            }
        }
        let reply = if automatic.len() == prompt.fields.len() {
            if prompt.fields.is_empty() && !native_generated {
                self.empty_forms += 1;
                if self.empty_forms > 2 {
                    return Err(Error::new(
                        ErrorCode::AuthenticationRequired,
                        "Server repeatedly returned an empty authentication form",
                    ));
                }
            } else {
                self.empty_forms = 0;
            }
            AuthReply {
                prompt_id: prompt.prompt_id,
                attempt_id: self.attempt_id,
                answers: Some(automatic),
            }
        } else {
            self.empty_forms = 0;
            // Prefilled values never enter a public DTO; only unresolved fields are presented.
            let complete = prompt.clone();
            prompt.fields.retain(|f| !automatic.contains_key(&f.name));
            *self
                .shared
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(Pending::Form(prompt.clone()));
            self.events
                .send(AuthEvent::Prompt(prompt.clone()))
                .map_err(|_| cancelled())?;
            let Response::Form(mut reply) = self.wait()? else {
                return Err(stale());
            };
            prompt.validate_reply(&reply)?;
            if let Some(answers) = &mut reply.answers {
                answers.extend(automatic);
            }
            prompt = complete;
            reply
        };
        prompt.validate_reply(&reply)?;
        let Some(answers) = reply.answers else {
            return Err(cancelled());
        };
        for (field, option) in prompt.fields.iter().zip(options) {
            let answer = answers
                .get(&field.name)
                .ok_or_else(|| Error::invalid("Missing authentication answer"))?;
            let selection = if field.kind == AuthFieldKind::Select {
                Some(
                    field
                        .choices
                        .iter()
                        .position(|c| c.id == answer.as_str())
                        .ok_or_else(stale)?,
                )
            } else {
                None
            };
            let value = cstring(if let Some(index) = selection {
                &bindings[&field.name][index]
            } else {
                answer
            })?;
            unsafe {
                check(
                    self.native
                        .openconnect_set_option_value(option, value.as_ptr().cast()),
                    "apply authentication answer",
                )?;
            }
            if option == form.authgroup_opt.cast() {
                form.authgroup_selection = selection.ok_or_else(stale)? as c_int;
            }
            if option == form.authgroup_opt.cast()
                && self.group_selected.as_deref() != Some(answer.as_str())
            {
                self.group_selected = Some(answer.to_string());
                return Ok(2);
            }
            if field.kind == AuthFieldKind::Password {
                self.password_used = true;
                self.secrets.password.take();
            }
        }
        Ok(0)
    }
    unsafe fn certificate(&mut self, reason: *const c_char) -> Result<c_int> {
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        let host = unsafe { text(self.native.openconnect_get_dnsname(self.vpn))? };
        let port =
            u16::try_from(unsafe { self.native.openconnect_get_port(self.vpn) }).map_err(|_| {
                Error::new(
                    ErrorCode::CertificateRejected,
                    "Invalid certificate peer port",
                )
            })?;
        let fingerprint = unsafe { text(self.native.openconnect_get_peer_cert_hash(self.vpn))? };
        let scope = CertificatePin::new(&host, port, fingerprint)?;
        for pin in self
            .accepted
            .iter()
            .filter(|p| p.host == scope.host && p.port == scope.port)
        {
            let hash = cstring(&pin.fingerprint)?;
            if unsafe {
                self.native
                    .openconnect_check_peer_cert_hash(self.vpn, hash.as_ptr().cast())
            } == 0
            {
                return Ok(0);
            }
        }
        let mut changed_pin = false;
        for pin in self
            .pins
            .iter()
            .filter(|p| p.host == scope.host && p.port == scope.port)
        {
            let hash = cstring(&pin.fingerprint)?;
            if unsafe {
                self.native
                    .openconnect_check_peer_cert_hash(self.vpn, hash.as_ptr().cast())
            } == 0
            {
                return Ok(0);
            }
            changed_pin = true;
        }
        if reason.is_null() && !changed_pin {
            return Ok(0);
        }
        let details_ptr = unsafe { self.native.openconnect_get_peer_cert_details(self.vpn) };
        let details = unsafe { optional_text(details_ptr) };
        if !details_ptr.is_null() {
            unsafe {
                self.native
                    .openconnect_free_cert_info(self.vpn, details_ptr.cast());
            }
        }
        let prompt = CertificatePrompt {
            prompt_id: Uuid::new_v4(),
            attempt_id: self.attempt_id,
            host: scope.host.clone(),
            port,
            fingerprint: scope.fingerprint.clone(),
            changed_pin,
            reason: if changed_pin {
                "The certificate differs from the saved host pin".into()
            } else {
                unsafe { optional_text(reason)? }
                    .unwrap_or_else(|| "Certificate approval required".into())
            },
            details: details?.unwrap_or_default(),
        };
        let prompt_id = prompt.prompt_id;
        *self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Pending::Certificate(prompt_id));
        self.events
            .send(AuthEvent::Certificate(prompt))
            .map_err(|_| cancelled())?;
        match self.wait()? {
            Response::Certificate(id, decision) if id == prompt_id => match decision {
                CertificateDecision::Reject => Err(Error::new(
                    ErrorCode::CertificateRejected,
                    "Peer certificate was rejected",
                )),
                CertificateDecision::AcceptAttempt | CertificateDecision::Pin => {
                    if self.accepted.len() >= 256 {
                        return Err(Error::new(
                            ErrorCode::CertificateRejected,
                            "Too many distinct authentication certificate peers",
                        ));
                    }
                    self.accepted.push(scope);
                    Ok(0)
                }
            },
            _ => Err(stale()),
        }
    }
}
