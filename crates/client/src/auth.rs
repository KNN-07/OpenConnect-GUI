//! Blocking native preparation and event routing shared by all user interfaces.
use crate::{
    credentials::{self, HotpTransaction, Purpose},
    profiles::ProfileStore,
};
use ocvpn_engine::{
    Engine,
    auth::{AuthSecrets, AuthTask, TokenCallbacks},
};
use ocvpn_model::{
    AuthHandoff, AuthPrompt, AuthReply, BrowserPrompt, CertificateDecision, CertificatePin,
    CertificatePrompt, Error, ErrorCode, Profile, Result, SecretText, TokenMode,
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use ocvpn_engine::auth::AuthEvent as NativeEvent;
pub enum AuthEvent {
    Prompt(AuthPrompt),
    Certificate(CertificatePrompt),
    Browser(BrowserPrompt),
    BrowserFinished(Uuid),
    Authenticated(AuthHandoff),
    Failed(Error),
    Cancelled,
}

#[derive(Default)]
pub struct AuthInputs {
    pub password: Option<Zeroizing<String>>,
    pub key_passphrase: Option<Zeroizing<String>>,
    pub secondary_key_passphrase: Option<Zeroizing<String>>,
    pub token_seed: Option<Zeroizing<String>>,
    pub proxy_credentials: Option<Zeroizing<String>>,
    pub non_interactive: bool,
}

struct HotpStore {
    profile_id: Uuid,
    non_interactive: bool,
    transaction: Mutex<Option<HotpTransaction>>,
}
impl TokenCallbacks for HotpStore {
    fn lock(&self) -> Result<Option<Zeroizing<String>>> {
        let mut slot = self
            .transaction
            .lock()
            .map_err(|_| Error::new(ErrorCode::RuntimeFailure, "Token transaction lock failed"))?;
        if slot.is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "A token generation transaction is already active",
            ));
        }
        let transaction = HotpTransaction::begin(self.profile_id, self.non_interactive)?;
        let seed = transaction.seed()?;
        *slot = Some(transaction);
        Ok(seed)
    }
    fn unlock(&self, new_seed: Option<&str>) -> Result<()> {
        let transaction = self
            .transaction
            .lock()
            .map_err(|_| Error::new(ErrorCode::RuntimeFailure, "Token transaction lock failed"))?
            .take();
        match transaction {
            Some(transaction) => transaction.commit(new_seed),
            None if new_seed.is_none() => Ok(()),
            None => Err(Error::new(
                ErrorCode::Conflict,
                "Token generation has no durable transaction",
            )),
        }
    }
}

#[derive(Clone)]
pub struct AuthControl {
    native: ocvpn_engine::auth::AuthControl,
    store: ProfileStore,
    certificates: Arc<Mutex<HashMap<Uuid, CertificatePrompt>>>,
    cancelled: Arc<AtomicBool>,
    browser: Arc<Mutex<Option<crate::browser::Control>>>,
}
impl AuthControl {
    pub fn reply(&self, reply: AuthReply) -> Result<()> {
        self.native.reply(reply)
    }
    fn browser_control(&self, transaction_id: Uuid) -> Result<crate::browser::Control> {
        self.browser
            .lock()
            .map_err(|_| Error::new(ErrorCode::RuntimeFailure, "Browser prompt state failed"))?
            .as_ref()
            .filter(|control| control.id() == transaction_id)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Conflict,
                    "Browser transaction is no longer current",
                )
            })
    }
    /// Secret-only access for the controlling interface, never status/log serialization.
    pub fn browser_manual_url(&self, transaction_id: Uuid) -> Result<SecretText> {
        self.browser_control(transaction_id)?.manual_url()
    }
    /// Blocking acknowledgement; GUI/async callers dispatch off their event loop.
    pub fn browser_callback(&self, transaction_id: Uuid, uri: SecretText) -> Result<()> {
        self.browser_control(transaction_id)?.callback(uri)
    }
    pub fn browser_confirm(&self, transaction_id: Uuid, accepted: bool) -> Result<()> {
        self.browser_control(transaction_id)?.confirm(accepted)
    }
    /// Blocking pin persistence; GUI/async adapters must dispatch off their event loop.
    pub fn certificate_reply(&self, prompt_id: Uuid, decision: CertificateDecision) -> Result<()> {
        let mut pending = self.certificates.lock().map_err(|_| {
            Error::new(ErrorCode::RuntimeFailure, "Certificate prompt state failed")
        })?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Authentication was cancelled",
            ));
        }
        let prompt = pending.get(&prompt_id).ok_or_else(|| {
            Error::new(
                ErrorCode::Conflict,
                "Certificate prompt is no longer current",
            )
        })?;
        // Native validation consumes the live prompt before any durable pin write.
        // A stale/expired reply therefore cannot alter the acceptance database.
        self.native.certificate_reply(prompt_id, decision)?;
        if decision == CertificateDecision::Pin {
            let saved = self.store.pins().and_then(|pins| {
                self.store.save_pin(
                    CertificatePin::new(&prompt.host, prompt.port, prompt.fingerprint.clone())?,
                    pins.revision,
                )
            });
            if let Err(error) = saved {
                self.cancel();
                pending.remove(&prompt_id);
                return Err(error);
            }
        }
        pending.remove(&prompt_id);
        Ok(())
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.native.cancel();
        if let Ok(mut pending) = self.certificates.try_lock() {
            pending.clear();
        }
        if let Ok(browser) = self.browser.lock() {
            if let Some(browser) = browser.as_ref() {
                browser.cancel();
            }
        }
    }
}

pub struct AuthSession {
    native: AuthTask,
    control: AuthControl,
    notices: Vec<Error>,
    profile_id: Uuid,
    save_password: Option<Zeroizing<String>>,
    non_interactive: bool,
    terminal: bool,
    engine: Engine,
    browser: Option<crate::browser::Task>,
    gui: Option<std::path::PathBuf>,
    browser_timeout: Duration,
}
impl AuthSession {
    pub fn control(&self) -> AuthControl {
        self.control.clone()
    }
    pub fn notices(&self) -> &[Error] {
        &self.notices
    }
    #[cfg(feature = "development")]
    /// # Safety
    /// The caller trusts this executable. Never use a frontend/profile-provided path.
    pub unsafe fn set_gui_for_development(&mut self, path: &std::path::Path) -> Result<()> {
        if !path.is_absolute() || !path.is_file() || self.browser.is_some() {
            return Err(Error::invalid(
                "A trusted absolute desktop executable is required before browser startup",
            ));
        }
        self.gui = Some(path.to_owned());
        Ok(())
    }
    #[cfg(feature = "development")]
    /// Shorten the browser deadline for bounded lab cancellation/timeout proof.
    /// Production sessions always use the full authentication deadline.
    pub fn set_browser_timeout_for_development(&mut self, timeout: Duration) -> Result<()> {
        if timeout.is_zero() || timeout > crate::browser::DEADLINE || self.browser.is_some() {
            return Err(Error::invalid(
                "A shorter positive deadline is required before browser startup",
            ));
        }
        self.browser_timeout = timeout;
        Ok(())
    }
    fn close_browser(&mut self) -> Result<()> {
        let result = if let Some(mut browser) = self.browser.take() {
            browser.close()
        } else {
            Ok(())
        };
        if let Ok(mut browser) = self.control.browser.lock() {
            *browser = None;
        }
        if result.is_err() {
            self.control.cancel();
            self.terminal = true;
            self.save_password = None;
        }
        result
    }
    /// Receive only on an owning blocking event worker. Handoffs stay in Rust.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<AuthEvent>> {
        if self.terminal {
            return Ok(None);
        }
        if self.control.cancelled.load(Ordering::Acquire) {
            self.close_browser()?;
            self.save_password = None;
            self.terminal = true;
            return Ok(Some(AuthEvent::Cancelled));
        }
        if let Some(notice) = self
            .browser
            .as_ref()
            .and_then(crate::browser::Task::try_recv)
        {
            match notice {
                crate::browser::Notice::Prompt(prompt) => {
                    return Ok(Some(AuthEvent::Browser(prompt)));
                }
                crate::browser::Notice::Failed(error) => {
                    self.control.cancel();
                    self.close_browser()?;
                    self.terminal = true;
                    self.save_password = None;
                    return Ok(Some(AuthEvent::Failed(error)));
                }
            }
        }
        let mut event = self
            .native
            .recv_timeout(timeout.min(Duration::from_millis(50)))?;
        if matches!(
            event,
            Some(NativeEvent::Authenticated(_) | NativeEvent::Failed(_) | NativeEvent::Cancelled)
        ) {
            while let Some(notice) = self
                .browser
                .as_ref()
                .and_then(crate::browser::Task::try_recv)
            {
                if let crate::browser::Notice::Failed(error) = notice {
                    event = Some(NativeEvent::Failed(error));
                }
            }
        }
        if matches!(event, Some(NativeEvent::Authenticated(_))) {
            // Do not release a handoff while a requested pin is still committing.
            let _pending = self.control.certificates.lock().map_err(|_| {
                Error::new(ErrorCode::RuntimeFailure, "Certificate prompt state failed")
            })?;
        }
        if self.control.cancelled.load(Ordering::Acquire) {
            self.save_password = None;
            self.terminal = true;
            self.close_browser()?;
            return Ok(Some(AuthEvent::Cancelled));
        }
        if self.non_interactive
            && matches!(
                event,
                Some(
                    NativeEvent::Prompt(_) | NativeEvent::Certificate(_) | NativeEvent::Browser(_)
                )
            )
        {
            self.control.cancel();
            self.terminal = true;
            self.save_password = None;
            return Ok(Some(AuthEvent::Failed(Error::new(
                ErrorCode::AuthenticationRequired,
                "Authentication requires interaction. Retry interactively; no browser or prompt was opened.",
            ))));
        }
        let event = match event {
            Some(NativeEvent::Browser(request)) => {
                self.close_browser()?;
                match crate::browser::Task::start(
                    self.engine.clone(),
                    request,
                    self.control.native.clone(),
                    self.gui.clone(),
                    self.browser_timeout,
                ) {
                    Ok(browser) => {
                        *self.control.browser.lock().map_err(|_| {
                            Error::new(ErrorCode::RuntimeFailure, "Browser prompt state failed")
                        })? = Some(browser.control());
                        self.browser = Some(browser);
                        return Ok(None);
                    }
                    Err(error) => {
                        self.control.cancel();
                        Some(AuthEvent::Failed(error))
                    }
                }
            }
            Some(NativeEvent::BrowserFinished(id)) => {
                self.close_browser()?;
                Some(AuthEvent::BrowserFinished(id))
            }
            Some(NativeEvent::Prompt(prompt)) => Some(AuthEvent::Prompt(prompt)),
            Some(NativeEvent::Certificate(prompt)) => Some(AuthEvent::Certificate(prompt)),
            Some(NativeEvent::Authenticated(handoff)) => Some(AuthEvent::Authenticated(handoff)),
            Some(NativeEvent::Failed(error)) => Some(AuthEvent::Failed(error)),
            Some(NativeEvent::Cancelled) => Some(AuthEvent::Cancelled),
            None => None,
        };
        match &event {
            Some(AuthEvent::Certificate(prompt)) => {
                self.control
                    .certificates
                    .lock()
                    .map_err(|_| {
                        Error::new(ErrorCode::RuntimeFailure, "Certificate prompt state failed")
                    })?
                    .insert(prompt.prompt_id, prompt.clone());
            }
            Some(AuthEvent::Authenticated(_)) => {
                if let Some(password) = self.save_password.take() {
                    let saved = if self.non_interactive {
                        credentials::save_without_ui(
                            self.profile_id,
                            Purpose::Password,
                            &password,
                            true,
                        )
                    } else {
                        credentials::save_blocking(
                            self.profile_id,
                            Purpose::Password,
                            &password,
                            true,
                        )
                    };
                    if let Err(error) = saved {
                        self.notices.push(error);
                    }
                }
                self.terminal = true;
                self.close_browser()?;
            }
            Some(AuthEvent::Failed(_) | AuthEvent::Cancelled) => {
                self.save_password = None;
                self.terminal = true;
                self.close_browser()?;
            }
            _ => {}
        }
        Ok(event)
    }
}

impl Drop for AuthSession {
    fn drop(&mut self) {
        self.control.cancel();
        let _ = self.close_browser();
    }
}

/// Preparation touches disk/keyring and loads native libraries; keep it off async/UI threads.
pub fn begin_blocking(
    attempt_id: Uuid,
    profile: Profile,
    inputs: AuthInputs,
) -> Result<AuthSession> {
    prepare(Engine::load()?, attempt_id, profile, inputs)
}

pub async fn begin(attempt_id: Uuid, profile: Profile, inputs: AuthInputs) -> Result<AuthSession> {
    tokio::task::spawn_blocking(move || begin_blocking(attempt_id, profile, inputs))
        .await
        .map_err(|_| {
            Error::new(
                ErrorCode::RuntimeFailure,
                "Authentication preparation worker stopped",
            )
        })?
}

#[cfg(feature = "development")]
/// # Safety
/// The operator must trust the complete native build; never use a frontend-supplied path.
pub unsafe fn begin_for_development(
    root: &std::path::Path,
    attempt_id: Uuid,
    profile: Profile,
    inputs: AuthInputs,
) -> Result<AuthSession> {
    prepare(
        unsafe { Engine::load_for_development(root)? },
        attempt_id,
        profile,
        inputs,
    )
}

fn prepare(
    engine: Engine,
    attempt_id: Uuid,
    profile: Profile,
    mut inputs: AuthInputs,
) -> Result<AuthSession> {
    let store = ProfileStore::open()?;
    profile.validate_for_connect(&engine.capabilities()?.protocols)?;
    let pins = store.pins()?.pins;
    let mut notices = Vec::new();
    let save_password = if profile.remember_password {
        inputs.password.clone()
    } else {
        None
    };
    let mut saved = |purpose| -> Result<Option<Zeroizing<String>>> {
        let result = if inputs.non_interactive {
            credentials::get_without_ui(profile.id, purpose)
        } else {
            credentials::get_blocking(profile.id, purpose)
        };
        match result {
            Ok(value) => Ok(value),
            Err(error)
                if !inputs.non_interactive && error.code == ErrorCode::KeyringUnavailable =>
            {
                notices.push(error);
                Ok(None)
            }
            Err(error) if error.code == ErrorCode::KeyringUnavailable => Err(Error::new(
                ErrorCode::AuthenticationRequired,
                "Auto/noninteractive authentication cannot access the locked credential store. Unlock it or connect interactively with session-only input.",
            )),
            Err(error) => Err(error),
        }
    };
    if inputs.password.is_none() && profile.remember_password {
        inputs.password = saved(Purpose::Password)?;
    }
    if inputs.key_passphrase.is_none() && profile.client_certificate.is_some() {
        inputs.key_passphrase = saved(Purpose::KeyPassphrase)?;
    }
    if inputs.secondary_key_passphrase.is_none() && profile.secondary_certificate.is_some() {
        inputs.secondary_key_passphrase = saved(Purpose::SecondaryKeyPassphrase)?;
    }
    if inputs.token_seed.is_none() && profile.token_mode != TokenMode::None {
        inputs.token_seed = saved(Purpose::TokenSeed)?;
    }
    if inputs.proxy_credentials.is_none() && profile.proxy.is_some() {
        inputs.proxy_credentials = saved(Purpose::ProxyCredentials)?;
    }
    let token_callbacks: Option<Arc<dyn TokenCallbacks>> = if profile.token_mode == TokenMode::Hotp
    {
        Some(Arc::new(HotpStore {
            profile_id: profile.id,
            non_interactive: inputs.non_interactive,
            transaction: Mutex::new(None),
        }))
    } else {
        None
    };
    let profile_id = profile.id;
    let native = engine.authenticate(
        attempt_id,
        profile,
        pins,
        AuthSecrets {
            password: inputs.password,
            key_passphrase: inputs.key_passphrase,
            secondary_key_passphrase: inputs.secondary_key_passphrase,
            token_seed: inputs.token_seed,
            proxy_credentials: inputs.proxy_credentials,
            token_callbacks,
        },
    )?;
    let control = AuthControl {
        native: native.control(),
        store,
        certificates: Arc::new(Mutex::new(HashMap::new())),
        cancelled: Arc::new(AtomicBool::new(false)),
        browser: Arc::new(Mutex::new(None)),
    };
    Ok(AuthSession {
        native,
        control,
        notices,
        profile_id,
        save_password,
        non_interactive: inputs.non_interactive,
        terminal: false,
        engine,
        browser: None,
        gui: None,
        browser_timeout: crate::browser::DEADLINE,
    })
}
