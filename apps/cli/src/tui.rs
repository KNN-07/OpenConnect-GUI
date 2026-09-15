use crate::{
    blocking, read_file, remove_profile, runtime_error, save_settings, store, terminal_text,
};
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ocvpn_client::{
    auth::AuthInputs,
    connect::{self, Attempt, ConnectEvent},
    daemon,
};
use ocvpn_model::*;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, IsTerminal},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;
struct Screen;
impl Screen {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode().map_err(|_| runtime_error("Cannot enter raw terminal mode"))?;
        let guard = Self;
        execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)
            .map_err(|_| runtime_error("Cannot open terminal screen"))?;
        Ok(guard)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}
struct Reader {
    stop: Arc<AtomicBool>,
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
struct Field {
    key: String,
    label: String,
    value: Zeroizing<String>,
    choices: Vec<(String, String)>,
    secret: bool,
    cursor: usize,
    limit: usize,
}
impl Field {
    fn new(key: &str, label: &str, value: String) -> Self {
        let cursor = value.len();
        Self {
            key: key.into(),
            label: label.into(),
            value: Zeroizing::new(value),
            choices: vec![],
            secret: false,
            cursor,
            limit: 65536,
        }
    }
    fn insert(&mut self, text: &str) {
        let clean = Zeroizing::new(text.chars().filter(|c| !c.is_control()).collect::<String>());
        if self.value.len() + clean.len() <= self.limit {
            self.value.insert_str(self.cursor, &clean);
            self.cursor += clean.len();
        }
    }
    fn key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor = self.value[..self.cursor]
                        .char_indices()
                        .last()
                        .map_or(0, |(i, _)| i);
                }
            }
            KeyCode::Right => {
                if self.cursor < self.value.len() {
                    self.cursor += self.value[self.cursor..].chars().next().unwrap().len_utf8();
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.value.len(),
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let previous = self.value[..self.cursor].char_indices().last().unwrap().0;
                    self.value.replace_range(previous..self.cursor, "");
                    self.cursor = previous;
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.value.len() {
                    let end =
                        self.cursor + self.value[self.cursor..].chars().next().unwrap().len_utf8();
                    self.value.replace_range(self.cursor..end, "");
                }
            }
            KeyCode::Char(c) => self.insert(&c.to_string()),
            _ => {}
        }
    }
    fn cycle(&mut self, back: bool) {
        if self.choices.is_empty() {
            return;
        }
        let index = self
            .choices
            .iter()
            .position(|(v, _)| v == self.value.as_str())
            .unwrap_or(0);
        let n = self.choices.len();
        let next = if back {
            (index + n - 1) % n
        } else {
            (index + 1) % n
        };
        *self.value = self.choices[next].0.clone();
        self.cursor = self.value.len();
    }
}
enum Purpose {
    Profile { original: Profile, new: bool },
    Settings(SettingsDocument),
    Auth(AuthPrompt),
    Certificate(CertificatePrompt),
    Browser(BrowserPrompt),
    Import,
    Export(String),
    Duplicate(String),
    Remove(Profile),
    Actions,
    Help,
    Forget(uuid::Uuid),
    Replace(Profile),
    Primary(Profile),
}
struct Modal {
    title: String,
    message: Zeroizing<String>,
    fields: Vec<Field>,
    focus: usize,
    scroll: Option<u16>,
    purpose: Purpose,
}
impl Modal {
    fn new(title: &str, purpose: Purpose, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            message: Zeroizing::new(String::new()),
            fields,
            focus: 0,
            scroll: None,
            purpose,
        }
    }
}
struct App {
    profiles: Vec<Profile>,
    selected: usize,
    filter: Field,
    log_filter: Field,
    filtering: bool,
    details_focus: bool,
    logs_tab: bool,
    logs: VecDeque<LogRecord>,
    log_scroll: u16,
    paused: bool,
    snapshot: Option<Snapshot>,
    error: Option<Error>,
    modal: Option<Modal>,
    attempt: Option<Attempt>,
    settings: SettingsDocument,
    quit: bool,
    no_color: bool,
}
fn choice(key: &str, label: &str, value: String, values: &[&str]) -> Field {
    let mut f = Field::new(key, label, value);
    f.choices = values
        .iter()
        .map(|s| (s.to_string(), s.to_string()))
        .collect();
    f
}
fn profile_modal(p: Profile, new: bool, capabilities: Option<&Capabilities>) -> Modal {
    let object = serde_json::to_value(&p).expect("profile serializes");
    let mut fields = Vec::new();
    for (key, label) in [
        ("name", "General · Name"),
        ("server", "General · HTTPS server"),
        ("protocol", "General · Protocol"),
        ("username", "Authentication · Username"),
        ("auth_group", "Authentication · Group"),
        ("gateway", "Authentication · Gateway"),
        ("browser_mode", "Authentication · Browser"),
        ("token_mode", "Authentication · Token"),
        (
            "remember_password",
            "Authentication · Remember password (OS keyring consent)",
        ),
        ("ca_file", "Authentication · CA file"),
        ("client_certificate", "Authentication · Certificate / URI"),
        ("client_key", "Authentication · Key / URI"),
        (
            "secondary_certificate",
            "Authentication · Secondary certificate",
        ),
        ("secondary_key", "Authentication · Secondary key"),
        ("proxy", "Advanced · Proxy (no credentials)"),
        ("user_agent", "Advanced · User agent"),
        ("reported_os", "Advanced · Reported OS"),
        ("mtu", "Advanced · MTU"),
        ("sni", "Advanced · SNI"),
        ("direct_gateway", "Advanced · Direct gateway"),
        ("disable_dtls", "Advanced · Disable DTLS"),
        ("disable_ipv6", "Advanced · Disable IPv6"),
        (
            "reconnect_timeout_secs",
            "Advanced · Reconnect timeout (seconds)",
        ),
    ] {
        let value = &object[key];
        let text = if value.is_null() {
            String::new()
        } else if let Some(s) = value.as_str() {
            s.into()
        } else {
            value.to_string()
        };
        let mut f = Field::new(key, label, text);
        if value.is_boolean() {
            f.choices = vec![("false".into(), "No".into()), ("true".into(), "Yes".into())];
        }
        if key == "browser_mode" {
            f = choice(
                key,
                label,
                f.value.to_string(),
                &["auto", "system", "embedded", "manual"],
            );
        }
        if key == "token_mode" {
            f = choice(
                key,
                label,
                f.value.to_string(),
                &["none", "totp", "hotp", "stoken", "yubioath", "oidc"],
            );
            if let Some(c) = capabilities {
                f.choices.retain(|(id, _)| {
                    id == f.value.as_str()
                        || match id.as_str() {
                            "totp" => c.totp,
                            "hotp" => c.hotp,
                            "stoken" => c.stoken,
                            "yubioath" => c.yubioath,
                            _ => true,
                        }
                });
            }
        }
        if key == "reported_os" {
            f = choice(
                key,
                label,
                f.value.to_string(),
                &[
                    "",
                    "linux",
                    "linux-64",
                    "win",
                    "mac-intel",
                    "android",
                    "apple-ios",
                ],
            );
        }
        if key == "protocol" {
            if let Some(c) = capabilities {
                f.choices = c
                    .protocols
                    .iter()
                    .map(|p| (p.id.clone(), p.label.clone()))
                    .collect();
                if !f.choices.iter().any(|(v, _)| v == f.value.as_str()) {
                    f.choices.push((
                        f.value.to_string(),
                        "Unavailable in this engine; preserved".into(),
                    ));
                }
            }
        }
        fields.push(f);
    }
    let mut modal = Modal::new(
        if new { "Add profile" } else { "Edit profile" },
        Purpose::Profile { original: p, new },
        fields,
    );
    *modal.message=match capabilities{
 Some(c)=>format!("Blank optional fields use upstream defaults. Direct gateway applies to GlobalProtect.\nEngine token support: TOTP {} · HOTP {} · stoken {} · YubiOATH {} · PKCS#11 {}\nUnavailable token choices are omitted; existing metadata is preserved. Unsupported protocols cannot connect.",c.totp,c.hotp,c.stoken,c.yubioath,c.pkcs11),
 None=>"Engine capabilities unavailable. Metadata remains editable; run ocvpn doctor before connecting.".into()
 };
    modal
}
impl App {
    fn visible(&self) -> Vec<&Profile> {
        self.profiles
            .iter()
            .filter(|p| {
                p.name
                    .to_lowercase()
                    .contains(&self.filter.value.to_lowercase())
            })
            .collect()
    }
    fn selected(&self) -> Option<Profile> {
        self.visible().get(self.selected).map(|p| (*p).clone())
    }
    async fn reload(&mut self) -> Result<()> {
        self.profiles = store(|s| Ok(s.list()?.profiles)).await?;
        self.selected = self.selected.min(self.visible().len().saturating_sub(1));
        Ok(())
    }
    fn begin(&mut self, profile: Profile) -> Result<()> {
        if profile.remember_password {
            let mut field = Field::new(
                "password",
                "Optional PRIMARY password (never OTP)",
                String::with_capacity(65536),
            );
            field.secret = true;
            let mut modal = Modal::new(
                "Remember primary password",
                Purpose::Primary(profile),
                vec![field],
            );
            *modal.message="This profile permits OS-keyring storage after successful authentication.\nEnter only a primary password here, never an OTP or other MFA response.\nLeave blank to reuse saved credentials or use session-only vendor forms.\nPasswords supplied in later vendor/MFA forms are never automatically saved.".into();
            self.modal = Some(modal);
        } else {
            self.attempt = Some(connect::start(profile, AuthInputs::default(), None)?);
        }
        Ok(())
    }
    fn auth_modal(&mut self, p: AuthPrompt) {
        let fields = p
            .fields
            .iter()
            .map(|field| {
                let label = format!(
                    "{}{}{}",
                    field.label,
                    if field.required {
                        " (required)"
                    } else {
                        " (optional)"
                    },
                    if field.numeric { " · digits only" } else { "" }
                );
                let mut input = Field::new(&field.name, &label, String::with_capacity(65536));
                input.secret = matches!(field.kind, AuthFieldKind::Password | AuthFieldKind::Token);
                input.choices = field
                    .choices
                    .iter()
                    .map(|choice| (choice.id.clone(), choice.label.clone()))
                    .collect();
                if let Some((id, _)) = input.choices.first() {
                    *input.value = id.clone();
                    input.cursor = input.value.len();
                }
                input
            })
            .collect();
        let message = [
            p.banner.as_deref(),
            p.message.as_deref(),
            p.error.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
        let mut modal = Modal::new(
            "Authentication / gateway selection",
            Purpose::Auth(p),
            fields,
        );
        *modal.message = message;
        self.modal = Some(modal);
    }
    async fn event(&mut self, event: ConnectEvent) -> Result<()> {
        match event {
            ConnectEvent::Prompt(p) => {
                if p.fields
                    .iter()
                    .any(|f| matches!(f.kind, AuthFieldKind::SsoToken | AuthFieldKind::SsoUser))
                {
                    return Err(Error::new(
                        ErrorCode::UnsupportedAuthentication,
                        "SSO fields require the native browser flow, not manual form answers",
                    ));
                }
                self.auth_modal(p);
            }
            ConnectEvent::Certificate(p) => {
                let mut modal = Modal::new(
                    "Verify certificate",
                    Purpose::Certificate(p.clone()),
                    vec![choice(
                        "decision",
                        "Decision",
                        "reject".into(),
                        &["reject", "accept_attempt", "pin"],
                    )],
                );
                *modal.message = format!(
                    "{}:{}\n{}\n{}\nFingerprint: {}{}",
                    p.host,
                    p.port,
                    p.reason,
                    p.details,
                    p.fingerprint,
                    if p.changed_pin {
                        " — CHANGED PIN"
                    } else {
                        ""
                    }
                );
                self.modal = Some(modal);
            }
            ConnectEvent::Browser(p) => {
                let mut fields = vec![];
                let mut message = format!(
                    "{} · {:?}\nComplete authentication in your browser. Esc cancels.",
                    p.expected_origin, p.phase
                );
                match p.stage {
                    BrowserStage::ManualInput => {
                        let control = self
                            .attempt
                            .as_ref()
                            .ok_or_else(|| runtime_error("Attempt ended"))?
                            .control();
                        let id = p.transaction_id;
                        let url = blocking(move || control.browser_manual_url(id)).await?;
                        message = format!(
                            "Private authentication URL (do not share):\n{}\nOS custom-scheme dispatch can expose callback arguments.",
                            url.as_str()
                        );
                        let mut field = Field::new(
                            "callback",
                            "Private callback",
                            String::with_capacity(MAX_BROWSER_BYTES),
                        );
                        field.secret = true;
                        field.limit = MAX_BROWSER_BYTES;
                        fields.push(field);
                    }
                    BrowserStage::ConfirmAccount => {
                        message = format!(
                            "Confirm account {} at {}",
                            p.account.as_deref().unwrap_or("unknown"),
                            p.expected_origin
                        );
                        fields.push(choice(
                            "accepted",
                            "Continue as this account",
                            "no".into(),
                            &["no", "yes"],
                        ));
                    }
                    _ => {}
                }
                let mut modal = Modal::new("Browser authentication", Purpose::Browser(p), fields);
                *modal.message = message;
                self.modal = Some(modal);
            }
            ConnectEvent::BrowserFinished(_) => {
                if self
                    .modal
                    .as_ref()
                    .is_some_and(|m| matches!(m.purpose, Purpose::Browser(_)))
                {
                    self.modal = None;
                }
            }
            ConnectEvent::Snapshot(s) => self.snapshot = Some(s),
            ConnectEvent::Connected(s) => {
                self.snapshot = Some(s);
                self.attempt = None;
                self.modal = None;
            }
            ConnectEvent::Failed(e) => {
                self.error = Some(e);
                self.attempt = None;
                self.modal = None;
            }
            ConnectEvent::Cancelled => {
                self.attempt = None;
                self.modal = None;
            }
            ConnectEvent::Notice(e) => self.error = Some(e),
        }
        Ok(())
    }
    async fn submit(&mut self) -> Result<()> {
        let Some(modal) = self.modal.take() else {
            return Ok(());
        };
        let get = |key: &str| {
            modal
                .fields
                .iter()
                .find(|f| f.key == key)
                .map(|f| f.value.as_str())
                .unwrap_or("")
        };
        let result = async {
            match &modal.purpose {
                Purpose::Profile { original, new } => {
                    let mut value = serde_json::to_value(original)
                        .map_err(|_| runtime_error("Cannot encode profile"))?;
                    for f in &modal.fields {
                        let old = &value[&f.key];
                        let input =
                            if old.is_boolean() {
                                serde_json::Value::Bool(
                                    f.value
                                        .parse()
                                        .map_err(|_| Error::invalid("Expected true or false"))?,
                                )
                            } else if f.key == "mtu" || f.key == "reconnect_timeout_secs" {
                                if f.value.is_empty() && f.key == "mtu" {
                                    serde_json::Value::Null
                                } else {
                                    serde_json::Value::from(f.value.parse::<u64>().map_err(
                                        |_| Error::invalid("Expected a positive integer"),
                                    )?)
                                }
                            } else if f.value.is_empty()
                                && !matches!(f.key.as_str(), "name" | "server" | "protocol")
                            {
                                serde_json::Value::Null
                            } else {
                                serde_json::Value::String(f.value.to_string())
                            };
                        value[&f.key] = input;
                    }
                    value["server"] =
                        serde_json::Value::String(parse_server(get("server"))?.to_string());
                    let p: Profile = crate::decode(
                        &serde_json::to_vec(&value)
                            .map_err(|_| runtime_error("Cannot encode profile"))?,
                    )?;
                    let new = *new;
                    store(move |s| if new { s.create(p) } else { s.update(p) }).await?;
                    self.reload().await?;
                }
                Purpose::Settings(doc) => {
                    let theme = crate::decode(format!("\"{}\"", get("theme")).as_bytes())?;
                    let id = if get("auto_connect_profile_id").is_empty() {
                        None
                    } else {
                        Some(
                            uuid::Uuid::parse_str(get("auto_connect_profile_id"))
                                .map_err(|_| Error::invalid("Select a saved profile"))?,
                        )
                    };
                    self.settings = save_settings(
                        Settings {
                            theme,
                            start_at_login: get("start_at_login") == "true",
                            close_to_tray: get("close_to_tray") == "true",
                            auto_connect_profile_id: id,
                        },
                        doc.revision,
                    )
                    .await?;
                }
                Purpose::Auth(p) => {
                    let mut answers = BTreeMap::new();
                    for f in &modal.fields {
                        answers.insert(f.key.clone(), f.value.clone());
                    }
                    let reply = AuthReply {
                        prompt_id: p.prompt_id,
                        attempt_id: p.attempt_id,
                        answers: Some(answers),
                    };
                    p.validate_reply(&reply)?;
                    let control = self.control()?;
                    blocking(move || control.reply(reply)).await?;
                }
                Purpose::Certificate(p) => {
                    let decision = match get("decision") {
                        "pin" => CertificateDecision::Pin,
                        "accept_attempt" => CertificateDecision::AcceptAttempt,
                        _ => CertificateDecision::Reject,
                    };
                    let id = p.prompt_id;
                    let control = self.control()?;
                    blocking(move || control.certificate_reply(id, decision)).await?;
                }
                Purpose::Browser(p) => {
                    let control = self.control()?;
                    let id = p.transaction_id;
                    match p.stage {
                        BrowserStage::ManualInput => {
                            let uri = SecretText::new(get("callback").to_owned());
                            blocking(move || control.browser_callback(id, uri)).await?;
                        }
                        BrowserStage::ConfirmAccount => {
                            let yes = get("accepted") == "yes";
                            blocking(move || control.browser_confirm(id, yes)).await?;
                        }
                        _ => {}
                    }
                }
                Purpose::Import => {
                    let path = std::path::PathBuf::from(get("path"));
                    store(move |s| s.import_json(&read_file(&path)?)).await?;
                    self.reload().await?;
                }
                Purpose::Export(selector) => {
                    let selector = selector.clone();
                    let path = std::path::PathBuf::from(get("path"));
                    let force = get("force") == "true";
                    store(move |s| s.export_file(Some(&selector), &path, force)).await?;
                }
                Purpose::Duplicate(selector) => {
                    let selector = selector.clone();
                    let name = get("name").to_string();
                    store(move |s| s.duplicate(&selector, &name)).await?;
                    self.reload().await?;
                }
                Purpose::Remove(p) => {
                    if get("confirm") == "yes" {
                        remove_profile(p.clone()).await?;
                        self.reload().await?;
                    }
                }
                Purpose::Forget(id) => {
                    if get("confirm") == "yes" {
                        ocvpn_client::credentials::delete_profile(*id).await?;
                    }
                }
                Purpose::Replace(profile) => {
                    if get("confirm") == "yes" {
                        crate::disconnect_wait().await?;
                        self.begin(profile.clone())?;
                    }
                }
                Purpose::Primary(profile) => {
                    let password = if get("password").is_empty() {
                        None
                    } else {
                        Some(Zeroizing::new(get("password").to_owned()))
                    };
                    self.attempt = Some(connect::start(
                        profile.clone(),
                        AuthInputs {
                            password,
                            ..Default::default()
                        },
                        None,
                    )?);
                }
                Purpose::Help => {}
                Purpose::Actions => {
                    let action = get("action");
                    let selected = self.selected();
                    self.modal = Some(match action {
                        "import" => Modal::new(
                            "Import profiles",
                            Purpose::Import,
                            vec![Field::new("path", "JSON file", String::new())],
                        ),
                        "duplicate" => {
                            let p = selected.ok_or_else(|| Error::invalid("Select a profile"))?;
                            Modal::new(
                                "Duplicate without credentials",
                                Purpose::Duplicate(p.id.to_string()),
                                vec![Field::new("name", "New unique name", String::new())],
                            )
                        }
                        "forget_credentials" => {
                            let p = selected.ok_or_else(|| Error::invalid("Select a profile"))?;
                            Modal::new(
                                "Remove saved credentials",
                                Purpose::Forget(p.id),
                                vec![choice(
                                    "confirm",
                                    "Remove saved credentials?",
                                    "no".into(),
                                    &["no", "yes"],
                                )],
                            )
                        }
                        _ => {
                            let p = selected.ok_or_else(|| Error::invalid("Select a profile"))?;
                            Modal::new(
                                "Export profile (no secrets)",
                                Purpose::Export(p.id.to_string()),
                                vec![
                                    Field::new("path", "Output file", String::new()),
                                    choice(
                                        "force",
                                        "Overwrite existing file",
                                        "false".into(),
                                        &["false", "true"],
                                    ),
                                ],
                            )
                        }
                    });
                }
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            self.modal = Some(modal);
        }
        result
    }
    fn control(&self) -> Result<connect::Control> {
        self.attempt
            .as_ref()
            .map(Attempt::control)
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "Authentication attempt ended"))
    }
    async fn key(
        &mut self,
        key: event::KeyEvent,
        capabilities: Option<&Capabilities>,
    ) -> Result<()> {
        if key.kind == KeyEventKind::Release {
            return Ok(());
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            if let Some(a) = &self.attempt {
                a.control().cancel();
            } else {
                self.quit = true;
            }
            return Ok(());
        }
        if self.modal.is_some() {
            if key.code == KeyCode::Esc {
                let auth = self.modal.as_ref().is_some_and(|m| {
                    matches!(
                        m.purpose,
                        Purpose::Auth(_) | Purpose::Certificate(_) | Purpose::Browser(_)
                    )
                });
                self.modal = None;
                if auth {
                    if let Some(a) = &self.attempt {
                        a.control().cancel();
                    }
                }
                return Ok(());
            }
            if ctrl && matches!(key.code, KeyCode::Enter | KeyCode::Char('s')) {
                return self.submit().await;
            }
            if let Some(modal) = self.modal.as_mut() {
                if matches!(key.code, KeyCode::PageUp | KeyCode::PageDown) {
                    let scroll = modal.scroll.get_or_insert(0);
                    *scroll = if key.code == KeyCode::PageUp {
                        scroll.saturating_sub(5)
                    } else {
                        scroll.saturating_add(5)
                    };
                    return Ok(());
                }
                modal.scroll = None;
            }
            let modal = self.modal.as_mut().unwrap();
            let count = modal.fields.len() + 1;
            match key.code {
                KeyCode::Tab | KeyCode::Down => modal.focus = (modal.focus + 1) % count,
                KeyCode::BackTab | KeyCode::Up => modal.focus = (modal.focus + count - 1) % count,
                KeyCode::Enter if modal.focus == modal.fields.len() => return self.submit().await,
                KeyCode::Enter => {
                    modal.focus = (modal.focus + 1) % count;
                }
                code => {
                    if let Some(f) = modal.fields.get_mut(modal.focus) {
                        if !f.choices.is_empty()
                            && matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' '))
                        {
                            f.cycle(code == KeyCode::Left);
                        } else {
                            f.key(code);
                        }
                    }
                }
            }
            return Ok(());
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.filtering = false,
                code => {
                    if self.logs_tab && self.details_focus {
                        self.log_filter.key(code);
                        self.log_scroll = 0;
                    } else {
                        self.filter.key(code);
                        self.selected = 0;
                    }
                }
            }
            return Ok(());
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('Q') => {
                if let Some(a) = &self.attempt {
                    a.control().cancel();
                } else {
                    crate::disconnect_wait().await?;
                }
                self.quit = true;
            }
            KeyCode::Esc => {
                if let Some(a) = &self.attempt {
                    a.control().cancel();
                }
                self.error = None;
            }
            KeyCode::Tab => self.details_focus = !self.details_focus,
            KeyCode::Down | KeyCode::Char('j') => {
                if self.details_focus {
                    self.paused = true;
                    self.log_scroll = self.log_scroll.saturating_add(1);
                } else {
                    self.selected = (self.selected + 1).min(self.visible().len().saturating_sub(1));
                }
            }
            KeyCode::Up | KeyCode::Char('k') if !ctrl => {
                if self.details_focus {
                    self.paused = true;
                    self.log_scroll = self.log_scroll.saturating_sub(1);
                } else {
                    self.selected = self.selected.saturating_sub(1);
                }
            }
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('k') if ctrl => self.filtering = true,
            KeyCode::Char('l') => {
                self.logs_tab = !self.logs_tab;
                self.details_focus = true;
            }
            KeyCode::Char('p') => {
                if !self.paused {
                    let query = self.log_filter.value.to_lowercase();
                    let count = self
                        .logs
                        .iter()
                        .filter(|l| l.message.to_lowercase().contains(&query))
                        .count() as u16;
                    let height = terminal::size()
                        .map_err(|_| runtime_error("Cannot read terminal size"))?
                        .1
                        .saturating_sub(8);
                    self.log_scroll = count.saturating_sub(height);
                }
                self.paused = !self.paused;
            }
            KeyCode::Char('x') if self.logs_tab => {
                self.logs.clear();
                self.log_scroll = 0;
            }
            KeyCode::Char('c') => {
                if self.attempt.is_some() {
                    return Err(Error::new(
                        ErrorCode::Busy,
                        "An authentication attempt is pending; Esc cancels it",
                    ));
                }
                let profile = self
                    .selected()
                    .ok_or_else(|| Error::invalid("Add or select a profile first"))?;
                if self.snapshot.as_ref().is_some_and(|s| {
                    matches!(
                        s.state,
                        ConnectionState::Connected | ConnectionState::Reconnecting
                    )
                }) {
                    self.modal = Some(Modal::new(
                        &format!("Disconnect current tunnel and connect {}?", profile.name),
                        Purpose::Replace(profile),
                        vec![choice(
                            "confirm",
                            "Disconnect then connect",
                            "no".into(),
                            &["no", "yes"],
                        )],
                    ));
                } else {
                    self.begin(profile)?;
                }
            }
            KeyCode::Char('d') => {
                if let Some(a) = &self.attempt {
                    a.control().cancel();
                } else {
                    crate::disconnect_wait().await?;
                }
            }
            KeyCode::Char('n') => {
                let p = Profile::new(
                    String::new(),
                    parse_server("https://vpn.example.org")?,
                    "anyconnect".into(),
                );
                let mut modal = profile_modal(p, true, capabilities);
                if let Some(f) = modal.fields.iter_mut().find(|f| f.key == "server") {
                    f.value.clear();
                    f.cursor = 0;
                }
                self.modal = Some(modal);
            }
            KeyCode::Char('e') | KeyCode::Enter => {
                let p = self
                    .selected()
                    .ok_or_else(|| Error::invalid("Select a profile"))?;
                self.modal = Some(profile_modal(p, false, capabilities));
            }
            KeyCode::Delete => {
                let p = self
                    .selected()
                    .ok_or_else(|| Error::invalid("Select a profile"))?;
                self.modal = Some(Modal::new(
                    &format!("Remove {} and saved credentials", p.name),
                    Purpose::Remove(p),
                    vec![choice(
                        "confirm",
                        "Confirm removal",
                        "no".into(),
                        &["no", "yes"],
                    )],
                ));
            }
            KeyCode::Char('a') => {
                self.modal = Some(Modal::new(
                    "Profile actions",
                    Purpose::Actions,
                    vec![choice(
                        "action",
                        "Action",
                        "duplicate".into(),
                        &["duplicate", "import", "export", "forget_credentials"],
                    )],
                ))
            }
            KeyCode::Char('s') => {
                let read = blocking(ocvpn_client::settings_read).await?;
                self.settings = read.document;
                self.error = read.auto_connect_error;
                let settings = &self.settings.settings;
                let mut auto = Field::new(
                    "auto_connect_profile_id",
                    "Auto-connect at login",
                    settings
                        .auto_connect_profile_id
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                );
                auto.choices.push((String::new(), "Disabled".into()));
                auto.choices.extend(
                    self.profiles
                        .iter()
                        .map(|p| (p.id.to_string(), p.name.clone())),
                );
                self.modal = Some(Modal::new(
                    "Settings",
                    Purpose::Settings(self.settings.clone()),
                    vec![
                        choice(
                            "theme",
                            "Theme",
                            format!("{:?}", settings.theme).to_lowercase(),
                            &["system", "light", "dark"],
                        ),
                        choice(
                            "start_at_login",
                            "Register user login auto-connect",
                            settings.start_at_login.to_string(),
                            &["false", "true"],
                        ),
                        auto,
                        choice(
                            "close_to_tray",
                            "Desktop close to tray",
                            settings.close_to_tray.to_string(),
                            &["false", "true"],
                        ),
                    ],
                ));
            }
            KeyCode::Char('?') => {
                let mut modal = Modal::new("Keyboard help", Purpose::Help, vec![]);
                *modal.message="Arrows / j k: select or scroll · Tab: switch pane\nc connect · d disconnect/cancel · n add · e edit · Delete remove\na profile actions (duplicate/import/export/credentials)\n/ filter focused profiles/logs · s settings · l details/logs · p pause logs · x clear view\nr reload and retry service · q leave tunnel running · Q disconnect and quit\nForms: Tab/Up/Down focus · Left/Right/Space choices\nEnter next field / submit · Ctrl+S save · Esc cancel\nText: Unicode, Home/End, arrows, Backspace/Delete, bracketed paste\nCtrl+C cancels an attempt, or exits leaving an established tunnel.\nNO_COLOR disables styling; terminal colors are limited to ANSI colors.".into();
                self.modal = Some(modal);
            }
            KeyCode::Char('r') => {
                self.reload().await?;
                self.snapshot = Some(daemon::snapshot().await?);
                self.error = None;
            }
            _ => {}
        }
        Ok(())
    }
    fn draw(&self, frame: &mut ratatui::Frame) {
        let area = frame.area();
        let accent = if self.no_color {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
                .fg(if self.settings.settings.theme == Theme::Light {
                    Color::Blue
                } else {
                    Color::Cyan
                })
                .add_modifier(Modifier::BOLD)
        };
        if !self.no_color {
            let base = match self.settings.settings.theme {
                Theme::Light => Style::default().bg(Color::White).fg(Color::Black),
                Theme::Dark => Style::default().bg(Color::Black).fg(Color::Gray),
                Theme::System => Style::default(),
            };
            frame.render_widget(Block::default().style(base), area);
        }
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ])
            .split(area);
        let searching_logs = self.logs_tab && self.details_focus;
        let scope = if searching_logs { "Logs" } else { "Profiles" };
        let title = format!(
            "OpenConnect GUI · {scope}{}{}",
            if self.filtering { " search: " } else { ": " },
            if searching_logs {
                self.log_filter.value.as_str()
            } else {
                self.filter.value.as_str()
            }
        );
        frame.render_widget(
            Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
            rows[0],
        );
        let narrow = area.width < 80;
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(if narrow {
                vec![Constraint::Percentage(100)]
            } else {
                vec![Constraint::Length(28), Constraint::Min(1)]
            })
            .split(rows[1]);
        let active_profile = self
            .snapshot
            .as_ref()
            .filter(|s| {
                !matches!(
                    s.state,
                    ConnectionState::Disconnected
                        | ConnectionState::Failed
                        | ConnectionState::AuthenticationRequired
                )
            })
            .and_then(|s| s.profile_id);
        let list = List::new(
            self.visible()
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let active = active_profile == Some(p.id);
                    ListItem::new(format!(
                        "{} {}\n  {}{}",
                        if i == self.selected { ">" } else { " " },
                        terminal_text(&p.name),
                        terminal_text(&p.protocol),
                        if active { " · active" } else { "" }
                    ))
                    .style(if i == self.selected {
                        accent
                    } else {
                        Style::default()
                    })
                })
                .collect::<Vec<_>>(),
        )
        .block(Block::default().title("Profiles").borders(Borders::ALL));
        if !narrow || !self.details_focus {
            let mut state = ratatui::widgets::ListState::default();
            state.select(Some(self.selected));
            frame.render_stateful_widget(list, panes[0], &mut state);
        }
        if !narrow || self.details_focus {
            let pane = if narrow { panes[0] } else { panes[1] };
            let text = if self.logs_tab {
                let query = self.log_filter.value.to_lowercase();
                self.logs
                    .iter()
                    .filter(|l| l.message.to_lowercase().contains(&query))
                    .map(|l| {
                        format!(
                            "{} {:?} {}",
                            l.timestamp,
                            l.level,
                            terminal_text(&l.message)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                match &self.snapshot{
 Some(s)=>{let network=s.network.as_ref();format!("State: {:?}\nProfile: {}\nSession: {}\nStarted: {}\nReceived: {} bytes · Sent: {} bytes\n\nInterface: {}\nTransport: {}\nAddresses: {}\nDNS: {}\nSearch: {}\nRoutes:\n{}\n\n{}",s.state,s.profile_name.as_deref().map(terminal_text).unwrap_or_else(||"None".into()),s.session_id.map(|v|v.to_string()).unwrap_or_default(),s.started_at.map(|v|v.to_string()).unwrap_or_default(),s.traffic.rx_bytes,s.traffic.tx_bytes,network.map(|n|terminal_text(&n.interface)).unwrap_or_else(||"—".into()),network.map(|n|terminal_text(&n.transport)).unwrap_or_else(||"—".into()),network.map(|n|n.addresses.join(", ")).unwrap_or_default(),network.map(|n|n.dns_servers.join(", ")).unwrap_or_default(),network.map(|n|n.search_domains.join(", ")).unwrap_or_default(),network.map(|n|n.routes.join("\n")).unwrap_or_default(),s.last_error.as_ref().map(|e|terminal_text(&e.message)).unwrap_or_default())},
 None=>"Service state unavailable. Press r to retry; run ocvpn doctor or ocvpn service repair.".into()
 }
            };
            let scroll = if self.logs_tab && !self.paused {
                (text.lines().count() as u16).saturating_sub(pane.height.saturating_sub(2))
            } else {
                self.log_scroll
            };
            frame.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .scroll((scroll, 0))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(if self.logs_tab {
                                if self.paused {
                                    "Logs · paused · / search"
                                } else {
                                    "Logs · live · / search"
                                }
                            } else {
                                "Connection details"
                            }),
                    ),
                pane,
            );
        }
        let footer=self.error.as_ref().map(|e|format!("{} · Esc dismiss",terminal_text(&e.message))).unwrap_or_else(||"c connect · d disconnect · n add · e edit · a actions · s settings · ? help · q leave VPN running".into());
        frame.render_widget(
            Paragraph::new(footer)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL)),
            rows[2],
        );
        if let Some(modal) = &self.modal {
            let width = area.width.saturating_sub(4).min(100);
            let height = area.height.saturating_sub(2);
            let rect = Rect::new(area.x + (area.width - width) / 2, area.y + 1, width, height);
            frame.render_widget(Clear, rect);
            let title = format!(
                "{} · Ctrl+S submit · Esc cancel",
                terminal_text(&modal.title)
            );
            let block = Block::default().borders(Borders::ALL).title(title);
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            let mut lines: Vec<Line> = wrapped_lines(&modal.message, inner.width as usize)
                .into_iter()
                .map(Line::from)
                .collect();
            if let Some(error) = &self.error {
                let style = if self.no_color {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Red)
                };
                lines.extend(
                    wrapped_lines(&terminal_text(&error.message), inner.width as usize)
                        .into_iter()
                        .map(|line| Line::styled(line, style)),
                );
                lines.push(Line::from(""));
            }
            let header_lines = lines.len();
            for (i, f) in modal.fields.iter().enumerate() {
                let display = if f.secret {
                    let before = "•".repeat(f.value[..f.cursor].chars().count());
                    let after = "•".repeat(f.value[f.cursor..].chars().count());
                    if i == modal.focus {
                        format!("{before}▏{after}")
                    } else {
                        format!("{before}{after}")
                    }
                } else if let Some((id, label)) =
                    f.choices.iter().find(|(id, _)| id == f.value.as_str())
                {
                    format!("{label} [{id}] ◀ ▶")
                } else if i == modal.focus {
                    format!("{}▏{}", &f.value[..f.cursor], &f.value[f.cursor..])
                } else {
                    terminal_text(&f.value)
                };
                lines.push(Line::styled(
                    format!("{} {}", if i == modal.focus { ">" } else { " " }, f.label),
                    if i == modal.focus {
                        accent
                    } else {
                        Style::default()
                    },
                ));
                let display = visible_input(&display, inner.width.saturating_sub(2) as usize);
                lines.push(Line::styled(
                    format!("  {display}"),
                    if i == modal.focus {
                        accent
                    } else {
                        Style::default()
                    },
                ));
            }
            lines.push(Line::styled(
                "[ Submit ] Ctrl+S save · Esc cancel · PgUp/PgDn message",
                if modal.focus == modal.fields.len() {
                    accent
                } else {
                    Style::default()
                },
            ));
            let automatic = if modal.fields.is_empty() {
                0
            } else {
                (header_lines + modal.focus * 2 + 2)
                    .saturating_sub(inner.height as usize)
                    .min(u16::MAX as usize) as u16
            };
            let offset = modal.scroll.unwrap_or(automatic);
            frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), inner);
        }
    }
}
pub async fn run() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::new(
            ErrorCode::AuthenticationRequired,
            "The TUI requires an interactive terminal",
        ));
    }
    let settings = store(|s| s.settings()).await?;
    let profiles = store(|s| Ok(s.list()?.profiles)).await?;
    let capabilities = blocking(ocvpn_client::capabilities).await;
    let mut app = App {
        profiles,
        selected: 0,
        filter: Field::new("filter", "Search", String::new()),
        log_filter: Field::new("log_filter", "Search logs", String::new()),
        filtering: false,
        details_focus: false,
        logs_tab: false,
        logs: VecDeque::new(),
        log_scroll: 0,
        paused: false,
        snapshot: None,
        error: capabilities.as_ref().err().cloned(),
        modal: None,
        attempt: None,
        settings,
        quit: false,
        no_color: std::env::var_os("NO_COLOR").is_some(),
    };
    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        old_hook(info);
    }));
    let _screen = Screen::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))
        .map_err(|_| runtime_error("Cannot initialize terminal"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let _reader = Reader { stop: stop.clone() };
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(64);
    let input = tokio::task::spawn_blocking(move || {
        while !stop.load(Ordering::Acquire) {
            match event::poll(Duration::from_millis(100)) {
                Ok(true) => match event::read() {
                    Ok(e) => {
                        if input_tx.blocking_send(Ok(e)).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = input_tx.blocking_send(Err(runtime_error("Terminal input failed")));
                        break;
                    }
                },
                Ok(false) => {}
                Err(_) => break,
            }
        }
    });
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(64);
    let snapshots = spawn_service(false, events_tx.clone());
    let logs = spawn_service(true, events_tx);
    let mut result=async{while !app.quit {terminal.draw(|frame|app.draw(frame)).map_err(|_|runtime_error("Terminal rendering failed"))?;
 tokio::select!{
 event=input_rx.recv()=>match event.ok_or_else(||runtime_error("Terminal input stopped"))??{
 Event::Key(key)=>{tokio::select!{
 result=app.key(key,capabilities.as_ref().ok())=>{if let Err(error)=result{app.error=Some(error);}},
 signal=crate::interruption()=>{signal?;app.quit=true;}
 }},
 Event::Paste(text)=>{let text=Zeroizing::new(text);if let Some(modal)=&mut app.modal{if let Some(field)=modal.fields.get_mut(modal.focus){field.insert(&text);}}else if app.filtering{if app.logs_tab&&app.details_focus{app.log_filter.insert(&text);}else{app.filter.insert(&text);}}},_=>{}},
 event=events_rx.recv()=>{if let Some(event)=event{match event{Ok(ipc::EventPayload::Snapshot(s))=>{app.snapshot=Some(s);},Ok(ipc::EventPayload::Log(l))=>{if app.logs.len()==2000{app.logs.pop_front();app.log_scroll=app.log_scroll.saturating_sub(1);}app.logs.push_back(l);},Err(e)=>{app.snapshot=None;app.error=Some(e);}}}},
 event=async{match &mut app.attempt{Some(a)=>a.next().await,None=>std::future::pending().await}}=>{if let Some(event)=event{if let Err(e)=app.event(event).await{app.error=Some(e);if let Some(a)=&app.attempt{a.control().cancel();}}}},
 signal=crate::interruption()=>{signal?;app.quit=true;}
 }
 }Ok(())}.await;
    if let Some(mut attempt) = app.attempt.take() {
        attempt.control().cancel();
        while let Some(event) = attempt.next().await {
            if let ConnectEvent::Failed(error) = event {
                if matches!(
                    error.code,
                    ErrorCode::ServiceUnavailable
                        | ErrorCode::RecoveryRequired
                        | ErrorCode::NetworkFailure
                ) {
                    result = Err(error);
                }
            }
        }
    }
    snapshots.abort();
    logs.abort();
    _reader.stop.store(true, Ordering::Release);
    drop(input_rx);
    let _ = input.await;
    result
}
fn spawn_service(
    logs: bool,
    tx: tokio::sync::mpsc::Sender<Result<ipc::EventPayload>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let result = async {
                let connection = daemon::Connection::open().await?;
                let mut events = if logs {
                    connection.follow_logs().await?
                } else {
                    connection.subscribe().await?
                };
                for record in events.take_backlog() {
                    if tx.send(Ok(ipc::EventPayload::Log(record))).await.is_err() {
                        return Ok(());
                    }
                }
                loop {
                    let event = events.next().await?;
                    if tx.send(Ok(event.payload)).await.is_err() {
                        return Ok(());
                    }
                }
            }
            .await;
            if let Err(e) = result {
                if tx.send(Err(e)).await.is_err() {
                    break;
                }
            } else {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    })
}
fn wrapped_lines(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let width = width.max(1);
    for line in text.lines() {
        let mut current = String::new();
        let mut used = 0;
        for c in line.chars().filter(|c| !c.is_control()) {
            let size = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
            if used + size > width && !current.is_empty() {
                lines.push(std::mem::take(&mut current));
                used = 0;
            }
            current.push(c);
            used += size;
        }
        lines.push(current);
    }
    lines
}
fn visible_input(text: &str, width: usize) -> String {
    let cursor = text.find('▏').unwrap_or(0);
    let mut left = cursor;
    let mut used = 0;
    for (index, c) in text[..cursor].char_indices().rev() {
        let size = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if used + size > width / 2 {
            break;
        }
        left = index;
        used += size;
    }
    let mut result = String::new();
    used = 0;
    for c in text[left..].chars() {
        let size = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if used + size > width {
            break;
        }
        result.push(c);
        used += size;
    }
    result
}
