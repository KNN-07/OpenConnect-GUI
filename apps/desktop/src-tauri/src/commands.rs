// SPDX-License-Identifier: GPL-3.0-only
use ocvpn_client::{
    auth::AuthInputs,
    connect::{self, ConnectEvent, Control},
    daemon,
    profiles::ProfileStore,
};
use ocvpn_model::{ipc::EventPayload, *};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri::{Manager, ipc::Channel};
use uuid::Uuid;

pub struct Pending {
    pub id: Uuid,
    pub control: Control,
    pub done: tokio::sync::watch::Receiver<bool>,
}
#[derive(Default)]
pub struct Desktop {
    pub pending: Mutex<Option<Pending>>,
    pub stream: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    pub clipboard: Arc<Mutex<Option<arboard::Clipboard>>>,
    pub status_item: Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>,
    pub tray: AtomicBool,
    pub close_explained: AtomicBool,
    pub quitting: AtomicBool,
}
fn failure() -> Error {
    Error::new(
        ErrorCode::RuntimeFailure,
        "Desktop worker stopped; retry the action",
    )
}
fn stale() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "This connection interaction has expired",
    )
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| failure())?
}
fn control(state: &Desktop, id: Uuid) -> Result<Control> {
    state
        .pending
        .lock()
        .map_err(|_| failure())?
        .as_ref()
        .filter(|p| p.id == id)
        .map(|p| p.control.clone())
        .ok_or_else(stale)
}
#[tauri::command]
pub async fn profiles() -> Result<ProfileDocument> {
    blocking(|| ProfileStore::open()?.list()).await
}
#[tauri::command]
pub async fn new_profile() -> Result<Profile> {
    Ok(Profile::new(
        String::new(),
        url::Url::parse("https://vpn.example.org").map_err(|_| failure())?,
        "anyconnect".into(),
    ))
}
#[tauri::command]
pub async fn save_profile(
    app: tauri::AppHandle,
    profile: Profile,
    create: bool,
) -> Result<Profile> {
    let value = blocking(move || {
        let store = ProfileStore::open()?;
        if create {
            store.create(profile)
        } else {
            store.update(profile)
        }
    })
    .await?;
    crate::refresh_tray(app);
    Ok(value)
}
#[tauri::command]
pub async fn duplicate_profile(app: tauri::AppHandle, id: Uuid, name: String) -> Result<Profile> {
    let value = blocking(move || ProfileStore::open()?.duplicate(&id.to_string(), &name)).await?;
    crate::refresh_tray(app);
    Ok(value)
}
#[tauri::command]
pub async fn remove_profile(app: tauri::AppHandle, id: Uuid, revision: u64) -> Result<()> {
    ocvpn_client::remove_profile(id, revision).await?;
    crate::refresh_tray(app);
    Ok(())
}
#[tauri::command]
pub async fn import_profiles(app: tauri::AppHandle) -> Result<()> {
    let file = rfd::AsyncFileDialog::new()
        .set_title("Import profiles")
        .add_filter("Profile JSON", &["json"])
        .pick_file()
        .await;
    if let Some(file) = file {
        let path = file.path().to_owned();
        blocking(move || {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .map_err(|_| Error::invalid("Cannot open import file"))?
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::invalid("Cannot read import file"))?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(Error::invalid("Import exceeds 8 MiB"));
            }
            ProfileStore::open()?.import_json(&bytes)?;
            Ok(())
        })
        .await?;
        crate::refresh_tray(app);
    }
    Ok(())
}
#[tauri::command]
pub async fn export_profiles(id: Option<Uuid>) -> Result<()> {
    if let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Export profiles")
        .set_file_name("profiles.json")
        .save_file()
        .await
    {
        let path = file.path().to_owned();
        // Native save dialog handles overwrite consent; store performs atomic replacement.
        blocking(move || {
            ProfileStore::open()?.export_file(
                id.as_ref().map(Uuid::to_string).as_deref(),
                &path,
                true,
            )
        })
        .await?;
    }
    Ok(())
}
#[tauri::command]
pub async fn choose_certificate() -> Result<Option<String>> {
    Ok(rfd::AsyncFileDialog::new()
        .set_title("Choose certificate or key")
        .pick_file()
        .await
        .map(|f| f.path().to_string_lossy().into_owned()))
}
#[tauri::command]
pub async fn read_settings() -> Result<SettingsRead> {
    blocking(ocvpn_client::settings_read).await
}
#[tauri::command]
pub async fn save_settings(settings: Settings, revision: u64) -> Result<SettingsDocument> {
    ocvpn_client::save_settings(settings, revision).await
}
#[tauri::command]
pub async fn forget_credentials(id: Uuid) -> Result<()> {
    ocvpn_client::credentials::delete_profile(id).await
}
#[tauri::command]
pub async fn doctor() -> DoctorReport {
    ocvpn_client::installation::doctor().await
}
#[tauri::command]
pub async fn licenses() -> Result<Vec<LicenseText>> {
    ocvpn_client::licenses().await
}
#[tauri::command]
pub async fn manage_service(action: ServiceAction) -> Result<ServiceStatus> {
    ocvpn_client::installation::manage(action).await
}
#[tauri::command]
pub async fn approval_settings() -> Result<()> {
    ocvpn_client::installation::open_approval_settings().await
}
#[tauri::command]
pub async fn disconnect() -> Result<()> {
    daemon::disconnect().await
}
#[tauri::command]
pub async fn snapshot() -> Result<Snapshot> {
    daemon::snapshot().await
}

#[derive(serde::Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Observation {
    Snapshot(Snapshot),
    Log(LogRecord),
    Error(Error),
}
#[tauri::command]
pub async fn observe(
    app: tauri::AppHandle,
    state: tauri::State<'_, Desktop>,
    channel: Channel<Observation>,
) -> Result<()> {
    let snapshots = daemon::Connection::open().await?.subscribe().await?;
    let logs = daemon::Connection::open().await?.follow_logs().await?;
    let mut handles = state.stream.lock().map_err(|_| failure())?;
    for task in handles.drain(..) {
        task.abort();
    }
    for mut events in [snapshots, logs] {
        let channel = channel.clone();
        let app = app.clone();
        handles.push(tauri::async_runtime::spawn(async move {
            for record in events.take_backlog() {
                if channel.send(Observation::Log(record)).is_err() {
                    return;
                }
            }
            // A single persistent reader owns each framed stream; no select drops a partial read.
            loop {
                let value = match events.next().await {
                    Ok(event) => match event.payload {
                        EventPayload::Snapshot(snapshot) => {
                            if let Some(tray) = app.tray_by_id("main") {
                                let _ = tray.set_tooltip(Some(format!(
                                    "OpenConnect GUI — {:?}",
                                    snapshot.state
                                )));
                            }
                            if let Ok(item) = app.state::<Desktop>().status_item.lock() {
                                if let Some(item) = item.as_ref() {
                                    let _ = item
                                        .set_text(format!("Service state: {:?}", snapshot.state));
                                }
                            }
                            Observation::Snapshot(snapshot)
                        }
                        EventPayload::Log(record) => Observation::Log(record),
                    },
                    Err(error) => {
                        if let Some(tray) = app.tray_by_id("main") {
                            let _ = tray.set_tooltip(Some("OpenConnect GUI — service unavailable"));
                        }
                        if let Ok(item) = app.state::<Desktop>().status_item.lock() {
                            if let Some(item) = item.as_ref() {
                                let _ = item.set_text("Service state: unavailable");
                            }
                        }
                        let _ = channel.send(Observation::Error(error));
                        return;
                    }
                };
                if channel.send(value).is_err() {
                    return;
                }
            }
        }));
    }
    Ok(())
}
#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SessionSecrets {
    password: Option<SecretText>,
    key_passphrase: Option<SecretText>,
    secondary_key_passphrase: Option<SecretText>,
    token_seed: Option<SecretText>,
    proxy_credentials: Option<SecretText>,
}
#[tauri::command]
pub async fn begin_connection(
    state: tauri::State<'_, Desktop>,
    app: tauri::AppHandle,
    id: Uuid,
    operation: Uuid,
    mut secrets: SessionSecrets,
    remember_other: bool,
    channel: Channel<ConnectEvent>,
) -> Result<()> {
    let profile = blocking(move || ProfileStore::open()?.resolve(&id.to_string())).await?;
    if let Some(value) = secrets.proxy_credentials.as_mut() {
        let (username, password) = value
            .as_str()
            .split_once(':')
            .ok_or_else(|| Error::invalid("Proxy credentials require username:password"))?;
        *value =
            SecretText::new(serde_json::to_string(&[username, password]).map_err(|_| failure())?);
    }
    if remember_other {
        use ocvpn_client::credentials::{Purpose, save};
        for (value, purpose) in [
            (&secrets.key_passphrase, Purpose::KeyPassphrase),
            (
                &secrets.secondary_key_passphrase,
                Purpose::SecondaryKeyPassphrase,
            ),
            (&secrets.token_seed, Purpose::TokenSeed),
            (&secrets.proxy_credentials, Purpose::ProxyCredentials),
        ] {
            if let Some(value) = value {
                save(id, purpose, &value.0, true).await?;
            }
        }
    }
    let mut guard = state.pending.lock().map_err(|_| failure())?;
    if guard.is_some() {
        return Err(Error::new(
            ErrorCode::Busy,
            "Another connection attempt is in progress",
        ));
    }
    let inputs = AuthInputs {
        password: secrets.password.map(|s| s.0),
        key_passphrase: secrets.key_passphrase.map(|s| s.0),
        secondary_key_passphrase: secrets.secondary_key_passphrase.map(|s| s.0),
        token_seed: secrets.token_seed.map(|s| s.0),
        proxy_credentials: secrets.proxy_credentials.map(|s| s.0),
        non_interactive: false,
    };
    let mut attempt = connect::start(profile, inputs, None)?;
    let (done, receiver) = tokio::sync::watch::channel(false);
    *guard = Some(Pending {
        id: operation,
        control: attempt.control(),
        done: receiver,
    });
    tauri::async_runtime::spawn(async move {
        while let Some(event) = attempt.next().await {
            if channel.send(event).is_err() {
                attempt.control().cancel();
            }
        }
        if let Ok(mut pending) = app.state::<Desktop>().pending.lock() {
            if pending.as_ref().is_some_and(|p| p.id == operation) {
                pending.take();
            }
        }
        done.send_replace(true);
    });
    Ok(())
}
#[tauri::command]
pub async fn cancel_connection(state: tauri::State<'_, Desktop>, operation: Uuid) -> Result<()> {
    let mut done = {
        let guard = state.pending.lock().map_err(|_| failure())?;
        let pending = guard
            .as_ref()
            .filter(|p| p.id == operation)
            .ok_or_else(stale)?;
        pending.control.cancel();
        pending.done.clone()
    };
    while !*done.borrow_and_update() {
        if done.changed().await.is_err() {
            break;
        }
    }
    Ok(())
}
#[tauri::command]
pub async fn auth_reply(
    state: tauri::State<'_, Desktop>,
    operation: Uuid,
    attempt_id: Uuid,
    prompt_id: Uuid,
    answers: BTreeMap<String, SecretText>,
) -> Result<()> {
    let answers = answers.into_iter().map(|(k, v)| (k, v.0)).collect();
    let control = control(&state, operation)?;
    blocking(move || {
        control.reply(AuthReply {
            attempt_id,
            prompt_id,
            answers: Some(answers),
        })
    })
    .await
}
#[tauri::command]
pub async fn certificate_reply(
    state: tauri::State<'_, Desktop>,
    operation: Uuid,
    prompt_id: Uuid,
    decision: CertificateDecision,
) -> Result<()> {
    let control = control(&state, operation)?;
    blocking(move || control.certificate_reply(prompt_id, decision)).await
}
#[tauri::command]
pub async fn browser_reply(
    state: tauri::State<'_, Desktop>,
    operation: Uuid,
    transaction_id: Uuid,
    accepted: bool,
) -> Result<()> {
    let control = control(&state, operation)?;
    blocking(move || control.browser_confirm(transaction_id, accepted)).await
}
#[tauri::command]
pub async fn browser_clipboard(
    state: tauri::State<'_, Desktop>,
    operation: Uuid,
    transaction_id: Uuid,
    paste: bool,
) -> Result<()> {
    let control = control(&state, operation)?;
    let clipboard = state.clipboard.clone();
    blocking(move || {
        let mut guard = clipboard.lock().map_err(|_| failure())?;
        if guard.is_none() {
            *guard = Some(arboard::Clipboard::new().map_err(|_| {
                Error::new(
                    ErrorCode::AuthenticationRequired,
                    "Native clipboard is unavailable; use embedded or system authentication",
                )
            })?);
        }
        let clipboard = guard.as_mut().ok_or_else(failure)?;
        if paste {
            let text = SecretText::new(
                clipboard
                    .get_text()
                    .map_err(|_| Error::invalid("Clipboard has no callback text"))?,
            );
            if text.as_str().len() > 1024 * 1024 {
                return Err(Error::invalid("Callback exceeds 1 MiB"));
            }
            control.browser_callback(transaction_id, text)?;
            let _ = clipboard.clear();
        } else {
            let text = control.browser_manual_url(transaction_id)?;
            clipboard.set_text(text.as_str()).map_err(|_| {
                Error::new(
                    ErrorCode::AuthenticationRequired,
                    "Cannot copy authentication URL",
                )
            })?;
        }
        Ok(())
    })
    .await
}
#[tauri::command]
pub async fn export_diagnostics() -> Result<()> {
    let report = ocvpn_client::installation::doctor().await;
    let snapshot = daemon::snapshot().await;
    let logs = match daemon::Connection::open().await {
        Ok(mut c) => {
            c.call(ocvpn_model::ipc::Method::Logs { follow: false })
                .await
        }
        Err(e) => Err(e),
    };
    if let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Export diagnostics")
        .set_file_name("openconnect-diagnostics.json")
        .save_file()
        .await
    {
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({ "schema_version":1, "doctor":report, "snapshot":snapshot, "logs":logs })).map_err(|_| failure())?;
        let path = file.path().to_owned();
        blocking(move || ocvpn_client::export_file(&path, &bytes, true)).await?;
    }
    Ok(())
}
pub async fn stop_pending(app: &tauri::AppHandle) {
    let pending = app
        .state::<Desktop>()
        .pending
        .lock()
        .ok()
        .and_then(|guard| {
            guard.as_ref().map(|p| {
                p.control.cancel();
                p.done.clone()
            })
        });
    if let Some(mut done) = pending {
        while !*done.borrow_and_update() {
            if done.changed().await.is_err() {
                break;
            }
        }
    }
}
#[tauri::command]
pub async fn quit_ui(app: tauri::AppHandle, disconnect_first: bool) -> Result<()> {
    stop_pending(&app).await;
    if disconnect_first {
        daemon::disconnect().await?;
    }
    app.state::<Desktop>()
        .quitting
        .store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}
