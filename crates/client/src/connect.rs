//! One connection attempt shared by CLI, TUI and desktop. Secrets never become UI events.
use crate::{
    auth::{self, AuthControl, AuthEvent, AuthInputs},
    daemon,
};
use ocvpn_model::{
    AuthHandoff, AuthPrompt, AuthReply, BrowserPrompt, CertificateDecision, CertificatePrompt,
    ConnectionState, Error, ErrorCode, Profile, Result, SecretText, Snapshot,
    ipc::{Event, EventPayload, Method, Payload},
};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use uuid::Uuid;

#[derive(Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ConnectEvent {
    Prompt(AuthPrompt),
    Certificate(CertificatePrompt),
    Browser(BrowserPrompt),
    BrowserFinished(Uuid),
    Snapshot(Snapshot),
    Notice(Error),
    Connected(Snapshot),
    Failed(Error),
    Cancelled,
}
fn cancelled() -> Error {
    Error::new(ErrorCode::Cancelled, "Connection attempt was cancelled")
}
fn stale() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "Authentication interaction is no longer current",
    )
}

#[derive(Clone)]
pub struct Control {
    cancelled: watch::Sender<bool>,
    progress: watch::Sender<u64>,
    auth: Arc<Mutex<Option<AuthControl>>>,
}
impl Control {
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
        if let Ok(auth) = self.auth.lock() {
            if let Some(auth) = auth.as_ref() {
                auth.cancel();
            }
        }
    }
    fn current(&self) -> Result<AuthControl> {
        if *self.cancelled.borrow() {
            return Err(cancelled());
        }
        self.auth
            .lock()
            .map_err(|_| stale())?
            .as_ref()
            .cloned()
            .ok_or_else(stale)
    }
    fn activity(&self) {
        self.progress
            .send_modify(|value| *value = value.wrapping_add(1));
    }
    /// Native replies/pin storage can block; async/GUI callers use spawn_blocking.
    pub fn reply(&self, reply: AuthReply) -> Result<()> {
        self.current()?.reply(reply)?;
        self.activity();
        Ok(())
    }
    pub fn certificate_reply(&self, id: Uuid, decision: CertificateDecision) -> Result<()> {
        self.current()?.certificate_reply(id, decision)?;
        self.activity();
        Ok(())
    }
    pub fn browser_callback(&self, id: Uuid, uri: SecretText) -> Result<()> {
        self.current()?.browser_callback(id, uri)?;
        self.activity();
        Ok(())
    }
    pub fn browser_confirm(&self, id: Uuid, accepted: bool) -> Result<()> {
        self.current()?.browser_confirm(id, accepted)?;
        self.activity();
        Ok(())
    }
    /// Explicit private terminal/native clipboard access, never status/log JSON.
    pub fn browser_manual_url(&self, id: Uuid) -> Result<SecretText> {
        self.current()?.browser_manual_url(id)
    }
}

pub struct Attempt {
    control: Control,
    events: mpsc::Receiver<ConnectEvent>,
    worker: Option<JoinHandle<Result<Snapshot>>>,
}
impl Attempt {
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    /// Cancellation-safe; terminal results cannot be lost behind a full event queue.
    pub async fn next(&mut self) -> Option<ConnectEvent> {
        let worker = self.worker.as_mut()?;
        let result = tokio::select! {
            biased;
            result = &mut *worker => result,
            event = self.events.recv() => match event { Some(event) => return Some(event), None => worker.await },
        };
        self.worker.take();
        self.events.close();
        Some(match result {
            Ok(Ok(snapshot)) => ConnectEvent::Connected(snapshot),
            Ok(Err(error)) if error.code == ErrorCode::Cancelled => ConnectEvent::Cancelled,
            Ok(Err(error)) => ConnectEvent::Failed(error),
            Err(_) => ConnectEvent::Failed(Error::new(
                ErrorCode::RuntimeFailure,
                "Connection worker stopped unexpectedly. Check service status before retrying.",
            )),
        })
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        // Do not abort a Start RPC: the worker must deliver attempt-scoped Cancel
        // after its acknowledgement, even if actual connection won the race.
        self.control.cancel();
    }
}

/// Requires a running Tokio client runtime. A supplied handoff is the explicit
/// advanced cookie-stdin path; it never passes through generic frontend events.
pub fn start(
    profile: Profile,
    inputs: AuthInputs,
    handoff: Option<AuthHandoff>,
) -> Result<Attempt> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
        Error::new(
            ErrorCode::RuntimeFailure,
            "A running client event runtime is required",
        )
    })?;
    let (cancelled, stopping) = watch::channel(false);
    let (progress, activity) = watch::channel(0);
    let control = Control {
        cancelled,
        progress,
        auth: Arc::new(Mutex::new(None)),
    };
    let (sender, events) = mpsc::channel(32);
    let owned = control.clone();
    let worker = runtime.spawn(async move {
        let result = run(profile, inputs, handoff, &owned, stopping, activity, sender).await;
        owned.cancel();
        result
    });
    Ok(Attempt {
        control,
        events,
        worker: Some(worker),
    })
}

struct Monitor {
    receiver: mpsc::Receiver<Result<Event>>,
    worker: JoinHandle<()>,
}
impl Monitor {
    async fn open() -> Result<Self> {
        let mut events = daemon::Connection::open().await?.subscribe().await?;
        let (sender, receiver) = mpsc::channel(32);
        let worker = tokio::spawn(async move {
            loop {
                let event = events.next().await;
                let failed = event.is_err();
                if sender.send(event).await.is_err() || failed {
                    break;
                }
            }
        });
        Ok(Self { receiver, worker })
    }
    async fn next(&mut self) -> Result<Event> {
        self.receiver.recv().await.ok_or_else(|| {
            Error::new(
                ErrorCode::ServiceUnavailable,
                "Service event stream ended; connection state is unknown",
            )
        })?
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

enum Pump {
    Auth(AuthEvent),
    Notice(Error),
}
fn pump_auth(
    profile: Profile,
    inputs: AuthInputs,
    attempt: Uuid,
    control: Control,
    sender: mpsc::Sender<Pump>,
) {
    let result: Result<()> = (|| {
        let mut session = auth::begin_blocking(attempt, profile, inputs)?;
        *control.auth.lock().map_err(|_| stale())? = Some(session.control());
        // Publishing first closes the cancellation race with blocking keychain preparation.
        if *control.cancelled.borrow() {
            session.control().cancel();
        }
        let mut noticed = 0;
        loop {
            if *control.cancelled.borrow() {
                session.control().cancel();
            }
            let event = session.recv_timeout(Duration::from_millis(50))?;
            for notice in &session.notices()[noticed..] {
                if sender.blocking_send(Pump::Notice(notice.clone())).is_err() {
                    return Ok(());
                }
            }
            noticed = session.notices().len();
            if let Some(event) = event {
                let terminal = matches!(
                    &event,
                    AuthEvent::Authenticated(_) | AuthEvent::Failed(_) | AuthEvent::Cancelled
                );
                if sender.blocking_send(Pump::Auth(event)).is_err() || terminal {
                    break;
                }
            }
        }
        Ok(())
    })();
    if let Ok(mut auth) = control.auth.lock() {
        *auth = None;
    }
    if let Err(error) = result {
        let _ = sender.blocking_send(Pump::Auth(AuthEvent::Failed(error)));
    }
}

async fn emit(
    sender: &mpsc::Sender<ConnectEvent>,
    event: ConnectEvent,
    stopping: &mut watch::Receiver<bool>,
) -> Result<()> {
    if *stopping.borrow() {
        return Err(cancelled());
    }
    tokio::select! {
        biased;
        _ = stopping.changed() => Err(cancelled()),
        result = sender.send(event) => result.map_err(|_| cancelled()),
    }
}
fn inspect(snapshot: &Snapshot, attempt: Uuid) -> Result<()> {
    if matches!(
        snapshot.state,
        ConnectionState::Failed | ConnectionState::AuthenticationRequired
    ) {
        return Err(snapshot.last_error.clone().unwrap_or_else(|| {
            Error::new(
                ErrorCode::AuthenticationRequired,
                "The service requires fresh authentication",
            )
        }));
    }
    if snapshot.attempt_id != Some(attempt) {
        return Err(stale());
    }
    if matches!(
        snapshot.state,
        ConnectionState::Disconnected | ConnectionState::Disconnecting
    ) {
        return Err(cancelled());
    }
    Ok(())
}

async fn run(
    profile: Profile,
    inputs: AuthInputs,
    handoff: Option<AuthHandoff>,
    control: &Control,
    mut stopping: watch::Receiver<bool>,
    activity: watch::Receiver<u64>,
    sender: mpsc::Sender<ConnectEvent>,
) -> Result<Snapshot> {
    if *stopping.borrow() {
        return Err(cancelled());
    }
    let mut connection = daemon::Connection::open().await?;
    if *stopping.borrow() {
        return Err(cancelled());
    }
    let usage = crate::configuration::reserve_profile(&profile).await?;
    if *stopping.borrow() {
        return Err(cancelled());
    }
    let attempt = match connection
        .call(Method::Reserve {
            profile_id: profile.id,
            profile_name: profile.name.clone(),
            protocol: profile.protocol.clone(),
        })
        .await?
    {
        Payload::Reserved { attempt_id } => attempt_id,
        _ => {
            return Err(Error::new(
                ErrorCode::ProtocolViolation,
                "The service did not reserve a connection attempt",
            ));
        }
    };
    drop(usage);
    let result = reserved(
        &mut connection,
        attempt,
        profile,
        inputs,
        handoff,
        control,
        &mut stopping,
        activity,
        &sender,
    )
    .await;
    if result.is_err() {
        control.cancel();
        let cancelled = connection
            .call(Method::Cancel {
                attempt_id: attempt,
            })
            .await;
        if let Err(error) = cancelled {
            if !matches!(error.code, ErrorCode::Busy | ErrorCode::Conflict) {
                // Never retry Start. A fresh authenticated channel may cancel
                // only this exact attempt, not a newer session from another UI.
                let recovered = match daemon::Connection::open().await {
                    Ok(mut connection) => {
                        connection
                            .call(Method::Cancel {
                                attempt_id: attempt,
                            })
                            .await
                    }
                    Err(error) => Err(error),
                };
                if recovered.is_err_and(|error| {
                    !matches!(error.code, ErrorCode::Busy | ErrorCode::Conflict)
                }) {
                    return Err(Error::new(
                        ErrorCode::ServiceUnavailable,
                        "Cancellation could not be confirmed. Check service status and disconnect before retrying; connection state is unknown.",
                    ));
                }
            }
        }
        wait_for_cleanup(attempt).await?;
    }
    result
}

async fn reserved(
    connection: &mut daemon::Connection,
    attempt: Uuid,
    profile: Profile,
    inputs: AuthInputs,
    handoff: Option<AuthHandoff>,
    control: &Control,
    stopping: &mut watch::Receiver<bool>,
    mut activity: watch::Receiver<u64>,
    sender: &mpsc::Sender<ConnectEvent>,
) -> Result<Snapshot> {
    if *stopping.borrow() {
        return Err(cancelled());
    }
    let mut monitor = Monitor::open().await?;
    let handoff = if let Some(handoff) = handoff {
        handoff
    } else {
        let (auth_sender, mut events) = mpsc::channel(16);
        let owned = control.clone();
        tokio::task::spawn_blocking(move || {
            pump_auth(profile, inputs, attempt, owned, auth_sender)
        });
        loop {
            if *stopping.borrow() {
                return Err(cancelled());
            }
            tokio::select! {
                biased;
                _ = stopping.changed() => return Err(cancelled()),
                result = monitor.next() => {
                    if let EventPayload::Snapshot(snapshot) = result?.payload {
                        inspect(&snapshot, attempt)?;
                        emit(sender, ConnectEvent::Snapshot(snapshot), stopping).await?;
                    }
                }
                _ = activity.changed() => {
                    if !matches!(connection.call(Method::AuthProgress { attempt_id: attempt }).await?, Payload::Accepted) {
                        return Err(Error::new(ErrorCode::ProtocolViolation, "Authentication activity was not acknowledged"));
                    }
                }
                event = events.recv() => match event.ok_or_else(|| Error::new(ErrorCode::RuntimeFailure, "Authentication worker stopped before completion"))? {
                    Pump::Notice(error) => emit(sender, ConnectEvent::Notice(error), stopping).await?,
                    Pump::Auth(AuthEvent::Authenticated(handoff)) => break handoff,
                    Pump::Auth(AuthEvent::Failed(error)) => return Err(error),
                    Pump::Auth(AuthEvent::Cancelled) => return Err(cancelled()),
                    Pump::Auth(AuthEvent::Prompt(prompt)) => emit(sender, ConnectEvent::Prompt(prompt), stopping).await?,
                    Pump::Auth(AuthEvent::Certificate(prompt)) => emit(sender, ConnectEvent::Certificate(prompt), stopping).await?,
                    Pump::Auth(AuthEvent::Browser(prompt)) => emit(sender, ConnectEvent::Browser(prompt), stopping).await?,
                    Pump::Auth(AuthEvent::BrowserFinished(id)) => emit(sender, ConnectEvent::BrowserFinished(id), stopping).await?,
                },
            }
        }
    };
    if *stopping.borrow() {
        return Err(cancelled());
    }
    if !matches!(
        connection
            .call(Method::Start {
                attempt_id: attempt,
                handoff
            })
            .await?,
        Payload::Accepted
    ) {
        return Err(Error::new(
            ErrorCode::ProtocolViolation,
            "The service did not acknowledge tunnel startup",
        ));
    }
    loop {
        if *stopping.borrow() {
            return Err(cancelled());
        }
        tokio::select! {
            biased;
            _ = stopping.changed() => return Err(cancelled()),
            result = monitor.next() => {
                if let EventPayload::Snapshot(snapshot) = result?.payload {
                    inspect(&snapshot, attempt)?;
                    if snapshot.state == ConnectionState::Connected { return Ok(snapshot); }
                    emit(sender, ConnectEvent::Snapshot(snapshot), stopping).await?;
                }
            }
        }
    }
}

async fn wait_for_cleanup(attempt: Uuid) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut connection = daemon::Connection::open().await?;
        loop {
            let snapshot = match connection.snapshot().await {
                Ok(snapshot) => snapshot,
                Err(error) if error.code == ErrorCode::Busy => return Ok(()),
                Err(error) => return Err(error),
            };
            // A new owned slot cannot be admitted until the old supervisor and
            // recovery finish. Never cancel or inspect another attempt further.
            if snapshot.attempt_id.is_some_and(|id| id != attempt) { return Ok(()); }
            if let Some(error) = &snapshot.last_error {
                if error.code == ErrorCode::RecoveryRequired { return Err(error.clone()); }
            }
            if !matches!(snapshot.state, ConnectionState::Authenticating | ConnectionState::Connecting |
                ConnectionState::Connected | ConnectionState::Reconnecting | ConnectionState::Disconnecting) { return Ok(()); }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.map_err(|_| Error::new(ErrorCode::RecoveryRequired,
        "Cancellation was requested but cleanup did not finish in time. Check service status and repair before retrying."))?
}
