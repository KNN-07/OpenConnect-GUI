//! One machine-wide slot, authorized using transport-observed peer identities.
use crate::{
    PeerIdentity,
    worker::{self, Update},
};
use ocvpn_model::{
    Capabilities, ConnectionState as State, Error, ErrorCode, LogLevel, LogRecord, Result,
    Snapshot, TrafficCounters,
    ipc::{self, Event, EventPayload, Hello, Method, Payload, Request, Response},
};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, broadcast, mpsc, watch},
    time::{Instant, timeout},
};
use uuid::Uuid;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn busy() -> Error {
    Error::new(
        ErrorCode::Busy,
        "The machine-wide VPN slot belongs to another session",
    )
}
struct Slot {
    owner: PeerIdentity,
    connection: Uuid,
    attempt: Uuid,
    protocol: String,
    lease: Instant,
    cancel: Option<mpsc::Sender<()>>,
}
struct Session {
    snapshot: Snapshot,
    slot: Option<Slot>,
    last_owner: Option<PeerIdentity>,
    logs: VecDeque<LogRecord>,
    recovery_blocked: bool,
    quiescence_blocked: bool,
    stopping: bool,
}
type EventBus = broadcast::Sender<(Option<PeerIdentity>, Event)>;
struct Service {
    state: Mutex<Session>,
    recovery: Arc<Mutex<()>>,
    events: EventBus,
    capabilities: Capabilities,
}
impl Session {
    fn authorize(&self, peer: &PeerIdentity) -> Result<()> {
        if self.slot.as_ref().is_some_and(|slot| &slot.owner != peer) {
            return Err(busy());
        }
        Ok(())
    }
    fn visible(&self, peer: &PeerIdentity) -> Snapshot {
        if self.slot.is_none() && self.last_owner.as_ref().is_some_and(|owner| owner != peer) {
            Snapshot {
                profile_id: None,
                profile_name: None,
                attempt_id: None,
                session_id: None,
                started_at: None,
                network: None,
                traffic: TrafficCounters::default(),
                last_error: None,
                state: State::Disconnected,
                ..self.snapshot.clone()
            }
        } else {
            self.snapshot.clone()
        }
    }
    fn publish(&mut self, events: &EventBus, message: Option<(&str, LogLevel)>) {
        if let Some((message, level)) = message {
            let log = LogRecord {
                timestamp: now(),
                level,
                message: message.into(),
            };
            if self.logs.len() == 2000 {
                self.logs.pop_front();
            }
            self.logs.push_back(log.clone());
            self.snapshot.sequence += 1;
            let _ = events.send((
                self.last_owner.clone(),
                Event {
                    service_instance_id: self.snapshot.service_instance_id,
                    sequence: self.snapshot.sequence,
                    payload: EventPayload::Log(log),
                },
            ));
        }
        self.snapshot.sequence += 1;
        let _ = events.send((
            self.last_owner.clone(),
            Event {
                service_instance_id: self.snapshot.service_instance_id,
                sequence: self.snapshot.sequence,
                payload: EventPayload::Snapshot(self.snapshot.clone()),
            },
        ));
    }
    fn cancel(&mut self, events: &EventBus) {
        if let Some(slot) = &self.slot {
            if let Some(cancel) = &slot.cancel {
                let _ = cancel.try_send(());
                self.snapshot.state = State::Disconnecting;
            } else {
                self.last_owner = Some(slot.owner.clone());
                self.slot = None;
                self.snapshot.state = State::Disconnected;
            }
            self.publish(events, Some(("VPN cancellation requested", LogLevel::Info)));
        }
    }
}
/// Runs until the supplied stop notification. The caller owns OS service signals.
pub async fn run(stop: watch::Receiver<bool>) -> Result<()> {
    run_with_ready(stop, || Ok(())).await
}
pub(crate) async fn run_with_ready(
    mut stop: watch::Receiver<bool>,
    ready: impl FnOnce() -> Result<()>,
) -> Result<()> {
    #[cfg(unix)]
    let mut listener = crate::unix::bind_control_listener().map_err(|_| {
        Error::new(
            ErrorCode::ServiceUnavailable,
            "Cannot bind protected control endpoint",
        )
    })?;
    #[cfg(unix)]
    let _endpoint = crate::unix::EndpointGuard::capture().map_err(|_| {
        Error::new(
            ErrorCode::ServiceUnavailable,
            "Cannot retain control endpoint identity",
        )
    })?;
    #[cfg(windows)]
    let mut listener = crate::windows::ControlListener::bind().map_err(|_| {
        Error::new(
            ErrorCode::ServiceUnavailable,
            "Cannot bind protected control pipe",
        )
    })?;
    #[cfg(unix)]
    crate::lifetime::DaemonLease::acquire().await?;
    let recovery = tokio::task::spawn_blocking(worker::recover_all)
        .await
        .map_err(|_| Error::new(ErrorCode::RecoveryRequired, "Startup recovery task failed"))?;
    let recovery_error = match recovery {
        Ok(warnings) if warnings.is_empty() => None,
        Ok(warnings) => Some(worker::recovery_warning(warnings)),
        Err(error) => Some(worker::recovery_warning(vec![error])),
    };
    let capabilities = tokio::task::spawn_blocking(|| ocvpn_engine::Engine::load()?.capabilities())
        .await
        .map_err(|_| {
            Error::new(
                ErrorCode::EngineUnavailable,
                "Native discovery worker failed",
            )
        })??;
    let (events, _) = broadcast::channel(256);
    let service = Arc::new(Service {
        events,
        capabilities,
        recovery: Arc::new(Mutex::new(())),
        state: Mutex::new(Session {
            snapshot: Snapshot {
                service_instance_id: Uuid::new_v4(),
                sequence: 0,
                state: State::Disconnected,
                profile_id: None,
                profile_name: None,
                attempt_id: None,
                session_id: None,
                started_at: None,
                network: None,
                traffic: TrafficCounters::default(),
                last_error: recovery_error.clone(),
            },
            slot: None,
            last_owner: None,
            logs: VecDeque::new(),
            recovery_blocked: recovery_error.is_some(),
            quiescence_blocked: false,
            stopping: false,
        }),
    });
    let mut lease_tick = tokio::time::interval(Duration::from_secs(1));
    let mut connections = tokio::task::JoinSet::new();
    ready()?;
    loop {
        tokio::select! {
            changed = stop.changed() => { if changed.is_err() || *stop.borrow() { break; } },
            _ = lease_tick.tick() => { let mut state = service.state.lock().await; if state.slot.as_ref().is_some_and(|slot| slot.cancel.is_none() && slot.lease.elapsed() >= Duration::from_secs(300)) { state.cancel(&service.events); } },
            incoming = accept(&mut listener), if connections.len() < 128 => {
                if let Ok(stream) = incoming { let service = service.clone(); connections.spawn(async move { let _ = authenticated_connection(stream, service).await; }); }
            },
            _ = connections.join_next(), if !connections.is_empty() => {},
        }
    }
    {
        let mut state = service.state.lock().await;
        state.stopping = true;
        state.cancel(&service.events);
    }
    // Supervisor itself escalates only its owned process after ten seconds and
    // runs recovery before releasing the slot. Never kill an unverified PID.
    loop {
        if service.state.lock().await.slot.is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
#[cfg(unix)]
async fn accept(
    listener: &mut tokio::net::UnixListener,
) -> std::io::Result<tokio::net::UnixStream> {
    listener.accept().await.map(|(stream, _)| stream)
}
#[cfg(windows)]
async fn accept(
    listener: &mut crate::windows::ControlListener,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    listener.accept().await
}
#[cfg(unix)]
async fn authenticated_connection(
    stream: tokio::net::UnixStream,
    service: Arc<Service>,
) -> Result<()> {
    let peer = crate::unix::peer_identity(&stream).map_err(|_| {
        Error::new(
            ErrorCode::AuthorizationDenied,
            "Cannot authenticate control peer",
        )
    })?;
    connection(stream, peer, service, false).await
}
#[cfg(windows)]
async fn authenticated_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    service: Arc<Service>,
) -> Result<()> {
    timeout(
        Duration::from_secs(10),
        ipc::read_frame::<_, Hello>(&mut stream),
    )
    .await
    .map_err(|_| Error::new(ErrorCode::ProtocolViolation, "IPC hello timed out"))??
    .validate()?;
    let peer = crate::windows::peer_identity(&stream).map_err(|_| {
        Error::new(
            ErrorCode::AuthorizationDenied,
            "Cannot authenticate control peer",
        )
    })?;
    connection(stream, peer, service, true).await
}
async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: PeerIdentity,
    service: Arc<Service>,
    hello_read: bool,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
    let result = connection_inner(&mut stream, &peer, &service, connection_id, hello_read).await;
    let mut state = service.state.lock().await;
    if state.slot.as_ref().is_some_and(|slot| {
        slot.connection == connection_id
            && matches!(
                state.snapshot.state,
                State::Authenticating | State::Connecting
            )
    }) {
        state.cancel(&service.events);
    }
    result
}
async fn connection_inner<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    peer: &PeerIdentity,
    service: &Arc<Service>,
    connection_id: Uuid,
    hello_read: bool,
) -> Result<()> {
    if !hello_read {
        timeout(Duration::from_secs(10), ipc::read_frame::<_, Hello>(stream))
            .await
            .map_err(|_| Error::new(ErrorCode::ProtocolViolation, "IPC hello timed out"))??
            .validate()?;
    }
    ipc::write_frame(
        stream,
        &Hello {
            version: ipc::VERSION,
        },
    )
    .await?;
    loop {
        let request: Request = ipc::read_frame(stream).await?;
        let follow = matches!(
            &request.method,
            Method::Subscribe | Method::Logs { follow: true }
        );
        let log_stream = matches!(&request.method, Method::Logs { follow: true });
        let mut events = service.events.subscribe();
        let result = dispatch(service, peer, connection_id, request.method).await;
        let accepted = result.is_ok();
        timeout(
            Duration::from_secs(10),
            ipc::write_frame(
                stream,
                &Response {
                    request_id: request.request_id,
                    result,
                },
            ),
        )
        .await
        .map_err(|_| Error::new(ErrorCode::ServiceUnavailable, "Slow control client"))??;
        if follow && accepted {
            loop {
                let event = match events.recv().await {
                    Ok((owner, event)) => {
                        service.state.lock().await.authorize(peer)?;
                        if owner.as_ref().is_some_and(|owner| owner != peer) {
                            return Err(busy());
                        }
                        event
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if log_stream {
                            return Err(Error::new(
                                ErrorCode::ServiceUnavailable,
                                "Log subscription fell behind; reconnect to reload recent records",
                            ));
                        }
                        let state = service.state.lock().await;
                        state.authorize(peer)?;
                        Event {
                            service_instance_id: state.snapshot.service_instance_id,
                            sequence: state.snapshot.sequence,
                            payload: EventPayload::Snapshot(state.visible(peer)),
                        }
                    }
                    Err(_) => return Ok(()),
                };
                timeout(Duration::from_secs(10), ipc::write_frame(stream, &event))
                    .await
                    .map_err(|_| {
                        Error::new(ErrorCode::ServiceUnavailable, "Slow event subscriber")
                    })??;
            }
        }
    }
}
async fn dispatch(
    service: &Arc<Service>,
    peer: &PeerIdentity,
    connection_id: Uuid,
    method: Method,
) -> Result<Payload> {
    if let Method::AdminQuiesce { authorization } = method {
        #[cfg(unix)]
        let root = peer.uid() == 0;
        #[cfg(windows)]
        let root = false; // Windows installer uses SCM, not this endpoint.
        if !root {
            #[cfg(target_os = "macos")]
            {
                let token = authorization.ok_or_else(|| {
                    Error::new(
                        ErrorCode::AuthorizationDenied,
                        "Native administrator authorization is required",
                    )
                })?;
                tokio::task::spawn_blocking(move || crate::installation::authorize_quiesce(&token))
                    .await
                    .map_err(|_| {
                        Error::new(
                            ErrorCode::AuthorizationDenied,
                            "Native authorization verification failed",
                        )
                    })??;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = authorization;
                return Err(Error::new(
                    ErrorCode::AuthorizationDenied,
                    "Administrator service control is unavailable on this connection",
                ));
            }
        }
        return quiesce(service).await;
    }
    let mut state = service.state.lock().await;
    state.authorize(peer)?;
    match method {
        Method::Capabilities => Ok(Payload::Capabilities(service.capabilities.clone())),
        Method::Snapshot | Method::Subscribe => Ok(Payload::Snapshot(state.visible(peer))),
        Method::Logs { .. } => Ok(Payload::Logs(
            if state.last_owner.as_ref().is_none_or(|owner| owner == peer) {
                state.logs.iter().cloned().collect()
            } else {
                Vec::new()
            },
        )),
        Method::Reserve {
            profile_id,
            profile_name,
            protocol,
        } => {
            if state.stopping {
                return Err(Error::new(
                    ErrorCode::ServiceUnavailable,
                    "Service is stopping",
                ));
            }
            if state.recovery_blocked {
                return Err(Error::new(
                    ErrorCode::RecoveryRequired,
                    "Repair pending network recovery before connecting",
                ));
            }
            if state.slot.is_some() {
                return Err(busy());
            }
            if profile_id.is_nil()
                || profile_name.trim().is_empty()
                || profile_name.len() > 256
                || profile_name.chars().any(char::is_control)
            {
                return Err(Error::invalid("Invalid reservation profile"));
            }
            if !service
                .capabilities
                .protocols
                .iter()
                .any(|p| p.id == protocol)
            {
                return Err(Error::new(
                    ErrorCode::UnsupportedProtocol,
                    "Protocol unavailable in installed engine",
                ));
            }
            let attempt = Uuid::new_v4();
            state.logs.clear();
            state.last_owner = Some(peer.clone());
            state.snapshot.state = State::Authenticating;
            state.snapshot.profile_id = Some(profile_id);
            state.snapshot.profile_name = Some(profile_name);
            state.snapshot.attempt_id = Some(attempt);
            state.snapshot.session_id = None;
            state.snapshot.started_at = None;
            state.snapshot.network = None;
            state.snapshot.traffic = TrafficCounters::default();
            state.snapshot.last_error = None;
            state.slot = Some(Slot {
                owner: peer.clone(),
                connection: connection_id,
                attempt,
                protocol,
                lease: Instant::now(),
                cancel: None,
            });
            state.publish(
                &service.events,
                Some(("Authentication reservation created", LogLevel::Info)),
            );
            Ok(Payload::Reserved {
                attempt_id: attempt,
            })
        }
        Method::Start {
            attempt_id,
            handoff,
        } => {
            let slot = state
                .slot
                .as_ref()
                .ok_or_else(|| Error::new(ErrorCode::Conflict, "No current reservation"))?;
            if slot.attempt != attempt_id
                || slot.connection != connection_id
                || slot.cancel.is_some()
                || slot.lease.elapsed() >= Duration::from_secs(300)
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "Authentication reservation is no longer current",
                ));
            }
            if slot.protocol != handoff.protocol {
                return Err(Error::invalid(
                    "Handoff protocol does not match reservation",
                ));
            }
            handoff.validate(&service.capabilities.protocols, now())?;
            let transaction = ocvpn_net::TransactionId {
                service_instance_id: state.snapshot.service_instance_id,
                attempt_id,
            };
            let (cancel, cancelled) = mpsc::channel(1);
            let (updates, mut receiver) = mpsc::channel(32);
            state.slot.as_mut().expect("validated slot").cancel = Some(cancel);
            state.snapshot.state = State::Connecting;
            state.publish(
                &service.events,
                Some(("Starting authenticated tunnel", LogLevel::Info)),
            );
            let supervisor =
                tokio::spawn(worker::supervise(transaction, handoff, cancelled, updates));
            let service = service.clone();
            tokio::spawn(async move {
                while let Some(update) = receiver.recv().await {
                    let mut state = service.state.lock().await;
                    if state
                        .slot
                        .as_ref()
                        .is_none_or(|slot| slot.attempt != attempt_id)
                    {
                        break;
                    }
                    match update {
                        Update::Connected(network)
                            if state.snapshot.state != State::Disconnecting =>
                        {
                            state.snapshot.network = Some(network);
                            state.snapshot.state = State::Connected;
                            if state.snapshot.session_id.is_none() {
                                state.snapshot.session_id = Some(Uuid::new_v4());
                                state.snapshot.started_at = Some(now());
                            }
                            state.publish(
                                &service.events,
                                Some(("Tunnel and network configuration verified", LogLevel::Info)),
                            );
                        }
                        Update::Reconnecting if state.snapshot.state != State::Disconnecting => {
                            state.snapshot.state = State::Reconnecting;
                            state.publish(
                                &service.events,
                                Some(("Native tunnel reconnecting", LogLevel::Info)),
                            );
                        }
                        Update::Traffic(traffic) => {
                            state.snapshot.traffic = traffic;
                            state.publish(&service.events, None);
                        }
                        Update::Finished { result, quiescent } => {
                            state.slot = None;
                            state.snapshot.network = None;
                            state.quiescence_blocked = !quiescent;
                            match result {
                                Ok(()) => {
                                    state.snapshot.state = State::Disconnected;
                                    state.snapshot.last_error = None;
                                }
                                Err(e) => {
                                    state.recovery_blocked = e.code == ErrorCode::RecoveryRequired;
                                    state.snapshot.state =
                                        if e.code == ErrorCode::AuthenticationRequired {
                                            State::AuthenticationRequired
                                        } else {
                                            State::Failed
                                        };
                                    state.snapshot.last_error = Some(e);
                                }
                            }
                            let message = if !quiescent {
                                "Tunnel termination is uncertain; network journal retained"
                            } else if state.recovery_blocked {
                                "Tunnel stopped; network recovery requires repair"
                            } else {
                                "Tunnel stopped"
                            };
                            state.publish(&service.events, Some((message, LogLevel::Info)));
                            break;
                        }
                        _ => {}
                    }
                }
                let _ = supervisor.await;
                let mut state = service.state.lock().await;
                if state
                    .slot
                    .as_ref()
                    .is_some_and(|slot| slot.attempt == attempt_id)
                {
                    state.slot = None;
                    state.recovery_blocked = true;
                    state.snapshot.state = State::Failed;
                    state.snapshot.network = None;
                    state.quiescence_blocked = true;
                    state.snapshot.last_error = Some(Error::new(
                        ErrorCode::RecoveryRequired,
                        "Tunnel supervisor stopped unexpectedly; journal retained for safe repair",
                    ));
                    state.publish(
                        &service.events,
                        Some(("Tunnel supervisor failed; repair required", LogLevel::Error)),
                    );
                }
            });
            Ok(Payload::Accepted)
        }
        Method::AuthProgress { attempt_id } => {
            if state.snapshot.state != State::Authenticating {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "Authentication is no longer pending",
                ));
            }
            let slot = state
                .slot
                .as_mut()
                .ok_or_else(|| Error::new(ErrorCode::Conflict, "No authentication reservation"))?;
            if slot.attempt != attempt_id
                || slot.connection != connection_id
                || slot.lease.elapsed() >= Duration::from_secs(300)
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "Authentication reservation is no longer current",
                ));
            }
            slot.lease = Instant::now();
            Ok(Payload::Accepted)
        }
        Method::Cancel { attempt_id } => {
            if let Some(slot) = &state.slot {
                if slot.attempt != attempt_id {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "Cancellation does not own the current attempt",
                    ));
                }
            }
            // OS identity was authorized above. An attempt-scoped cancellation
            // can recover an uncertain Start reply without racing a new session.
            state.cancel(&service.events);
            Ok(Payload::Accepted)
        }
        Method::Disconnect => {
            if state.slot.as_ref().is_some_and(|slot| {
                slot.connection != connection_id
                    && matches!(
                        state.snapshot.state,
                        State::Authenticating | State::Connecting
                    )
            }) {
                return Err(busy());
            }
            state.cancel(&service.events);
            Ok(Payload::Accepted)
        }
        Method::AdminQuiesce { .. } => Err(Error::new(
            ErrorCode::AuthorizationDenied,
            "Invalid administrative dispatch",
        )),
    }
}

async fn quiesce(service: &Arc<Service>) -> Result<Payload> {
    // Move this owned guard into the blocking recovery task: a client timeout
    // must not release serialization while that task still mutates journals.
    let recovery_guard = timeout(
        Duration::from_secs(180),
        service.recovery.clone().lock_owned(),
    )
    .await
    .map_err(|_| {
        Error::new(
            ErrorCode::RecoveryRequired,
            "Administrative recovery is already in progress",
        )
    })?;
    {
        let mut state = service.state.lock().await;
        state.stopping = true;
        state.cancel(&service.events);
    }
    timeout(Duration::from_secs(180), async {
        loop {
            {
                let state = service.state.lock().await;
                if state.slot.is_none() {
                    if state.quiescence_blocked { return Err(Error::new(ErrorCode::RecoveryRequired, "Owned process quiescence is uncertain; establish termination before uninstalling")); }
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let warnings = tokio::task::spawn_blocking(move || {
            let _guard = recovery_guard;
            worker::recover_all()
        }).await
            .map_err(|_| Error::new(ErrorCode::RecoveryRequired, "Administrative recovery task failed"))??;
        if !warnings.is_empty() { return Err(worker::recovery_warning(warnings)); }
        let mut state = service.state.lock().await;
        state.recovery_blocked = false;
        state.snapshot.last_error = None;
        Ok(Payload::Accepted)
    }).await.map_err(|_| Error::new(ErrorCode::RecoveryRequired, "Administrative teardown timed out; service remains quiesced and installation is retained"))?
}
