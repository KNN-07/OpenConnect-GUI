use ocvpn_engine::{Engine, tunnel::TunnelEvent};
use ocvpn_model::{
    AuthHandoff, Error, ErrorCode, NetworkObservation, NetworkReason, Result, TrafficCounters,
    ipc::{read_frame, write_frame},
};
use ocvpn_net::{TransactionId, monitor::Monitor};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    process::Command,
    sync::mpsc,
    time::{interval, timeout},
};
use uuid::Uuid;
struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize, Deserialize)]
struct Start {
    service_instance_id: Uuid,
    attempt_id: Uuid,
    handoff: AuthHandoff,
}
#[derive(Serialize, Deserialize)]
enum CommandMessage {
    Cancel,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum Update {
    Connected(NetworkObservation),
    Reconnecting,
    Traffic(TrafficCounters),
    Finished { result: Result<()>, quiescent: bool },
}
pub(crate) fn installed_worker() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok("/usr/libexec/openconnect-gui/ocvpnd".into())
    }
    #[cfg(target_os = "macos")]
    {
        Ok("/Applications/OpenConnect GUI.app/Contents/MacOS/ocvpnd".into())
    }
    #[cfg(windows)]
    {
        Ok(ocvpn_engine::installed_native_directory()?
            .parent()
            .ok_or_else(|| error("Invalid installation"))?
            .join("ocvpnd.exe"))
    }
}
fn error(message: &str) -> Error {
    Error::new(ErrorCode::ServiceUnavailable, message)
}
pub(crate) fn recovery_warning(warnings: Vec<Error>) -> Error {
    let mut error = Error::new(
        ErrorCode::RecoveryRequired,
        "Network recovery requires repair before reconnecting",
    );
    error.details = Some(
        warnings
            .iter()
            .take(32)
            .map(|warning| {
                let mut detail: String = warning
                    .message
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(512)
                    .collect();
                if let Some(value) = &warning.details {
                    detail.push_str(": ");
                    detail.extend(value.chars().filter(|c| !c.is_control()).take(512));
                }
                detail
            })
            .collect::<Vec<_>>()
            .join("; "),
    );
    error
}
pub(crate) fn recover_all() -> Result<Vec<Error>> {
    #[cfg(unix)]
    {
        crate::lifetime::recover(ocvpn_net::recover_all)
    }
    #[cfg(windows)]
    {
        ocvpn_net::recover_all()
    }
}
pub(crate) async fn supervise(
    transaction: TransactionId,
    handoff: AuthHandoff,
    mut cancel: mpsc::Receiver<()>,
    updates: mpsc::Sender<Update>,
) {
    let mut quiescent = true;
    let result = supervise_inner(transaction, handoff, &mut cancel, &updates, &mut quiescent).await;
    // Uncertain live descendants must never race journal restoration.
    if !quiescent {
        let result = Err(Error::new(
            ErrorCode::RecoveryRequired,
            "Owned worker quiescence is uncertain; network journal retained",
        ));
        let _ = updates
            .send(Update::Finished {
                result,
                quiescent: false,
            })
            .await;
        return;
    }
    // Recover only after the complete owned process tree is quiescent.
    let recovery = tokio::task::spawn_blocking(move || {
        #[cfg(unix)]
        {
            crate::lifetime::recover(|| ocvpn_net::recover(transaction))
        }
        #[cfg(windows)]
        {
            ocvpn_net::recover(transaction)
        }
    })
    .await;
    let result = match recovery {
        Ok(Ok(warnings)) if warnings.is_empty() => result,
        Ok(Ok(warnings)) => Err(recovery_warning(warnings)),
        Ok(Err(error)) => Err(recovery_warning(vec![error])),
        Err(_) => Err(Error::new(
            ErrorCode::RecoveryRequired,
            "Network recovery worker failed; repair before reconnecting",
        )),
    };
    let _ = updates
        .send(Update::Finished {
            result,
            quiescent: true,
        })
        .await;
}
async fn supervise_inner(
    transaction: TransactionId,
    handoff: AuthHandoff,
    cancel: &mut mpsc::Receiver<()>,
    updates: &mpsc::Sender<Update>,
    quiescent: &mut bool,
) -> Result<()> {
    let worker = installed_worker()?;
    crate::trust::installed_file(&worker)?;
    crate::trust::installed_file(&ocvpn_engine::tunnel::installed_helper()?)?;
    #[cfg(windows)]
    crate::trust::installed_file(&worker.with_file_name("wintun.dll"))?;
    let mut command = Command::new(worker);
    command
        .arg("--worker")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(unix)]
    let lifetime = crate::lifetime::WorkerLease::prepare(&mut command)?;
    let mut child = command
        .spawn()
        .map_err(|_| error("Cannot launch installed private tunnel worker"))?;
    *quiescent = false;
    #[cfg(unix)]
    let process_tree = crate::process_tree::OwnedTree::attach(&child, lifetime.spawned())?;
    #[cfg(windows)]
    let process_tree = crate::process_tree::OwnedTree::attach(&child)?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| error("Missing private worker input"))?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| error("Missing private worker output"))?;
    // ChildStdin/Stdout are inherited anonymous pipes. No listener or wire-selected
    // descriptor exists, and no authentication secret enters argv/environment.
    let start = Start {
        service_instance_id: transaction.service_instance_id,
        attempt_id: transaction.attempt_id,
        handoff,
    };
    if !matches!(
        timeout(Duration::from_secs(10), write_frame(&mut input, &start)).await,
        Ok(Ok(()))
    ) {
        terminate_worker(&process_tree, &mut child).await?;
        process_tree.wait_quiet().await?;
        *quiescent = true;
        return Err(error("Private worker handoff failed"));
    }
    drop(start);
    let (tx, mut rx) = mpsc::channel(32);
    let reader = tokio::spawn(async move {
        let mut output = output;
        loop {
            let update = read_frame::<_, Update>(&mut output).await;
            let end = update.is_err() || matches!(&update, Ok(Update::Finished { .. }));
            if tx.send(update).await.is_err() || end {
                break;
            }
        }
    });
    let _reader_guard = AbortOnDrop(reader.abort_handle());
    let mut terminal = None;
    let mut stopping = false;
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    let result = loop {
        tokio::select! {
            _ = cancel.recv(), if !stopping => { stopping = true; deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10)); let _ = timeout(Duration::from_secs(1), write_frame(&mut input, &CommandMessage::Cancel)).await; }
            _ = &mut deadline, if stopping => { terminate_worker(&process_tree, &mut child).await?; break terminal.unwrap_or(Ok(())); }
            update = rx.recv(), if terminal.is_none() => match update {
                Some(Ok(Update::Finished { result, .. })) => { terminal = Some(result); stopping = true; deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10)); },
                Some(Ok(update)) => { if updates.send(update).await.is_err() { stopping = true; deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10)); let _ = timeout(Duration::from_secs(1), write_frame(&mut input, &CommandMessage::Cancel)).await; } },
                _ => { terminal = Some(Err(error("Private tunnel worker channel closed unexpectedly"))); stopping = true; deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10)); let _ = timeout(Duration::from_secs(1), write_frame(&mut input, &CommandMessage::Cancel)).await; }
            },
            status = child.wait() => {
                // The final frame can still be buffered when the process exits.
                if terminal.is_none() {
                    if let Ok(Some(result)) = timeout(Duration::from_secs(1), async {
                        while let Some(update) = rx.recv().await { match update { Ok(Update::Finished { result, .. }) => return Some(result), Ok(_) => {}, Err(_) => break } }
                        None
                    }).await { terminal = Some(result); }
                }
                break match (status, terminal) { (Ok(_), Some(result)) => result, _ => Err(error("Private tunnel worker exited unexpectedly")) };
            }
        }
    };
    reader.abort();
    let _ = reader.await;
    process_tree.wait_quiet().await?;
    *quiescent = true;
    result
}
async fn terminate_worker(
    tree: &crate::process_tree::OwnedTree,
    child: &mut tokio::process::Child,
) -> Result<()> {
    tree.terminate().map_err(|_| {
        Error::new(
            ErrorCode::RecoveryRequired,
            "Cannot terminate owned worker tree; network journal retained",
        )
    })?;
    timeout(Duration::from_secs(10), child.wait())
        .await
        .map_err(|_| {
            Error::new(
                ErrorCode::RecoveryRequired,
                "Owned worker exit timed out; network journal retained",
            )
        })?
        .map_err(|_| {
            Error::new(
                ErrorCode::RecoveryRequired,
                "Cannot establish owned worker exit; network journal retained",
            )
        })?;
    Ok(())
}
/// Internal mode consumes only inherited standard pipes, never the control IPC.
pub async fn run() -> Result<()> {
    crate::trust::worker_process()?;
    #[cfg(unix)]
    for fd in [0, 1] {
        // The handoff/control pipes belong only to this worker, not native
        // script descendants. Lifetime lease descriptors alone cross exec.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(error("Cannot protect private worker channel descriptors"));
        }
    }
    let result = run_channel(tokio::io::stdin(), tokio::io::stdout()).await;
    // On a failed private channel, native cancellation may still be inside a
    // helper. This verified worker is its own Unix process-group leader.
    #[cfg(unix)]
    if result.is_err() {
        unsafe {
            libc::kill(-libc::getpid(), libc::SIGKILL);
        }
    }
    result
}
async fn run_channel<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin>(
    mut input: R,
    mut output: W,
) -> Result<()> {
    let start: Start = timeout(Duration::from_secs(10), read_frame(&mut input))
        .await
        .map_err(|_| error("Missing inherited worker handoff"))??;
    if start.service_instance_id.is_nil() || start.attempt_id.is_nil() {
        return Err(Error::invalid("Invalid private worker transaction"));
    }
    let transaction = TransactionId {
        service_instance_id: start.service_instance_id,
        attempt_id: start.attempt_id,
    };
    let mut monitor = Monitor::bind(transaction).await?;
    let engine = tokio::task::spawn_blocking(Engine::load)
        .await
        .map_err(|_| error("Native loader failed"))??;
    crate::trust::installed_file(&ocvpn_engine::tunnel::installed_helper()?)?;
    let task = engine.tunnel(start.handoff, monitor.environment())?;
    let (reports_tx, mut reports) = mpsc::channel(16);
    let monitor_task = tokio::spawn(async move {
        loop {
            let report = monitor.recv().await;
            let failed = report.is_err();
            if reports_tx.send(report).await.is_err() || failed {
                break;
            }
        }
    });
    let _monitor_guard = AbortOnDrop(monitor_task.abort_handle());
    let control = task.control();
    let cancel_control = control.clone();
    let input_task = tokio::spawn(async move {
        let _ = read_frame::<_, CommandMessage>(&mut input).await;
        cancel_control.cancel();
        // EOF also means the supervisor died. Independently bound native/helper
        // cleanup so Unix descendants cannot outlive the private worker forever.
        tokio::time::sleep(Duration::from_secs(10)).await;
        #[cfg(unix)]
        unsafe {
            libc::kill(-libc::getpid(), libc::SIGKILL);
        }
        #[cfg(windows)]
        std::process::exit(1);
    });
    let _input_guard = AbortOnDrop(input_task.abort_handle());
    let mut tick = interval(Duration::from_secs(1));
    let mut native_ready = false;
    let mut reconnecting = false;
    let mut native_reconnected = false;
    let mut observation: Option<NetworkObservation> = None;
    let mut connected = false;
    let mut failure = None;
    let mut transport = String::new();
    loop {
        tokio::select! {
            _ = tick.tick() => { control.request_statistics(); },
            report = reports.recv(), if !reports.is_closed() || !reports.is_empty() => {
                match report.unwrap_or_else(|| Err(error("Network monitor stopped"))) {
                    Ok(report) if report.transaction.service_instance_id == transaction.service_instance_id && report.transaction.attempt_id == transaction.attempt_id => match report.result {
                        Err(e) => { failure = Some(e); control.cancel(); },
                        Ok(value) => match report.reason {
                            NetworkReason::AttemptReconnect => { reconnecting = true; connected = false; observation = None; write_frame(&mut output, &Update::Reconnecting).await?; },
                            NetworkReason::Connect if !reconnecting => { observation = value; },
                            NetworkReason::Reconnect if reconnecting => { observation = value; },
                            NetworkReason::Connect | NetworkReason::Reconnect => { failure = Some(error("Unexpected network lifecycle order")); control.cancel(); },
                            NetworkReason::Disconnect | NetworkReason::PreInit => {},
                        }
                    },
                    Ok(_) => { failure = Some(error("Network helper transaction mismatch")); control.cancel(); },
                    Err(e) => { failure = Some(e); control.cancel(); }
                }
            }
        }
        while let Some(event) = task.try_recv()? {
            match event {
                TunnelEvent::Statistics {
                    traffic,
                    tun_ready,
                    transport: actual,
                } => {
                    native_ready = tun_ready;
                    transport = actual;
                    write_frame(&mut output, &Update::Traffic(traffic)).await?;
                }
                TunnelEvent::Reconnected => {
                    native_reconnected = true;
                }
                TunnelEvent::Finished(result) => {
                    input_task.abort();
                    monitor_task.abort();
                    let _ = input_task.await;
                    let _ = monitor_task.await;
                    let result = failure.map_or(result, Err);
                    write_frame(
                        &mut output,
                        &Update::Finished {
                            result: result.clone(),
                            quiescent: false,
                        },
                    )
                    .await?;
                    return result;
                }
            }
        }
        if !connected && failure.is_none() && native_ready && (!reconnecting || native_reconnected)
        {
            if let Some(mut network) = observation.take() {
                network.transport = transport.clone();
                write_frame(&mut output, &Update::Connected(network)).await?;
                connected = true;
                reconnecting = false;
                native_reconnected = false;
            }
        }
        if reports.is_closed() && failure.is_none() {
            failure = Some(error("Network monitor stopped"));
            control.cancel();
        }
    }
}
