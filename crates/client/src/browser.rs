//! One user-owned browser transaction. Only safe prompt metadata leaves Rust.
use crate::{
    browser_bootstrap, browser_os,
    browser_transport::{self, BrowserIo, UserConnection, UserListener},
    globalprotect::{self, GpCompletion},
    private_fs,
};
use ocvpn_engine::{Engine, auth::AuthControl as NativeControl};
use ocvpn_model::{
    BrowserClientMessage as Incoming, BrowserHello, BrowserMode, BrowserPage, BrowserPeerRole,
    BrowserPrompt, BrowserReply, BrowserRequest, BrowserServerMessage as Outgoing, BrowserStage,
    Error, ErrorCode, MAX_BROWSER_BYTES, NativeBrowserKind, Result, SecretText,
    ipc::{read_frame, write_frame},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc as blocking},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::WriteHalf,
    process::Child,
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use uuid::Uuid;

pub(crate) const DEADLINE: Duration = Duration::from_secs(300);
const IO_DEADLINE: Duration = Duration::from_secs(5);
fn stale() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "Browser transaction is no longer current",
    )
}
fn unavailable() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "Browser authentication is unavailable; retry with an installed desktop/display, system browser, or manual mode",
    )
}
fn cancelled() -> Error {
    Error::new(ErrorCode::Cancelled, "Browser authentication was cancelled")
}
fn pin_limit() -> Error {
    Error::new(
        ErrorCode::UnsupportedAuthentication,
        "Embedded SSO cannot enforce explicit certificate pins before sending credentials. Choose system/manual mode explicitly, or provision the organization CA and remove the conflicting pin. Native VPN pins remain strict.",
    )
}
fn recovery() -> Error {
    Error::new(
        ErrorCode::RecoveryRequired,
        "Authentication processes did not finish closing. Close remaining authentication windows before retrying; private data was retained rather than removed while in use.",
    )
}

pub fn create_ephemeral_directory(transaction_id: Uuid) -> Result<PathBuf> {
    if transaction_id.is_nil() {
        return Err(Error::invalid("Browser transaction ID is required"));
    }
    let parent = browser_transport::runtime_directory()?.join("profiles");
    private_fs::ensure_private_directory(&parent)?;
    let path = parent.join(transaction_id.to_string());
    if fs::symlink_metadata(&path).is_ok() {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Browser profile already exists; start a fresh transaction",
        ));
    }
    private_fs::ensure_private_directory(&path)?;
    Ok(path)
}
pub fn remove_ephemeral_directory(transaction_id: Uuid) -> Result<()> {
    if transaction_id.is_nil() {
        return Err(Error::invalid("Browser transaction ID is required"));
    }
    let path = browser_transport::runtime_directory()?
        .join("profiles")
        .join(transaction_id.to_string());
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(unavailable()),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(Error::new(
                ErrorCode::AuthorizationDenied,
                "Browser profile ownership is invalid",
            ));
        }
        Ok(_) => {}
    }
    private_fs::ensure_private_directory(&path)?;
    fs::remove_dir_all(path).map_err(|_| Error::new(ErrorCode::RecoveryRequired, "Private browser data could not be removed after closure; close the authentication process and retry cleanup"))
}

/// OS callback receiver entrypoint. No browser request or credential is printed.
pub async fn submit_callback(uri: SecretText) -> Result<()> {
    globalprotect::decode_callback(uri.as_str())?;
    timeout(IO_DEADLINE, async {
        let mut connection = browser_transport::connect().await?;
        write_frame(
            &mut connection.stream,
            &BrowserHello {
                version: 1,
                role: BrowserPeerRole::Callback,
            },
        )
        .await?;
        write_frame(&mut connection.stream, &Incoming::Callback { uri }).await?;
        match read_frame::<_, Outgoing>(&mut connection.stream).await? {
            Outgoing::Accepted => Ok(()),
            Outgoing::Error { error } => Err(Error::new(
                error.code,
                "Callback was rejected by the current authentication transaction",
            )),
            _ => Err(stale()),
        }
    })
    .await
    .map_err(|_| unavailable())?
}

pub(crate) enum Notice {
    Prompt(BrowserPrompt),
    Failed(Error),
}
enum Command {
    Callback(SecretText, blocking::SyncSender<Result<()>>),
    Confirm(bool, blocking::SyncSender<Result<()>>),
}
#[derive(Clone)]
pub(crate) struct Control {
    id: Uuid,
    commands: mpsc::Sender<Command>,
    stop: watch::Sender<bool>,
    manual: Arc<Mutex<Option<SecretText>>>,
}
impl Control {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn cancel(&self) {
        self.stop.send_replace(true);
        if let Ok(mut value) = self.manual.lock() {
            *value = None;
        }
    }
    pub fn manual_url(&self) -> Result<SecretText> {
        if *self.stop.borrow() {
            return Err(stale());
        }
        self.manual
            .lock()
            .map_err(|_| stale())?
            .as_ref()
            .map(|v| SecretText::new(v.as_str().to_owned()))
            .ok_or_else(stale)
    }
    /// Blocking acknowledgement: dispatch off UI/async threads, as with certificate replies.
    pub fn callback(&self, uri: SecretText) -> Result<()> {
        if uri.as_str().len() > MAX_BROWSER_BYTES || *self.stop.borrow() {
            return Err(stale());
        }
        let (tx, rx) = blocking::sync_channel(1);
        self.commands
            .try_send(Command::Callback(uri, tx))
            .map_err(|_| stale())?;
        rx.recv_timeout(IO_DEADLINE).map_err(|_| stale())?
    }
    pub fn confirm(&self, accepted: bool) -> Result<()> {
        if *self.stop.borrow() {
            return Err(stale());
        }
        let (tx, rx) = blocking::sync_channel(1);
        self.commands
            .try_send(Command::Confirm(accepted, tx))
            .map_err(|_| stale())?;
        rx.recv_timeout(IO_DEADLINE).map_err(|_| stale())?
    }
}
pub(crate) struct Task {
    control: Control,
    notices: blocking::Receiver<Notice>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl Task {
    pub fn start(
        engine: Engine,
        request: BrowserRequest,
        native: NativeControl,
        gui: Option<PathBuf>,
        wait: Duration,
    ) -> Result<Self> {
        request.validate()?;
        let (commands, receiver) = mpsc::channel(16);
        let (stop, stopping) = watch::channel(false);
        let (notices, events) = blocking::sync_channel(16);
        let control = Control {
            id: request.transaction_id,
            commands,
            stop,
            manual: Arc::new(Mutex::new(None)),
        };
        let owned = control.clone();
        let worker = thread::Builder::new()
            .name("ocvpn-browser".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match runtime {
                        Ok(runtime) => runtime.block_on(run(
                            engine,
                            request,
                            native.clone(),
                            receiver,
                            stopping,
                            owned.manual.clone(),
                            notices.clone(),
                            gui,
                            wait,
                        )),
                        Err(_) => Err(unavailable()),
                    }
                }))
                .unwrap_or_else(|_| Err(recovery()));
                if let Err(error) = &result {
                    let unexpected = !*owned.stop.borrow();
                    if unexpected || error.code == ErrorCode::RecoveryRequired {
                        let _ = notices.try_send(Notice::Failed(error.clone()));
                    }
                    if unexpected {
                        let _ = native.browser_reply(owned.id, BrowserReply::Failed(error.clone()));
                        native.cancel();
                    }
                }
                owned.cancel();
                result
            })
            .map_err(|_| unavailable())?;
        Ok(Self {
            control,
            notices: events,
            worker: Some(worker),
        })
    }
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    pub fn try_recv(&self) -> Option<Notice> {
        self.notices.try_recv().ok()
    }
    pub fn close(&mut self) -> Result<()> {
        self.control.cancel();
        if let Some(worker) = self.worker.take() {
            if let Err(error) = worker.join().map_err(|_| recovery())? {
                if error.code == ErrorCode::RecoveryRequired {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct Flow {
    request: Arc<BrowserRequest>,
    native: NativeControl,
    notices: blocking::SyncSender<Notice>,
    pending: Option<GpCompletion>,
    submitted: bool,
    opened: bool,
}
impl Flow {
    fn prompt(&self, stage: BrowserStage, account: Option<String>) -> Result<()> {
        self.notices
            .try_send(Notice::Prompt(BrowserPrompt {
                attempt_id: self.request.attempt_id,
                transaction_id: self.request.transaction_id,
                expected_origin: self.request.expected_origin.to_string(),
                phase: self.request.phase,
                mode: self.request.mode,
                stage,
                account,
            }))
            .map_err(|_| Error::new(ErrorCode::Busy, "Browser prompt consumer is not responding"))
    }
    fn opened(&mut self) -> Result<()> {
        if !self.opened && self.request.kind == NativeBrowserKind::External {
            self.native
                .browser_reply(self.request.transaction_id, BrowserReply::Opened)?;
        }
        self.opened = true;
        self.prompt(
            if self.request.mode == BrowserMode::Manual {
                BrowserStage::ManualInput
            } else {
                BrowserStage::Waiting
            },
            None,
        )
    }
    fn callback(&mut self, uri: SecretText) -> Result<()> {
        if self.request.protocol != "gp"
            || self.request.kind != NativeBrowserKind::Webview
            || self.request.mode == BrowserMode::Embedded
            || self.pending.is_some()
            || self.submitted
        {
            return Err(stale());
        }
        let decoded = globalprotect::decode_callback(uri.as_str())?;
        let completion = globalprotect::parse_completion(&decoded)?;
        self.confirmation(completion)
    }
    fn confirmation(&mut self, completion: GpCompletion) -> Result<()> {
        if completion.username.len() > 4096 {
            return Err(Error::invalid("Browser account name exceeds the limit"));
        }
        if self.request.mode != BrowserMode::Embedded {
            claim_completion(completion.cookie.as_str())?;
        }
        self.prompt(
            BrowserStage::ConfirmAccount,
            Some(completion.username.to_string()),
        )?;
        self.pending = Some(completion);
        Ok(())
    }
    fn confirm(&mut self, accepted: bool) -> Result<()> {
        let completion = self.pending.take().ok_or_else(stale)?;
        if !accepted {
            self.native.cancel();
            return Err(cancelled());
        }
        let page = BrowserPage {
            uri: SecretText::new(self.request.expected_origin.to_string()),
            cookies: Vec::new(),
            headers: vec![
                (
                    SecretText::new("saml-auth-status".into()),
                    SecretText::new("1".into()),
                ),
                (
                    SecretText::new("saml-username".into()),
                    SecretText(completion.username),
                ),
                (
                    SecretText::new(completion.cookie_name),
                    SecretText(completion.cookie),
                ),
            ],
            document: None,
        };
        self.native
            .browser_reply(self.request.transaction_id, BrowserReply::Page(page))?;
        self.submitted = true;
        self.prompt(BrowserStage::Waiting, None)
    }
    fn page(&mut self, mut page: BrowserPage) -> Result<()> {
        page.validate(&self.request.expected_origin)?;
        if self.request.kind == NativeBrowserKind::External
            || self.pending.is_some()
            || self.submitted
        {
            return Ok(());
        }
        if self.request.protocol == "gp" {
            if let Some(completion) = page_completion(&page)? {
                self.confirmation(completion)?;
            }
            // Never let native's permissive detector accumulate partial fields
            // across pages or accept a header token without successful SAML status.
            Ok(())
        } else {
            page.document = None;
            self.native
                .browser_reply(self.request.transaction_id, BrowserReply::Page(page))
        }
    }
}

struct Embedded {
    writer: WriteHalf<Box<dyn BrowserIo>>,
    reader: JoinHandle<()>,
}
impl Drop for Embedded {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
enum Peer {
    Embedded(UserConnection),
    Callback(UserConnection, SecretText),
}
async fn identify(mut connection: UserConnection) -> Result<Peer> {
    timeout(IO_DEADLINE, async {
        let hello: BrowserHello = read_frame(&mut connection.stream).await?;
        if hello.version != 1 {
            return Err(stale());
        }
        match hello.role {
            BrowserPeerRole::Embedded => Ok(Peer::Embedded(connection)),
            BrowserPeerRole::Callback => match read_frame(&mut connection.stream).await? {
                Incoming::Callback { uri } => Ok(Peer::Callback(connection, uri)),
                _ => Err(stale()),
            },
        }
    })
    .await
    .map_err(|_| unavailable())?
}
async fn send(writer: &mut (impl tokio::io::AsyncWrite + Unpin), message: &Outgoing) -> Result<()> {
    timeout(IO_DEADLINE, write_frame(writer, message))
        .await
        .map_err(|_| unavailable())?
}
async fn run(
    engine: Engine,
    mut request: BrowserRequest,
    native: NativeControl,
    mut commands: mpsc::Receiver<Command>,
    mut stopping: watch::Receiver<bool>,
    manual: Arc<Mutex<Option<SecretText>>>,
    notices: blocking::SyncSender<Notice>,
    gui: Option<PathBuf>,
    wait: Duration,
) -> Result<()> {
    let mut listener = UserListener::bind().await?;
    request.mode = match request.mode {
        BrowserMode::Auto
            if request.kind == NativeBrowserKind::External
                || (request.protocol == "gp" && request.external_allowed == Some(true)) =>
        {
            BrowserMode::System
        }
        BrowserMode::Auto => BrowserMode::Embedded,
        mode => mode,
    };
    if request.mode == BrowserMode::Embedded && !request.tls.pins.is_empty() {
        return Err(pin_limit());
    }
    if request.mode == BrowserMode::System
        && request.protocol == "gp"
        && !browser_os::callback_available().await?
    {
        return Err(Error::new(
            ErrorCode::AuthenticationRequired,
            "GlobalProtect callback association is absent or belongs to another application. Register it with explicit consent, or choose manual/embedded authentication. System browsers use their own CA trust.",
        ));
    }
    let mut bootstrap = browser_bootstrap::bind(request.uri.as_str()).await?;
    request.uri = SecretText::new(bootstrap.url.as_str().to_owned());
    if request.mode == BrowserMode::Manual {
        *manual.lock().map_err(|_| stale())? =
            Some(SecretText::new(bootstrap.url.as_str().to_owned()));
    }
    let request = Arc::new(request);
    let mut flow = Flow {
        request: request.clone(),
        native,
        notices,
        pending: None,
        submitted: false,
        opened: false,
    };
    flow.prompt(BrowserStage::Opening, None)?;
    let mut child = if request.mode == BrowserMode::Embedded {
        let executable = match gui {
            Some(path) => path,
            None => browser_os::installed_gui()?,
        };
        let mut command = tokio::process::Command::new(executable);
        command
            .arg("--auth-window")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            command.process_group(0);
        }
        Some(command.spawn().map_err(|_| unavailable())?)
    } else {
        None
    };
    #[cfg(unix)]
    let group = child.as_ref().and_then(Child::id);
    #[cfg(windows)]
    let process_tree = child
        .as_ref()
        .map(|child| {
            let handle = child.raw_handle().ok_or_else(unavailable)?;
            // The helper is blocked on Open, so no renderer can precede assignment.
            ocvpn_engine::process_tree::ProcessTree::attach(unsafe {
                std::os::windows::io::BorrowedHandle::borrow_raw(handle)
            })
        })
        .transpose()?;
    let launch_request = request.clone();
    let mut launch = if request.mode == BrowserMode::System {
        Some(tokio::spawn(async move {
            browser_os::launch(launch_request.uri.as_str()).await
        }))
    } else {
        None
    };
    if request.mode == BrowserMode::Manual {
        flow.opened()?;
    }
    let mut peers = JoinSet::new();
    let mut embedded: Option<Embedded> = None;
    let (messages, mut incoming) = mpsc::channel(16);
    let deadline = Instant::now() + wait;
    let mut bootstrap_done = false;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let result: Result<()> = async {
        loop {
            if *stopping.borrow() { return Ok(()); }
            tokio::select! {
                _ = stopping.changed() => return Ok(()),
                _ = tokio::time::sleep_until(deadline) => return Err(Error::new(ErrorCode::AuthenticationRequired, "Browser authentication timed out; start a fresh attempt")),
                result = &mut bootstrap.finished, if !bootstrap_done => {
                    result.map_err(|_| unavailable())??; bootstrap_done = true;
                }
                result = async { launch.as_mut().expect("guarded launch").await }, if launch.is_some() => {
                    result.map_err(|_| unavailable())??; launch = None; flow.opened()?;
                }
                _ = tick.tick() => {
                    if let Some(child) = child.as_mut() {
                        if child.try_wait().map_err(|_| unavailable())?.is_some() && embedded.is_none() { return Err(unavailable()); }
                    }
                }
                command = commands.recv() => match command {
                    Some(Command::Callback(uri, answer)) => { let result = flow.callback(uri); let _ = answer.try_send(result); }
                    Some(Command::Confirm(accepted, answer)) => {
                        let result = flow.confirm(accepted);
                        let cancelled = result.as_ref().err().is_some_and(|e| e.code == ErrorCode::Cancelled);
                        let _ = answer.try_send(result);
                        if cancelled { return Err(self::cancelled()); }
                    }
                    None => return Ok(()),
                },
                connection = listener.accept(), if peers.len() < 4 => {
                    // Identity failures reject only that peer, not the valid flow.
                    if let Ok(connection) = connection { peers.spawn(identify(connection)); }
                }
                peer = peers.join_next(), if !peers.is_empty() => {
                    match peer {
                        Some(Ok(Ok(Peer::Callback(mut connection, uri)))) => {
                            let reply = match flow.callback(uri) { Ok(()) => Outgoing::Accepted, Err(error) => Outgoing::Error { error } };
                            let _ = send(&mut connection.stream, &reply).await;
                        }
                        Some(Ok(Ok(Peer::Embedded(mut connection)))) => {
                            let owned_pid = child.as_ref().and_then(Child::id);
                            if child.is_none() || embedded.is_some() || connection.pid.zip(owned_pid).is_some_and(|(actual, expected)| actual != expected) {
                                let _ = send(&mut connection.stream, &Outgoing::Error { error: stale() }).await;
                                continue;
                            }
                            send(&mut connection.stream, &Outgoing::Open { request: request.clone() }).await?;
                            let (mut reader, writer) = tokio::io::split(connection.stream);
                            let messages = messages.clone();
                            let reader = tokio::spawn(async move {
                                loop {
                                    // read_frame is not cancellation-safe: only this reader owns
                                    // it, and it is aborted only when the entire connection closes.
                                    let message = read_frame::<_, Incoming>(&mut reader).await;
                                    let failed = message.is_err();
                                    if messages.send(message).await.is_err() || failed { break; }
                                }
                            });
                            embedded = Some(Embedded { writer, reader });
                        }
                        _ => {}
                    }
                }
                message = incoming.recv(), if embedded.is_some() => {
                    match message.ok_or_else(unavailable)?? {
                        Incoming::Ready { transaction_id } if transaction_id == request.transaction_id => flow.opened()?,
                        Incoming::Page { transaction_id, page } if transaction_id == request.transaction_id && flow.opened => flow.page(page)?,
                        Incoming::Certificate { challenge } if challenge.transaction_id == request.transaction_id => {
                            if challenge.challenge_id.is_nil() || ocvpn_model::https_origin(challenge.origin.as_str())? != challenge.origin { return Err(stale()); }
                            let verification = engine.verify_browser_chain(&challenge.origin, &challenge.chain, &request.tls)?;
                            let accept = verification.trusted && request.tls.pins.is_empty();
                            send(&mut embedded.as_mut().ok_or_else(stale)?.writer, &Outgoing::CertificateDecision { challenge_id: challenge.challenge_id, accept }).await?;
                            if !accept { return Err(Error::new(ErrorCode::CertificateRejected, "Embedded browser certificate is not trusted. Provision the organization CA or explicitly choose system/manual authentication; an unenforceable browser pin was not accepted.")); }
                        }
                        Incoming::Closed { transaction_id } if transaction_id == request.transaction_id => return Err(cancelled()),
                        Incoming::Failed { transaction_id, error } if transaction_id == request.transaction_id => {
                            return Err(Error::new(error.code, "Native authentication window failed; retry with system/manual mode or repair the desktop installation"));
                        }
                        _ => return Err(stale()),
                    }
                }
            }
        }
    }.await;
    if let Some(launch) = launch {
        launch.abort();
    }
    if let Some(embedded) = embedded.as_mut() {
        let _ = send(
            &mut embedded.writer,
            &Outgoing::Close {
                transaction_id: request.transaction_id,
            },
        )
        .await;
    }
    drop(embedded);
    peers.abort_all();
    while peers.join_next().await.is_some() {}
    if let Some(child) = child.as_mut() {
        if !matches!(
            timeout(Duration::from_secs(3), child.wait()).await,
            Ok(Ok(_))
        ) {
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
            #[cfg(windows)]
            if let Some(tree) = &process_tree {
                tree.terminate().map_err(|_| recovery())?;
            }
            let _ = child.start_kill();
            if !matches!(
                timeout(Duration::from_secs(3), child.wait()).await,
                Ok(Ok(_))
            ) {
                return Err(recovery());
            }
        }
        #[cfg(windows)]
        if let Some(tree) = &process_tree {
            tree.terminate().map_err(|_| recovery())?;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            #[cfg(unix)]
            let stopped = group.is_none_or(|pid| unsafe { libc::kill(-(pid as i32), 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
            #[cfg(windows)]
            let stopped = match &process_tree {
                Some(tree) => tree.active_processes().map_err(|_| recovery())? == 0,
                None => true,
            };
            if stopped {
                break;
            }
            if Instant::now() >= deadline {
                return Err(recovery());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        // A killed helper could not run its own final cleanup.
        remove_ephemeral_directory(request.transaction_id)?;
    }
    result
}

fn page_completion(page: &BrowserPage) -> Result<Option<GpCompletion>> {
    let names = [
        "saml-auth-status",
        "saml-username",
        "prelogin-cookie",
        "portal-userauthcookie",
    ];
    let mut values: [Option<&str>; 4] = [None; 4];
    for (name, value) in &page.headers {
        if let Some(index) = names
            .iter()
            .position(|candidate| candidate.eq_ignore_ascii_case(name.as_str()))
        {
            if values[index].replace(value.as_str()).is_some() {
                return Err(Error::invalid("Duplicate browser completion field"));
            }
        }
    }
    if values.iter().any(Option::is_some) {
        if values[0] != Some("1") {
            return Err(Error::new(
                ErrorCode::AuthenticationRejected,
                "GlobalProtect did not report successful SAML authentication",
            ));
        }
        let username = values[1]
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Error::invalid("Missing browser completion account"))?;
        let (cookie_name, cookie) = match (values[2], values[3]) {
            (Some(value), None) => (names[2], value),
            (None, Some(value)) => (names[3], value),
            _ => {
                return Err(Error::invalid(
                    "Missing or conflicting browser completion credential",
                ));
            }
        };
        if cookie.trim().is_empty() || username.chars().chain(cookie.chars()).any(char::is_control)
        {
            return Err(Error::invalid("Invalid browser completion field"));
        }
        return Ok(Some(GpCompletion {
            username: zeroize::Zeroizing::new(username.to_owned()),
            cookie_name: cookie_name.into(),
            cookie: zeroize::Zeroizing::new(cookie.to_owned()),
        }));
    }
    page.document.as_ref().map_or(Ok(None), |document| {
        globalprotect::parse_completion_if_present(document.as_str())
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consumed {
    digest: [u8; 32],
    expires: u64,
}
/// The user transaction lock covers this bounded cross-process replay ledger.
/// Only one-way cookie digests persist; raw cookies remain zeroizing memory-only.
fn claim_completion(cookie: &str) -> Result<()> {
    let path = browser_transport::replay_directory()?.join("consumed-callbacks.json");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable())?
        .as_secs();
    claim_completion_at(&path, cookie, now)
}

fn claim_completion_at(path: &std::path::Path, cookie: &str, now: u64) -> Result<()> {
    let mut records: Vec<Consumed> = if let Some(file) = private_fs::open_private_read(path)? {
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        if bytes.len() > 65536 {
            return Err(Error::new(
                ErrorCode::CorruptStorage,
                "Browser replay ledger exceeds its limit",
            ));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            Error::new(
                ErrorCode::CorruptStorage,
                "Browser replay ledger is invalid; authentication was not submitted",
            )
        })?
    } else {
        Vec::new()
    };
    records.retain(|record| record.expires > now);
    let digest: [u8; 32] = Sha256::digest(cookie.as_bytes()).into();
    if records.iter().any(|record| record.digest == digest) {
        return Err(Error::new(
            ErrorCode::AuthenticationRejected,
            "Browser completion was already consumed; start a fresh authentication",
        ));
    }
    if records.len() >= 256 {
        return Err(Error::new(
            ErrorCode::Busy,
            "Browser replay ledger is full; retry after previous transactions expire",
        ));
    }
    records.push(Consumed {
        digest,
        expires: now.saturating_add(86400),
    });
    private_fs::atomic_write(
        path,
        &serde_json::to_vec(&records).map_err(|_| unavailable())?,
        true,
    )
}

#[cfg(test)]
mod tests;
