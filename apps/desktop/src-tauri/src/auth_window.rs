//! Dedicated, unprivileged authentication process; never starts the application UI.
use ocvpn_model::{
    BrowserClientMessage, BrowserHello, BrowserPeerRole, BrowserRequest, BrowserServerMessage,
    Error, ErrorCode, NativeBrowserKind, ipc,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tauri::{Manager, WebviewWindow};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

#[cfg(target_os = "linux")]
#[path = "auth_window/linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "auth_window/macos.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "auth_window/windows.rs"]
mod platform;

const LABEL: &str = "authentication";
const IO_DEADLINE: Duration = Duration::from_secs(10);
const AUTH_DEADLINE: Duration = Duration::from_secs(300);
const USER_CLOSED: u8 = 1;
const HOST_CLOSED: u8 = 2;
const FAILED: u8 = 3;

struct Lifetime {
    reason: AtomicU8,
    finished: watch::Sender<u8>,
}
impl Lifetime {
    fn finish(&self, reason: u8) -> bool {
        if self
            .reason
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.finished.send_replace(reason);
        true
    }
}
fn failure() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "Embedded authentication could not continue; retry or use system/manual authentication",
    )
}

// Called only on the event-loop thread. Native adapters enqueue their teardown on
// the same GUI queue before destroy, so retained callbacks cannot outlive the view.
fn stop(window: &WebviewWindow, lifetime: &Lifetime, reason: u8) {
    if lifetime.finish(reason) {
        let _ = platform::close(window);
        let _ = window.destroy();
    }
}

async fn dispatch_close(app: &tauri::AppHandle, lifetime: Arc<Lifetime>, reason: u8) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(window) = handle.get_webview_window(LABEL) {
            stop(&window, &lifetime, reason);
        } else {
            lifetime.finish(reason);
        }
    });
}

fn allowed_navigation(uri: &url::Url, request: &BrowserRequest) -> bool {
    if uri.as_str() == "about:blank" || uri.as_str() == request.uri.as_str() {
        return true;
    }
    if uri.scheme() == "https"
        && uri.host().is_some()
        && uri.username().is_empty()
        && uri.password().is_none()
    {
        return true;
    }
    request.kind == NativeBrowserKind::External
        && request.protocol == "anyconnect"
        && uri.scheme() == "http"
        && uri.host_str() == Some("[::1]")
        && uri.port() == Some(29786)
        && uri.username().is_empty()
        && uri.password().is_none()
}

/// Called by the actual GUI-thread attachment callback, not after merely queuing
/// with_webview. Navigation must not race ahead of certificate/origin handlers.
fn attached(
    request: &BrowserRequest,
    sender: &mpsc::Sender<BrowserClientMessage>,
) -> ocvpn_model::Result<()> {
    sender
        .try_send(BrowserClientMessage::Ready {
            transaction_id: request.transaction_id,
        })
        .map_err(|_| failure())
}

// Never re-enter Tauri's webview lock from a native attachment or callback.
fn defer_close(window: WebviewWindow) {
    tauri::async_runtime::spawn(async move {
        let _ = window.close();
    });
}

async fn open_request() -> ocvpn_model::Result<(
    ocvpn_client::browser_transport::UserConnection,
    Arc<BrowserRequest>,
)> {
    tokio::time::timeout(IO_DEADLINE, async {
        let mut connection = ocvpn_client::browser_transport::connect().await?;
        ipc::write_frame(
            &mut connection.stream,
            &BrowserHello {
                version: 1,
                role: BrowserPeerRole::Embedded,
            },
        )
        .await?;
        let BrowserServerMessage::Open { request } =
            ipc::read_frame(&mut connection.stream).await?
        else {
            return Err(failure());
        };
        request.validate()?;
        let uri = url::Url::parse(request.uri.as_str()).map_err(|_| failure())?;
        // Only the broker's HTTPS target or literal loopback bootstrap may be the initial URL.
        let bootstrap = uri.scheme() == "http"
            && matches!(uri.host(),
            Some(url::Host::Ipv4(ip)) if ip.is_loopback())
            || uri.scheme() == "http"
                && matches!(uri.host(),
                Some(url::Host::Ipv6(ip)) if ip.is_loopback());
        if !(uri.scheme() == "https" || bootstrap)
            || uri.host().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
        {
            return Err(failure());
        }
        Ok((connection, request))
    })
    .await
    .map_err(|_| failure())?
}

async fn write_messages<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    mut messages: mpsc::Receiver<BrowserClientMessage>,
    mut finished: watch::Receiver<u8>,
    transaction_id: Uuid,
    app: &tauri::AppHandle,
    request: &Arc<BrowserRequest>,
) -> ocvpn_model::Result<()> {
    let mut navigated = false;
    loop {
        tokio::select! {
            biased;
            result = finished.changed() => {
                if result.is_err() { return Err(failure()); }
                let reason = *finished.borrow_and_update();
                let mut final_message = match reason {
                    USER_CLOSED => Some(BrowserClientMessage::Closed { transaction_id }),
                    FAILED => Some(BrowserClientMessage::Failed { transaction_id, error: failure() }),
                    HOST_CLOSED => None,
                    _ => continue,
                };
                if reason != HOST_CLOSED {
                    while let Ok(message) = messages.try_recv() {
                        if matches!(&message, BrowserClientMessage::Failed { transaction_id: id, .. } if *id == transaction_id) {
                            final_message = Some(message);
                        }
                    }
                }
                if let Some(message) = final_message {
                    tokio::time::timeout(IO_DEADLINE, ipc::write_frame(&mut writer, &message))
                        .await.map_err(|_| failure())??;
                }
                return Ok(());
            }
            message = messages.recv() => {
                let message = message.ok_or_else(failure)?;
                if let BrowserClientMessage::Ready { transaction_id: id } = &message {
                    if navigated || *id != transaction_id { return Err(failure()); }
                    let (sent, done) = oneshot::channel();
                    let handle = app.clone();
                    let request = request.clone();
                    // This runs from the async writer, after with_webview released
                    // Tauri's webview lock. Reentrant navigation there deadlocks.
                    app.run_on_main_thread(move || {
                        let result = handle.get_webview_window(LABEL).ok_or_else(failure)
                            .and_then(|window| window.navigate(url::Url::parse(request.uri.as_str()).map_err(|_| failure())?).map_err(|_| failure()));
                        let _ = sent.send(result);
                    }).map_err(|_| failure())?;
                    tokio::time::timeout(IO_DEADLINE, done).await.map_err(|_| failure())?.map_err(|_| failure())??;
                    navigated = true;
                }
                tokio::time::timeout(IO_DEADLINE, ipc::write_frame(&mut writer, &message))
                    .await.map_err(|_| failure())??;
            }
        }
    }
}

async fn read_messages<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    app: tauri::AppHandle,
    lifetime: Arc<Lifetime>,
    transaction_id: Uuid,
) {
    let work = async {
        loop {
            let message: BrowserServerMessage = ipc::read_frame(&mut reader).await?;
            match message {
                BrowserServerMessage::CertificateDecision {
                    challenge_id,
                    accept,
                } => {
                    // Acknowledge each GUI operation before reading the next frame: an
                    // authenticated but malfunctioning host cannot flood the GUI queue.
                    let (sent, done) = oneshot::channel();
                    let handle = app.clone();
                    let state = lifetime.clone();
                    app.run_on_main_thread(move || {
                        let result = if state.reason.load(Ordering::Acquire) != 0 {
                            Err(failure())
                        } else if let Some(window) = handle.get_webview_window(LABEL) {
                            platform::certificate_decision(&window, challenge_id, accept)
                        } else {
                            Err(failure())
                        };
                        let _ = sent.send(result);
                    })
                    .map_err(|_| failure())?;
                    done.await.map_err(|_| failure())??;
                }
                BrowserServerMessage::Close { transaction_id: id } if id == transaction_id => {
                    dispatch_close(&app, lifetime.clone(), HOST_CLOSED).await;
                    return Ok::<(), Error>(());
                }
                _ => return Err(failure()),
            }
        }
    };
    if !matches!(tokio::time::timeout(AUTH_DEADLINE, work).await, Ok(Ok(()))) {
        dispatch_close(&app, lifetime, FAILED).await;
    }
}

/// Entered on the process main thread, before any normal application setup.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none_or(|value| value.is_empty())
        && std::env::var_os("WAYLAND_DISPLAY").is_none_or(|value| value.is_empty())
    {
        return Err(Error::new(ErrorCode::AuthenticationRequired,
            "Embedded authentication requires a graphical desktop; use system or manual authentication").into());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| failure())?;
    let (connection, request) = runtime.block_on(open_request()).map_err(|_| failure())?;
    let transaction_id = request.transaction_id;
    let directory = ocvpn_client::browser::create_ephemeral_directory(transaction_id)?;
    let result = (|| -> ocvpn_model::Result<()> {
        // Remove configured windows as well as avoiding the normal app's setup,
        // command handlers and plugins. No capability matches this window label.
        let mut context = tauri::generate_context!();
        context.config_mut().app.windows.clear();
        let app = tauri::Builder::default()
            .build(context)
            .map_err(|_| failure())?;
        let (finished, finish_receiver) = watch::channel(0);
        let lifetime = Arc::new(Lifetime {
            reason: AtomicU8::new(0),
            finished,
        });
        let (sender, receiver) = mpsc::channel(16);
        let navigation = request.clone();
        let window = tauri::WebviewWindowBuilder::new(
            &app,
            LABEL,
            tauri::WebviewUrl::External(url::Url::parse("about:blank").map_err(|_| failure())?),
        )
        .title("OpenConnect GUI — Authentication")
        .inner_size(960.0, 720.0)
        .min_inner_size(640.0, 480.0)
        .incognito(true)
        .data_directory(directory.clone())
        .devtools(false)
        .disable_drag_drop_handler()
        .on_navigation(move |uri| allowed_navigation(uri, &navigation))
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .build()
        .map_err(|_| failure())?;
        let setup = platform::attach(&window, request.clone(), sender.clone());
        if setup.is_err() {
            stop(&window, &lifetime, FAILED);
        }
        let (reader, writer) = tokio::io::split(connection.stream);
        let writer_app = app.handle().clone();
        let writer_state = lifetime.clone();
        let writer_task = runtime.spawn(async move {
            let result = write_messages(
                writer,
                receiver,
                finish_receiver,
                transaction_id,
                &writer_app,
                &request,
            )
            .await;
            if result.is_err() {
                dispatch_close(&writer_app, writer_state, FAILED).await;
            }
            result
        });
        let reader_task = runtime.spawn(read_messages(
            reader,
            app.handle().clone(),
            lifetime.clone(),
            transaction_id,
        ));
        drop(sender);
        drop(window);
        let events_state = lifetime.clone();
        let exit_code = app.run_return(move |handle, event| match event {
            tauri::RunEvent::WindowEvent {
                label,
                event: tauri::WindowEvent::CloseRequested { api, .. },
                ..
            } if label == LABEL => {
                api.prevent_close();
                if let Some(window) = handle.get_webview_window(LABEL) {
                    stop(&window, &events_state, USER_CLOSED);
                }
            }
            tauri::RunEvent::WindowEvent {
                label,
                event: tauri::WindowEvent::Destroyed,
                ..
            } if label == LABEL => {
                events_state.finish(USER_CLOSED);
            }
            tauri::RunEvent::ExitRequested { api, .. } => {
                if let Some(window) = handle.get_webview_window(LABEL) {
                    api.prevent_exit();
                    stop(&window, &events_state, USER_CLOSED);
                }
            }
            _ => {}
        });
        lifetime.finish(USER_CLOSED);
        reader_task.abort();
        let flushed = runtime.block_on(async {
            let _ = reader_task.await;
            // In-flight page write plus final Closed each have their own deadline.
            writer_task.await.map_err(|_| failure())?
        });
        if exit_code != 0 || lifetime.reason.load(Ordering::Acquire) == FAILED || setup.is_err() {
            return Err(failure());
        }
        flushed
    })();
    runtime.shutdown_timeout(IO_DEADLINE);
    // run_return has released the native runtime and all adapters before deletion.
    let removed = ocvpn_client::browser::remove_ephemeral_directory(transaction_id);
    result?;
    removed?;
    Ok(())
}
