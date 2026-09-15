//! Desktop portal activation keeps bootstrap URLs out of application-created argv.
use std::{collections::HashMap, os::unix::fs::MetadataExt, path::PathBuf, process::Stdio};

use futures_util::StreamExt;
use ocvpn_model::{Error, ErrorCode, Result};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{Duration, timeout},
};
use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

pub(super) const HANDLER: &str = "org.openconnectgui.Callback.desktop";
const MIME: &str = "x-scheme-handler/globalprotectcallback";
const PORTAL: &str = "org.freedesktop.portal.Desktop";
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
const MIME_TIMEOUT: Duration = Duration::from_secs(10);
const DESKTOP_ENTRY: &[u8] = b"[Desktop Entry]\nType=Application\nName=OpenConnect GUI Authentication Callback\nNoDisplay=true\nTerminal=false\nExec=/usr/bin/ocvpn-auth-callback %u\nMimeType=x-scheme-handler/globalprotectcallback;\n";

fn unavailable(message: &'static str) -> Error {
    Error::new(ErrorCode::AuthenticationRequired, message)
}

// A dropped launch (including cancellation by the broker) closes its portal dialog.
struct PendingRequest(Option<Proxy<'static>>);
impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(proxy) = self.0.take() {
            tokio::spawn(async move {
                let _ = timeout(Duration::from_secs(2), proxy.call_noreply("Close", &())).await;
            });
        }
    }
}

pub(super) async fn launch(uri: &str) -> Result<()> {
    timeout(ACTIVATION_TIMEOUT, launch_portal(uri)).await.map_err(|_| unavailable(
        "Default browser activation timed out; retry or choose embedded/manual authentication",
    ))?
}

async fn launch_portal(uri: &str) -> Result<()> {
    let failed = || {
        unavailable(
            "Cannot open the default browser through xdg-desktop-portal; install a desktop portal backend or choose embedded/manual authentication",
        )
    };
    let connection = Connection::session().await.map_err(|_| failed())?;
    let sender = connection
        .unique_name()
        .ok_or_else(failed)?
        .as_str()
        .trim_start_matches(':')
        .replace('.', "_");
    let token = format!("ocvpn_{}", uuid::Uuid::new_v4().simple());
    let path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
    let request = Proxy::new_owned(
        connection.clone(),
        PORTAL.to_owned(),
        path.clone(),
        "org.freedesktop.portal.Request".to_owned(),
    )
    .await
    .map_err(|_| failed())?;
    // Install the sender/path-specific match before OpenURI can emit Response.
    let mut responses = request
        .receive_signal("Response")
        .await
        .map_err(|_| failed())?;
    let mut pending = PendingRequest(Some(request.clone()));
    let portal = Proxy::new(
        &connection,
        PORTAL,
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.OpenURI",
    )
    .await
    .map_err(|_| failed())?;
    let options: HashMap<&str, Value<'_>> = HashMap::from([
        ("handle_token", Value::from(token.as_str())),
        ("ask", Value::from(false)),
    ]);
    let handle: OwnedObjectPath = portal
        .call("OpenURI", &("", uri, options))
        .await
        .map_err(|_| failed())?;
    if handle.as_str() != path {
        // Old/nonconforming portals cannot provide the race-free request contract.
        if let Ok(actual) = Proxy::new_owned(
            connection.clone(),
            PORTAL.to_owned(),
            handle,
            "org.freedesktop.portal.Request".to_owned(),
        )
        .await
        {
            drop(PendingRequest(Some(actual)));
        }
        return Err(failed());
    }
    let response = responses.next().await.ok_or_else(failed)?;
    let (status, _): (u32, HashMap<String, OwnedValue>) =
        response.body().deserialize().map_err(|_| failed())?;
    pending.0 = None;
    match status {
        0 => Ok(()),
        1 => Err(unavailable(
            "Default browser opening was cancelled; retry or choose embedded/manual authentication",
        )),
        _ => Err(failed()),
    }
}

async fn xdg_mime(args: &[&str]) -> Result<String> {
    let failed = || {
        unavailable(
            "Cannot query or set the callback association; install xdg-utils and use a desktop session, or choose embedded/manual authentication",
        )
    };
    let mut child = Command::new("/usr/bin/xdg-mime")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| failed())?;
    let mut stdout = child.stdout.take().ok_or_else(failed)?.take(4097);
    let result = timeout(MIME_TIMEOUT, async {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map_err(|_| failed())?;
        if bytes.len() > 4096 {
            return Err(failed());
        }
        if !child.wait().await.map_err(|_| failed())?.success() {
            return Err(failed());
        }
        String::from_utf8(bytes).map_err(|_| failed())
    })
    .await
    .map_err(|_| failed())?;
    result
}

pub(super) async fn association() -> Result<Option<String>> {
    let output = xdg_mime(&["query", "default", MIME]).await?;
    let handler = output.trim();
    if handler.is_empty() {
        return Ok(None);
    }
    // Only an inert desktop file identifier may reach diagnostics or comparison.
    if !handler.ends_with(".desktop")
        || handler.len() > 255
        || !handler
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(unavailable(
            "The desktop reported an invalid callback association; repair desktop MIME settings or choose embedded/manual authentication",
        ));
    }
    Ok(Some(handler.to_owned()))
}

fn install_entry() -> Result<()> {
    let failed = || {
        unavailable(
            "Cannot install the private callback desktop entry; check ownership and permissions of the user applications directory or choose embedded/manual authentication",
        )
    };
    let base = directories::BaseDirs::new().ok_or_else(failed)?;
    let applications: PathBuf = base.data_dir().join("applications");
    if !applications.is_absolute() {
        return Err(failed());
    }
    // Standard applications directories are often 0755. Do not chmod a shared
    // desktop directory to 0700; reject symlinks and other-user write access.
    for ancestor in applications.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata)
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.mode() & 0o022 != 0
                    || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() }) =>
            {
                return Err(failed());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed()),
        }
    }
    if !applications.exists() {
        crate::private_fs::ensure_private_directory(&applications).map_err(|_| failed())?;
    }
    let metadata = std::fs::symlink_metadata(&applications).map_err(|_| failed())?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(failed());
    }
    crate::private_fs::atomic_write(&applications.join(HANDLER), DESKTOP_ENTRY, true)
        .map_err(|_| failed())
}

pub(super) async fn register(replace_existing: bool) -> Result<()> {
    super::installed_callback()?;
    let existing = association().await?;
    if existing
        .as_deref()
        .is_some_and(|handler| handler != HANDLER)
        && !replace_existing
    {
        return Err(unavailable(
            "Another application owns GlobalProtect callbacks; explicitly approve replacing its association or choose embedded/manual authentication",
        ));
    }
    tokio::task::spawn_blocking(install_entry)
        .await
        .map_err(|_| {
            unavailable(
                "Cannot install the callback desktop entry; choose embedded/manual authentication",
            )
        })??;
    // Recheck after filesystem work so an intervening association change is not
    // silently replaced without the explicit replacement permission.
    if !replace_existing
        && association()
            .await?
            .as_deref()
            .is_some_and(|handler| handler != HANDLER)
    {
        return Err(unavailable(
            "The callback association changed; explicitly approve replacement or choose embedded/manual authentication",
        ));
    }
    xdg_mime(&["default", HANDLER, MIME]).await?;
    if association().await?.as_deref() != Some(HANDLER) {
        return Err(unavailable(
            "The desktop did not select the OpenConnect callback receiver; select it in desktop settings or choose embedded/manual authentication",
        ));
    }
    Ok(())
}
