use crate::{LifecycleReport, TransactionId, secure};
use ocvpn_model::ipc::{Hello, VERSION, read_frame, write_frame};
use ocvpn_model::{Error, ErrorCode, Result};
use std::time::Duration;
fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "Network lifecycle peer is not the privileged worker",
    )
}
fn unavailable() -> Error {
    crate::failure("Private network lifecycle channel is unavailable")
}
#[cfg(unix)]
fn endpoint(t: TransactionId) -> std::path::PathBuf {
    // Preserve all 256 UUID bits within macOS sockaddr_un's 104-byte path limit.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut name = String::with_capacity(48);
    let mut accumulator = 0u32;
    let mut bits = 0;
    for byte in t
        .service_instance_id
        .as_bytes()
        .iter()
        .chain(t.attempt_id.as_bytes())
    {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            name.push(ALPHABET[((accumulator >> bits) & 63) as usize] as char);
        }
    }
    if bits > 0 {
        name.push(ALPHABET[((accumulator << (6 - bits)) & 63) as usize] as char);
    }
    name.push_str(".sock");
    secure::root().join(name)
}
#[cfg(unix)]
pub struct Monitor {
    transaction: TransactionId,
    listener: tokio::net::UnixListener,
    path: std::path::PathBuf,
}
#[cfg(unix)]
impl Monitor {
    pub async fn bind(transaction: TransactionId) -> Result<Self> {
        secure::privileged()?;
        secure::directory(&secure::root())?;
        let path = endpoint(transaction);
        let listener = tokio::net::UnixListener::bind(&path).map_err(|_| unavailable())?;
        Ok(Self {
            transaction,
            listener,
            path,
        })
    }
    pub fn environment(&self) -> Vec<(String, String)> {
        environment(self.transaction)
    }
    pub async fn recv(&mut self) -> Result<LifecycleReport> {
        loop {
            let (mut stream, _) = self.listener.accept().await.map_err(|_| unavailable())?;
            if stream.peer_cred().map_err(|_| denied())?.uid() != 0 {
                continue;
            }
            let result = tokio::time::timeout(Duration::from_secs(180), async {
                let hello: Hello = read_frame(&mut stream).await?;
                hello.validate()?;
                write_frame(&mut stream, &Hello { version: VERSION }).await?;
                let report: LifecycleReport = read_frame(&mut stream).await?;
                if report.transaction != self.transaction {
                    return Err(denied());
                }
                write_frame(&mut stream, &Hello { version: VERSION }).await?;
                Ok(report)
            })
            .await
            .map_err(|_| unavailable())?;
            return result;
        }
    }
}
#[cfg(unix)]
impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
fn environment(t: TransactionId) -> Vec<(String, String)> {
    vec![
        (
            "OCVPN_SERVICE_INSTANCE_ID".into(),
            t.service_instance_id.to_string(),
        ),
        ("OCVPN_ATTEMPT_ID".into(), t.attempt_id.to_string()),
    ]
}
pub(crate) fn transaction() -> Result<TransactionId> {
    fn id(name: &str) -> Result<uuid::Uuid> {
        let s = std::env::var(name).map_err(|_| denied())?;
        let id: uuid::Uuid = s.parse().map_err(|_| denied())?;
        if id.is_nil() || id.to_string() != s {
            return Err(denied());
        }
        Ok(id)
    }
    Ok(TransactionId {
        service_instance_id: id("OCVPN_SERVICE_INSTANCE_ID")?,
        attempt_id: id("OCVPN_ATTEMPT_ID")?,
    })
}
#[cfg(unix)]
pub(crate) async fn connect(t: TransactionId) -> Result<tokio::net::UnixStream> {
    secure::privileged()?;
    secure::check(&secure::root(), true)?;
    let mut stream = tokio::net::UnixStream::connect(endpoint(t))
        .await
        .map_err(|_| unavailable())?;
    if stream.peer_cred().map_err(|_| denied())?.uid() != 0 {
        return Err(denied());
    }
    write_frame(&mut stream, &Hello { version: VERSION }).await?;
    let hello: Hello = read_frame(&mut stream).await?;
    hello.validate()?;
    Ok(stream)
}
#[cfg(windows)]
#[path = "monitor_windows.rs"]
mod native;
#[cfg(windows)]
pub use native::Monitor;
#[cfg(windows)]
pub(crate) use native::connect;

/// Authenticate the endpoint before reading lifecycle input or mutating the OS.
pub async fn run_helper() -> Result<()> {
    secure::privileged()?;
    let t = transaction()?;
    let mut stream = tokio::time::timeout(Duration::from_secs(10), connect(t))
        .await
        .map_err(|_| unavailable())??;
    let env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let parsed = crate::parse_environment(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let reason = env
        .iter()
        .find(|(k, _)| k == "reason")
        .and_then(|(_, v)| match v.as_str() {
            "pre-init" => Some(ocvpn_model::NetworkReason::PreInit),
            "connect" => Some(ocvpn_model::NetworkReason::Connect),
            "reconnect" => Some(ocvpn_model::NetworkReason::Reconnect),
            "attempt-reconnect" => Some(ocvpn_model::NetworkReason::AttemptReconnect),
            "disconnect" => Some(ocvpn_model::NetworkReason::Disconnect),
            _ => None,
        })
        .ok_or_else(|| Error::invalid("Unsupported network lifecycle reason"))?;
    let result = match parsed {
        Ok(input) => tokio::task::spawn_blocking(move || crate::journal::lifecycle(t, input))
            .await
            .map_err(|_| unavailable())?,
        Err(e) => Err(e),
    };
    let failure = result.as_ref().err().cloned();
    let report = LifecycleReport {
        transaction: t,
        reason,
        result,
    };
    let delivered = tokio::time::timeout(Duration::from_secs(10), async {
        write_frame(&mut stream, &report).await?;
        let ack: Hello = read_frame(&mut stream).await?;
        ack.validate()
    })
    .await;
    if !matches!(delivered, Ok(Ok(()))) {
        let warnings = tokio::task::spawn_blocking(move || crate::recover(t))
            .await
            .map_err(|_| unavailable())??;
        if !warnings.is_empty() {
            return Err(Error::new(
                ErrorCode::RecoveryRequired,
                "Worker report delivery failed and network recovery requires repair",
            ));
        }
        return Err(unavailable());
    }
    if let Some(error) = failure {
        Err(error)
    } else {
        Ok(())
    }
}
