use crate::{AuthHandoff, Capabilities, Error, ErrorCode, LogRecord, Result, Snapshot};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
pub const CONTROL_ENDPOINT: &str = "/run/openconnect-gui/control.sock";
// macOS /var/run is group-writable; endpoint ancestors must be protected.
#[cfg(target_os = "macos")]
pub const CONTROL_ENDPOINT: &str = "/private/var/db/org.openconnectgui/control.sock";
#[cfg(windows)]
pub const CONTROL_ENDPOINT: &str = r"\\.\pipe\OpenConnectGUI.control.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u32,
}
impl Hello {
    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            return Err(protocol_error("Unsupported IPC version"));
        }
        Ok(())
    }
}

/// Contains secrets for Start; intentionally no Debug or public TS representation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: Uuid,
    #[serde(flatten)]
    pub method: Method,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Method {
    Capabilities,
    Reserve {
        profile_id: Uuid,
        profile_name: String,
        protocol: String,
    },
    Start {
        attempt_id: Uuid,
        handoff: AuthHandoff,
    },
    /// Renew only after a real auth interaction, never passive status polling.
    AuthProgress {
        attempt_id: Uuid,
    },
    Cancel {
        attempt_id: Uuid,
    },
    Disconnect,
    Snapshot,
    Subscribe,
    Logs {
        follow: bool,
    },
    /// Native installer authorization only; never a public desktop command.
    AdminQuiesce {
        authorization: Option<crate::SecretText>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub request_id: Uuid,
    pub result: std::result::Result<Payload, Error>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Payload {
    Capabilities(Capabilities),
    Reserved { attempt_id: Uuid },
    Accepted,
    Snapshot(Snapshot),
    Logs(Vec<LogRecord>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub service_instance_id: Uuid,
    pub sequence: u64,
    pub payload: EventPayload,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    Snapshot(Snapshot),
    Log(LogRecord),
}

fn protocol_error(message: &str) -> Error {
    Error::new(ErrorCode::ProtocolViolation, message)
}

/// Zeroize every frame, including malformed secret-bearing JSON, on all exit paths.
pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let length = reader
        .read_u32()
        .await
        .map_err(|_| protocol_error("Missing or truncated IPC frame header"))?
        as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(protocol_error(
            "IPC frame size is outside the permitted range",
        ));
    }
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| protocol_error("Truncated IPC frame payload"))?;
    serde_json::from_slice(&bytes).map_err(|_| protocol_error("Invalid IPC payload"))
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    let mut bytes = Zeroizing::new(Vec::new());
    {
        let mut bounded = BoundedWriter(&mut bytes);
        serde_json::to_writer(&mut bounded, value)
            .map_err(|_| protocol_error("IPC payload cannot be encoded within the frame limit"))?;
    }
    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| protocol_error("Cannot write IPC header"))?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| protocol_error("Cannot write IPC payload"))?;
    writer
        .flush()
        .await
        .map_err(|_| protocol_error("Cannot flush IPC payload"))
}
struct BoundedWriter<'a>(&'a mut Vec<u8>);
impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Frame exceeds size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
