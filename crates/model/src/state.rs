use crate::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Authenticating,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    AuthenticationRequired,
    Failed,
}
impl ConnectionState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use ConnectionState::*;
        matches!(
            (self, next),
            (
                Disconnected | AuthenticationRequired | Failed,
                Authenticating
            ) | (
                Authenticating,
                Connecting | Disconnecting | AuthenticationRequired | Failed
            ) | (
                Connecting,
                Connected | Disconnecting | AuthenticationRequired | Failed
            ) | (
                Connected,
                Reconnecting | Disconnecting | AuthenticationRequired | Failed
            ) | (
                Reconnecting,
                Connected | Disconnecting | AuthenticationRequired | Failed
            ) | (
                Disconnecting,
                Disconnected | AuthenticationRequired | Failed
            ) | (AuthenticationRequired | Failed, Disconnected)
        )
    }
    pub fn transition(&mut self, next: Self) -> Result<()> {
        if !self.can_transition_to(next) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Invalid session state transition",
            ));
        }
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct NetworkObservation {
    pub interface: String,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub routes: Vec<String>,
    pub transport: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct TrafficCounters {
    #[ts(type = "number")]
    pub rx_bytes: u64,
    #[ts(type = "number")]
    pub tx_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct Snapshot {
    pub service_instance_id: Uuid,
    #[ts(type = "number")]
    pub sequence: u64,
    pub state: ConnectionState,
    pub profile_id: Option<Uuid>,
    pub profile_name: Option<String>,
    pub attempt_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    #[ts(type = "number | null")]
    pub started_at: Option<i64>,
    pub network: Option<NetworkObservation>,
    pub traffic: TrafficCounters,
    pub last_error: Option<Error>,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct LogRecord {
    #[ts(type = "number")]
    pub timestamp: i64,
    pub level: LogLevel,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct Capabilities {
    pub engine_version: String,
    pub api_major: u32,
    pub api_minor: u32,
    pub protocols: Vec<crate::ProtocolInfo>,
    pub pkcs11: bool,
    pub totp: bool,
    pub hotp: bool,
    pub stoken: bool,
    pub yubioath: bool,
    pub hpke: bool,
}
