use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ErrorCode {
    InvalidInput,
    UnsupportedProtocol,
    UnsupportedAuthentication,
    EngineUnavailable,
    RuntimeFailure,
    AuthenticationRequired,
    AuthenticationRejected,
    ServiceUnavailable,
    AuthorizationDenied,
    Busy,
    Conflict,
    NotFound,
    CorruptStorage,
    NewerSchema,
    KeyringUnavailable,
    CertificateRejected,
    Cancelled,
    ProtocolViolation,
    NetworkFailure,
    RecoveryRequired,
}

/// Messages must be application-authored; native/remote payloads are never error details.
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
#[ts(export)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}
impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }
    pub fn exit_code(&self) -> u8 {
        match self.code {
            ErrorCode::InvalidInput
            | ErrorCode::UnsupportedProtocol
            | ErrorCode::ProtocolViolation => 2,
            ErrorCode::AuthenticationRequired
            | ErrorCode::AuthenticationRejected
            | ErrorCode::UnsupportedAuthentication
            | ErrorCode::KeyringUnavailable
            | ErrorCode::CertificateRejected => 3,
            ErrorCode::ServiceUnavailable | ErrorCode::AuthorizationDenied => 4,
            ErrorCode::Busy | ErrorCode::Conflict => 5,
            ErrorCode::Cancelled => 130,
            _ => 1,
        }
    }
}
