//! Browser secrets travel only through owner-authenticated Rust IPC, never status DTOs.
use crate::{BrowserMode, CertificatePin, Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAX_BROWSER_BYTES: usize = 1024 * 1024;

pub struct SecretText(pub Zeroizing<String>);
impl SecretText {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BrowserPhase {
    Authentication,
    Portal,
    Gateway,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeBrowserKind {
    Webview,
    External,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BrowserStage {
    Opening,
    Waiting,
    ManualInput,
    ConfirmAccount,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BrowserPrompt {
    pub attempt_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_origin: String,
    pub phase: BrowserPhase,
    pub mode: BrowserMode,
    pub stage: BrowserStage,
    pub account: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserTlsPolicy {
    pub ca_file: Option<String>,
    pub pins: Vec<CertificatePin>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRequest {
    pub attempt_id: Uuid,
    pub transaction_id: Uuid,
    pub protocol: String,
    pub expected_origin: Url,
    pub phase: BrowserPhase,
    pub kind: NativeBrowserKind,
    pub mode: BrowserMode,
    pub uri: SecretText,
    pub external_allowed: Option<bool>,
    pub tls: BrowserTlsPolicy,
}
impl BrowserRequest {
    pub fn validate(&self) -> Result<()> {
        if self.attempt_id.is_nil()
            || self.transaction_id.is_nil()
            || self.protocol.is_empty()
            || self.protocol.len() > 64
            || self.uri.as_str().is_empty()
            || self.uri.as_str().len() > MAX_BROWSER_BYTES
            || self.uri.as_str().contains('\0')
            || self.tls.pins.len() > 1024
        {
            return Err(Error::invalid("Invalid browser authentication request"));
        }
        if https_origin(self.expected_origin.as_str())? != self.expected_origin {
            return Err(Error::invalid(
                "Browser completion origin must not contain a path or credential",
            ));
        }
        if self
            .tls
            .ca_file
            .as_ref()
            .is_some_and(|path| path.is_empty() || path.len() > 4096 || path.contains('\0'))
        {
            return Err(Error::invalid("Invalid browser CA path"));
        }
        for pin in &self.tls.pins {
            CertificatePin::new(&pin.host, pin.port, pin.fingerprint.clone())?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPage {
    pub uri: SecretText,
    pub cookies: Vec<(SecretText, SecretText)>,
    pub headers: Vec<(SecretText, SecretText)>,
    pub document: Option<SecretText>,
}
impl BrowserPage {
    pub fn validate(&self, expected_origin: &Url) -> Result<()> {
        if self.cookies.len() > 128
            || self.headers.len() > 128
            || https_origin(self.uri.as_str())? != *expected_origin
        {
            return Err(Error::invalid(
                "Browser completion came from an unexpected origin",
            ));
        }
        let mut bytes = self.uri.as_str().len();
        for value in self
            .cookies
            .iter()
            .chain(&self.headers)
            .flat_map(|(name, value)| [name, value])
            .chain(self.document.iter())
        {
            bytes = bytes
                .checked_add(value.as_str().len())
                .ok_or_else(|| Error::invalid("Browser response exceeds limit"))?;
            if value.as_str().contains('\0') {
                return Err(Error::invalid("Invalid browser response encoding"));
            }
        }
        if bytes > MAX_BROWSER_BYTES {
            return Err(Error::invalid("Browser response exceeds limit"));
        }
        Ok(())
    }
}

pub enum BrowserReply {
    Page(BrowserPage),
    Opened,
    Cancel,
    Failed(Error),
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserPeerRole {
    Callback,
    Embedded,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserHello {
    pub version: u16,
    pub role: BrowserPeerRole,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCertificateChallenge {
    pub transaction_id: Uuid,
    pub challenge_id: Uuid,
    pub origin: Url,
    pub chain: Vec<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserClientMessage {
    Callback {
        uri: SecretText,
    },
    Ready {
        transaction_id: Uuid,
    },
    Page {
        transaction_id: Uuid,
        page: BrowserPage,
    },
    Certificate {
        challenge: BrowserCertificateChallenge,
    },
    Closed {
        transaction_id: Uuid,
    },
    Failed {
        transaction_id: Uuid,
        error: Error,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserServerMessage {
    Open {
        request: std::sync::Arc<BrowserRequest>,
    },
    CertificateDecision {
        challenge_id: Uuid,
        accept: bool,
    },
    Close {
        transaction_id: Uuid,
    },
    Accepted,
    Error {
        error: Error,
    },
}

/// Parse only the nonsecret authority, not a callback's credential-bearing path/query.
pub fn https_origin(uri: &str) -> Result<Url> {
    if !uri
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        || uri.len() > MAX_BROWSER_BYTES
        || uri.chars().any(char::is_control)
    {
        return Err(Error::invalid(
            "Browser navigation requires an absolute HTTPS URL",
        ));
    }
    let authority = uri[8..].split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(Error::invalid("Browser origin cannot contain credentials"));
    }
    Url::parse(&format!("https://{authority}/"))
        .map_err(|_| Error::invalid("Invalid browser HTTPS origin"))
}
