use crate::{Error, Result, profile::validate_https};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};
use ts_rs::TS;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AuthFieldKind {
    Text,
    Password,
    Select,
    Token,
    SsoToken,
    SsoUser,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct AuthChoice {
    pub id: String,
    pub label: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct AuthField {
    pub name: String,
    pub label: String,
    pub kind: AuthFieldKind,
    pub required: bool,
    pub numeric: bool,
    pub choices: Vec<AuthChoice>,
}
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct AuthPrompt {
    pub prompt_id: Uuid,
    pub attempt_id: Uuid,
    pub auth_id: String,
    pub banner: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub fields: Vec<AuthField>,
}

/// Intentionally neither Debug nor TS: answers never enter public state.
pub struct AuthReply {
    pub prompt_id: Uuid,
    pub attempt_id: Uuid,
    pub answers: Option<BTreeMap<String, Zeroizing<String>>>,
}
impl AuthPrompt {
    pub fn validate_reply(&self, reply: &AuthReply) -> Result<()> {
        if self.prompt_id != reply.prompt_id || self.attempt_id != reply.attempt_id {
            return Err(Error::new(
                crate::ErrorCode::Conflict,
                "Authentication prompt is no longer current",
            ));
        }
        let Some(answers) = &reply.answers else {
            return Ok(());
        };
        if answers
            .keys()
            .any(|key| !self.fields.iter().any(|f| &f.name == key))
        {
            return Err(Error::invalid("Unknown authentication field"));
        }
        for field in &self.fields {
            let value = answers.get(&field.name).map(|v| v.as_str()).unwrap_or("");
            if value.len() > 65536 || value.contains('\0') || (field.required && value.is_empty()) {
                return Err(Error::invalid("Missing or invalid authentication answer"));
            }
            if !value.is_empty() && field.numeric && !value.bytes().all(|c| c.is_ascii_digit()) {
                return Err(Error::invalid(
                    "Authentication answer must contain only digits",
                ));
            }
            if field.kind == AuthFieldKind::Select && !field.choices.iter().any(|c| c.id == value) {
                return Err(Error::invalid(
                    "Authentication selection is no longer available",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct CertificatePrompt {
    pub prompt_id: Uuid,
    pub attempt_id: Uuid,
    pub host: String,
    pub port: u16,
    pub reason: String,
    pub details: String,
    pub fingerprint: String,
    pub changed_pin: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CertificateDecision {
    Reject,
    AcceptAttempt,
    Pin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelOptions {
    pub proxy: Option<Url>,
    pub sni: Option<String>,
    pub user_agent: Option<String>,
    pub reported_os: Option<String>,
    pub mtu: Option<u16>,
    pub disable_dtls: bool,
    pub disable_ipv6: bool,
    pub reconnect_timeout_secs: u32,
}

/// IPC-only secret type. No Debug, Clone or TypeScript export.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthHandoff {
    pub protocol: String,
    pub connect_url: Url,
    pub dns_name: String,
    pub peer_address: Option<IpAddr>,
    pub peer_fingerprint: String,
    #[serde(with = "secret_string")]
    pub cookie: Zeroizing<String>,
    #[serde(default, with = "optional_secret_string")]
    pub proxy_credentials: Option<Zeroizing<String>>,
    pub expires_at: Option<i64>,
    pub tunnel_options: TunnelOptions,
}
impl AuthHandoff {
    pub fn validate(&self, available: &[crate::ProtocolInfo], now: i64) -> Result<()> {
        validate_https(&self.connect_url)?;
        if !available.iter().any(|p| p.id == self.protocol) {
            return Err(Error::new(
                crate::ErrorCode::UnsupportedProtocol,
                "Unsupported tunnel protocol",
            ));
        }
        if self.cookie.is_empty() || self.cookie.len() > 65536 || self.cookie.contains('\0') {
            return Err(Error::invalid("Invalid authentication cookie"));
        }
        if self.proxy_credentials.as_ref().is_some_and(|secret| {
            secret.len() > 65536 || secret.contains('\0') || self.tunnel_options.proxy.is_none()
        }) {
            return Err(Error::invalid("Invalid private proxy credentials"));
        }
        if self.dns_name.is_empty() || url::Host::parse(&self.dns_name).is_err() {
            return Err(Error::invalid("Invalid authentication DNS name"));
        }
        crate::profile::validate_fingerprint(&self.peer_fingerprint)?;
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(Error::new(
                crate::ErrorCode::AuthenticationRequired,
                "Authentication has expired",
            ));
        }
        let mut profile = crate::Profile::new(
            "handoff".into(),
            self.connect_url.clone(),
            self.protocol.clone(),
        );
        let options = &self.tunnel_options;
        profile.proxy = options.proxy.clone();
        profile.sni = options.sni.clone();
        profile.user_agent = options.user_agent.clone();
        profile.reported_os = options.reported_os.clone();
        profile.mtu = options.mtu;
        profile.disable_ipv6 = options.disable_ipv6;
        profile.validate()
    }
}

mod secret_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;
    pub fn serialize<S: Serializer>(
        value: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

mod optional_secret_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;
    pub fn serialize<S: Serializer>(
        value: &Option<Zeroizing<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(value.as_str()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Zeroizing<String>>, D::Error> {
        Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
    }
}
