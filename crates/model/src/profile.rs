use serde::{Deserialize, Serialize};
use ts_rs::TS;
use url::Url;
use uuid::Uuid;

use crate::{Error, ErrorCode, Result};

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct ProtocolInfo {
    pub id: String,
    pub label: String,
    pub description: String,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BrowserMode {
    #[default]
    Auto,
    System,
    Embedded,
    Manual,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum TokenMode {
    #[default]
    None,
    Totp,
    Hotp,
    Stoken,
    Yubioath,
    Oidc,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct Profile {
    pub id: Uuid,
    #[ts(type = "number")]
    pub revision: u64,
    pub name: String,
    pub protocol: String,
    pub server: Url,
    pub username: Option<String>,
    pub auth_group: Option<String>,
    pub gateway: Option<String>,
    pub ca_file: Option<String>,
    pub client_certificate: Option<String>,
    pub client_key: Option<String>,
    pub secondary_certificate: Option<String>,
    pub secondary_key: Option<String>,
    pub proxy: Option<Url>,
    pub user_agent: Option<String>,
    pub reported_os: Option<String>,
    pub mtu: Option<u16>,
    pub sni: Option<String>,
    #[serde(default)]
    pub direct_gateway: bool,
    #[serde(default)]
    pub disable_dtls: bool,
    #[serde(default)]
    pub disable_ipv6: bool,
    #[serde(default)]
    pub browser_mode: BrowserMode,
    #[serde(default)]
    pub token_mode: TokenMode,
    #[serde(default = "default_reconnect_timeout")]
    pub reconnect_timeout_secs: u32,
    #[serde(default)]
    pub remember_password: bool,
}

fn default_reconnect_timeout() -> u32 {
    300
}

impl Profile {
    pub fn new(name: String, server: Url, protocol: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            revision: 1,
            name,
            protocol,
            server,
            username: None,
            auth_group: None,
            gateway: None,
            ca_file: None,
            client_certificate: None,
            client_key: None,
            secondary_certificate: None,
            secondary_key: None,
            proxy: None,
            user_agent: None,
            reported_os: None,
            mtu: None,
            sni: None,
            direct_gateway: false,
            disable_dtls: false,
            disable_ipv6: false,
            browser_mode: BrowserMode::Auto,
            token_mode: TokenMode::None,
            reconnect_timeout_secs: default_reconnect_timeout(),
            remember_password: false,
        }
    }

    /// Metadata validation deliberately preserves future protocol IDs.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_nil() || self.revision == 0 {
            return Err(Error::invalid("Profile ID and revision must be nonzero"));
        }
        if self.name.trim().is_empty() || self.name.chars().any(char::is_control) {
            return Err(Error::invalid(
                "Profile name must be nonempty and contain no control characters",
            ));
        }
        validate_https(&self.server)?;
        if self.protocol.is_empty()
            || !self
                .protocol
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::invalid("Invalid protocol identifier"));
        }
        if let Some(mtu) = self.mtu {
            let minimum = if self.disable_ipv6 { 576 } else { 1280 };
            if !(minimum..=9000).contains(&mtu) {
                return Err(Error::invalid(format!("MTU must be {minimum}..9000")));
            }
        }
        if let Some(os) = &self.reported_os {
            if ![
                "linux",
                "linux-64",
                "win",
                "mac-intel",
                "android",
                "apple-ios",
            ]
            .contains(&os.as_str())
            {
                return Err(Error::invalid("Unsupported reported OS"));
            }
        }
        if let Some(proxy) = &self.proxy {
            validate_proxy(proxy)?;
        }
        for value in [
            &self.username,
            &self.auth_group,
            &self.gateway,
            &self.ca_file,
            &self.client_certificate,
            &self.client_key,
            &self.secondary_certificate,
            &self.secondary_key,
            &self.user_agent,
            &self.reported_os,
            &self.sni,
        ]
        .into_iter()
        .flatten()
        {
            if value.chars().any(char::is_control) {
                return Err(Error::invalid(
                    "Profile options cannot contain control characters",
                ));
            }
        }
        for value in [
            &self.ca_file,
            &self.client_certificate,
            &self.client_key,
            &self.secondary_certificate,
            &self.secondary_key,
        ]
        .into_iter()
        .flatten()
        {
            validate_certificate_reference(value)?;
        }
        if let Some(sni) = &self.sni {
            if sni.is_empty() || url::Host::parse(sni).is_err() {
                return Err(Error::invalid("SNI must be a valid hostname"));
            }
        }
        Ok(())
    }

    pub fn validate_for_connect(&self, protocols: &[ProtocolInfo]) -> Result<()> {
        self.validate()?;
        if !protocols.iter().any(|p| p.id == self.protocol) {
            return Err(Error::new(
                ErrorCode::UnsupportedProtocol,
                "This engine does not support the profile's protocol",
            ));
        }
        Ok(())
    }
}

fn validate_certificate_reference(value: &str) -> Result<()> {
    let Some((scheme, attributes)) = value.split_once(':') else {
        return Ok(());
    };
    // RFC 7512 §2.3: case-insensitive scheme and attribute names; percent
    // encoding belongs to values, not attribute names. p11-kit uri.c also
    // strips literal whitespace and accepts PIN attributes in the path,
    // including the legacy pinfile spelling. Control characters fail above.
    if !scheme
        .bytes()
        .filter(|byte| *byte != b' ')
        .map(|byte| byte.to_ascii_lowercase())
        .eq(b"pkcs11".iter().copied())
    {
        return Ok(());
    }
    let attributes = if attributes.contains(' ') {
        std::borrow::Cow::Owned(attributes.replace(' ', ""))
    } else {
        std::borrow::Cow::Borrowed(attributes)
    };
    let (path, query) = attributes.split_once('?').unwrap_or((&attributes, ""));
    for attribute in path
        .split(';')
        .chain(query.split('&'))
        .filter(|part| !part.is_empty())
    {
        let Some((name, _)) = attribute.split_once('=') else {
            return Err(Error::invalid("Invalid PKCS#11 attribute"));
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Error::invalid(
                "Invalid PKCS#11 attribute name; percent encoding is only allowed in values",
            ));
        }
        if ["pin-value", "pin-source", "pinfile"]
            .iter()
            .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
        {
            return Err(Error::invalid(
                "PKCS#11 PIN values and sources cannot be saved in profile metadata; use the credential prompt",
            ));
        }
    }
    Ok(())
}

pub fn parse_server(input: &str) -> Result<Url> {
    let input = input.trim();
    let url = if input.contains("://") {
        Url::parse(input)
    } else {
        Url::parse(&format!("https://{input}"))
    }
    .map_err(|_| Error::invalid("Invalid server URL"))?;
    validate_https(&url)?;
    Ok(url)
}

pub fn validate_https(url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(Error::invalid(
            "Server must be an absolute HTTPS URL without credentials or fragment and with a valid port",
        ));
    }
    Ok(())
}

pub fn validate_proxy(proxy: &Url) -> Result<()> {
    if !["http", "socks", "socks5"].contains(&proxy.scheme())
        || proxy.host().is_none()
        || !proxy.username().is_empty()
        || proxy.password().is_some()
        || proxy.fragment().is_some()
        || proxy.query().is_some()
        || !["", "/"].contains(&proxy.path())
        || proxy.port() == Some(0)
    {
        return Err(Error::invalid(
            "Proxy must be an HTTP/SOCKS endpoint without credentials, path, query or fragment",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProfileExport {
    pub schema_version: u32,
    pub profiles: Vec<Profile>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct Settings {
    pub theme: Theme,
    pub start_at_login: bool,
    pub auto_connect_profile_id: Option<Uuid>,
    pub close_to_tray: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            start_at_login: false,
            auto_connect_profile_id: None,
            close_to_tray: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct CertificatePin {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
}
impl CertificatePin {
    pub fn new(host: &str, port: u16, fingerprint: String) -> Result<Self> {
        validate_fingerprint(&fingerprint)?;
        if port == 0 {
            return Err(Error::invalid("Invalid certificate pin"));
        }
        let host = url::Host::parse(host)
            .map_err(|_| Error::invalid("Invalid pin host"))?
            .to_string();
        Ok(Self {
            host,
            port,
            fingerprint,
        })
    }
}

pub(crate) fn validate_fingerprint(fingerprint: &str) -> Result<()> {
    use base64::Engine as _;
    // OpenConnect also accepts four-character prefixes. Persistent trust and
    // secret handoffs require the complete digest, never that CLI convenience.
    let valid = if let Some(value) = fingerprint.strip_prefix("pin-sha256:") {
        let mut digest = [0u8; 32];
        value.len() == 44
            && base64::engine::general_purpose::STANDARD
                .decode_slice(value, &mut digest)
                .is_ok_and(|length| length == digest.len())
    } else {
        let (value, length) = if let Some(value) = fingerprint.strip_prefix("sha256:") {
            (value, 64)
        } else {
            (fingerprint.strip_prefix("sha1:").unwrap_or(fingerprint), 40)
        };
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    if valid {
        Ok(())
    } else {
        Err(Error::invalid(
            "Certificate fingerprints require a complete supported hash",
        ))
    }
}
