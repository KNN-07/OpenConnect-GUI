use crate::{CertificatePin, Profile, Settings};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProfileDocument {
    pub schema_version: u32,
    #[ts(type = "number")]
    pub revision: u64,
    pub profiles: Vec<Profile>,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct SettingsDocument {
    pub schema_version: u32,
    #[ts(type = "number")]
    pub revision: u64,
    pub settings: Settings,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct PinsDocument {
    pub schema_version: u32,
    #[ts(type = "number")]
    pub revision: u64,
    pub pins: Vec<CertificatePin>,
}

/// Derived readiness is separate from the stored settings document.
#[derive(Clone, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct SettingsRead {
    pub document: SettingsDocument,
    pub auto_connect_error: Option<crate::Error>,
}
