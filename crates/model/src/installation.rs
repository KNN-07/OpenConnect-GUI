use crate::{Capabilities, Error};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Repair,
}

/// Registration and verified IPC readiness are independent observations.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ServiceStatus {
    pub packaged: bool,
    pub registered: bool,
    pub running: bool,
    pub approval_required: bool,
    pub login_registered: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct DoctorReport {
    pub capabilities: Option<Capabilities>,
    pub engine_error: Option<Error>,
    pub service: Option<ServiceStatus>,
    pub service_error: Option<Error>,
    pub driver_ready: bool,
    pub driver_error: Option<Error>,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct LicenseText {
    pub name: String,
    pub text: String,
}
