//! Authenticated machine-wide VPN supervision and fixed private native worker.

pub use ocvpn_model::ipc::CONTROL_ENDPOINT;

pub mod daemon;
pub mod installation;
#[cfg(unix)]
mod lifetime;
mod process_tree;
#[cfg(windows)]
pub mod scm;
mod trust;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;
pub mod worker;

/// An OS-observed user identity, deliberately not serializable or constructible
/// from wire DTOs. Session authorization compares identities, never JSON fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    #[cfg(unix)]
    uid: u32,
    #[cfg(windows)]
    sid: Vec<u8>,
}

impl PeerIdentity {
    #[cfg(unix)]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The canonical binary SID copied from the native access token.
    #[cfg(windows)]
    pub fn sid(&self) -> &[u8] {
        &self.sid
    }
}

fn denied(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}
