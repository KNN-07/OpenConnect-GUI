//! OS-keyring-only persistence. Blocking APIs and the complete HOTP transaction
//! must run on a blocking authentication worker, never an async or UI thread.

use std::{
    fs::File,
    sync::{Mutex, MutexGuard},
};

use directories::ProjectDirs;
use fs2::FileExt;
use ocvpn_model::{Error, ErrorCode, Result};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::private_fs;

const SERVICE: &str = "org.openconnectgui.app";
// The native backends recommend serial access even for different entries.
static KEYRING_ACCESS: Mutex<()> = Mutex::new(());

#[cfg(target_os = "linux")]
#[path = "credentials/quiet_linux.rs"]
mod quiet;
#[cfg(target_os = "macos")]
#[path = "credentials/quiet_macos.rs"]
mod quiet;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Password,
    KeyPassphrase,
    SecondaryKeyPassphrase,
    TokenSeed,
    /// Opaque serialized username/password pair; neither field is metadata.
    ProxyCredentials,
}

impl Purpose {
    const ALL: [Self; 5] = [
        Self::Password,
        Self::KeyPassphrase,
        Self::SecondaryKeyPassphrase,
        Self::TokenSeed,
        Self::ProxyCredentials,
    ];

    fn identity(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::KeyPassphrase => "key_passphrase",
            Self::SecondaryKeyPassphrase => "secondary_key_passphrase",
            Self::TokenSeed => "token_seed",
            Self::ProxyCredentials => "proxy_credentials",
        }
    }
}

fn unavailable() -> Error {
    Error::new(
        ErrorCode::KeyringUnavailable,
        "The OS credential store is locked or unavailable. Unlock or enable it, or use session-only input. HOTP requires a durable saved seed and cannot use session-only storage.",
    )
}

fn keyring_error(error: keyring::Error) -> Error {
    // This variant owns the invalid secret bytes. Never format a native error,
    // and wipe those bytes rather than dropping an ordinary Vec unchanged.
    if let keyring::Error::BadEncoding(mut bytes) = error {
        bytes.zeroize();
    }
    unavailable()
}

fn serialize_access() -> Result<MutexGuard<'static, ()>> {
    // Fail closed on poison: a previous operation may have been interrupted.
    KEYRING_ACCESS.lock().map_err(|_| unavailable())
}

fn entry(profile_id: Uuid, purpose: Purpose) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, &format!("{profile_id}:{}", purpose.identity()))
        .map_err(keyring_error)
}

fn lock_profile(profile_id: Uuid) -> Result<File> {
    // Deliberately independent of OCVPN_CONFIG_DIR: two metadata directories
    // still address the same keyring entries and must share their locks.
    let dirs =
        ProjectDirs::from("org", "OpenConnectGUI", "OpenConnectGUI").ok_or_else(unavailable)?;
    let directory = dirs.data_local_dir().join("credentials-locks");
    private_fs::ensure_private_directory(&directory).map_err(|_| unavailable())?;
    let file = private_fs::open_private_lock(&directory.join(format!("{profile_id}.lock")))
        .map_err(|_| unavailable())?;
    FileExt::lock_exclusive(&file).map_err(|_| unavailable())?;
    // Never unlink lock files: existing waiters must keep sharing one inode.
    Ok(file)
}

// Callers hold the per-profile lock before acquiring the process-wide mutex.
fn read_locked(
    profile_id: Uuid,
    purpose: Purpose,
    non_interactive: bool,
) -> Result<Option<Zeroizing<String>>> {
    let _access = serialize_access()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if non_interactive {
        return quiet::read(&format!("{profile_id}:{}", purpose.identity()));
    }
    #[cfg(windows)]
    let _ = non_interactive; // CredReadW never displays credential UI.
    match entry(profile_id, purpose)?.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(keyring_error(error)),
    }
}

fn write_locked(
    profile_id: Uuid,
    purpose: Purpose,
    value: &str,
    non_interactive: bool,
) -> Result<()> {
    let _access = serialize_access()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if non_interactive {
        return quiet::write(&format!("{profile_id}:{}", purpose.identity()), value);
    }
    #[cfg(windows)]
    let _ = non_interactive; // CredWriteW never displays credential UI.
    entry(profile_id, purpose)?
        .set_password(value)
        .map_err(keyring_error)
}

fn delete_locked(profile_id: Uuid, purpose: Purpose) -> Result<()> {
    let _access = serialize_access()?;
    match entry(profile_id, purpose)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(keyring_error(error)),
    }
}

pub fn get_blocking(profile_id: Uuid, purpose: Purpose) -> Result<Option<Zeroizing<String>>> {
    let _lock = lock_profile(profile_id)?;
    read_locked(profile_id, purpose, false)
}

pub(crate) fn get_without_ui(
    profile_id: Uuid,
    purpose: Purpose,
) -> Result<Option<Zeroizing<String>>> {
    let _lock = lock_profile(profile_id)?;
    read_locked(profile_id, purpose, true)
}

pub(crate) fn save_without_ui(
    profile_id: Uuid,
    purpose: Purpose,
    value: &str,
    opt_in: bool,
) -> Result<()> {
    require_opt_in(opt_in)?;
    let _lock = lock_profile(profile_id)?;
    write_locked(profile_id, purpose, value, true)
}

/// Persist only after the caller obtained explicit user consent. On refusal,
/// the borrowed input remains with the caller for session-only authentication.
pub fn save_blocking(
    profile_id: Uuid,
    purpose: Purpose,
    value: &str,
    persistence_opt_in: bool,
) -> Result<()> {
    require_opt_in(persistence_opt_in)?;
    let _lock = lock_profile(profile_id)?;
    write_locked(profile_id, purpose, value, false)
}

fn require_opt_in(opt_in: bool) -> Result<()> {
    if opt_in {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::AuthorizationDenied,
            "Saving credentials requires explicit opt-in. Keep this input in memory for this session instead.",
        ))
    }
}

pub fn delete_blocking(profile_id: Uuid, purpose: Purpose) -> Result<()> {
    let _lock = lock_profile(profile_id)?;
    delete_locked(profile_id, purpose)
}

/// Idempotent removal of all known purposes. The metadata store calls this
/// while holding its own lock and removes metadata only after success.
/// Native keyrings have no multi-entry rollback; a failure may remove some
/// credentials, but retains profile metadata and makes a retry safe.
pub fn delete_profile_blocking(profile_id: Uuid) -> Result<()> {
    let _lock = lock_profile(profile_id)?;
    for purpose in Purpose::ALL {
        delete_locked(profile_id, purpose)?;
    }
    Ok(())
}

pub async fn get(profile_id: Uuid, purpose: Purpose) -> Result<Option<Zeroizing<String>>> {
    tokio::task::spawn_blocking(move || get_blocking(profile_id, purpose))
        .await
        .map_err(|_| unavailable())?
}

/// Borrow the caller's zeroizing input so a rejected save never consumes its
/// session-only value. The worker's necessary owned copy is also zeroized.
pub async fn save(
    profile_id: Uuid,
    purpose: Purpose,
    value: &Zeroizing<String>,
    persistence_opt_in: bool,
) -> Result<()> {
    require_opt_in(persistence_opt_in)?;
    let value = value.clone();
    tokio::task::spawn_blocking(move || {
        save_blocking(profile_id, purpose, value.as_str(), persistence_opt_in)
    })
    .await
    .map_err(|_| unavailable())?
}

pub async fn delete(profile_id: Uuid, purpose: Purpose) -> Result<()> {
    tokio::task::spawn_blocking(move || delete_blocking(profile_id, purpose))
        .await
        .map_err(|_| unavailable())?
}

pub async fn delete_profile(profile_id: Uuid) -> Result<()> {
    tokio::task::spawn_blocking(move || delete_profile_blocking(profile_id))
        .await
        .map_err(|_| unavailable())?
}

/// Owns the cross-process lock for upstream token read/generate/write callbacks.
/// Run the entire transaction on one blocking authentication worker. Never call
/// ordinary credential APIs for the same profile while holding this guard.
/// Only release a generated HOTP response after commit(Some(updated_seed))
/// succeeds; failure must abort authentication, not retry the old counter.
/// Dropping the guard or committing None cancels without changing the keyring.
/// The seed is the opaque upstream format, including its updated counter; no
/// separate counter file or OTP response is ever persisted.
#[must_use = "Keep the transaction alive through upstream token generation and commit"]
pub struct HotpTransaction {
    profile_id: Uuid,
    seed: Zeroizing<String>,
    non_interactive: bool,
    _lock: File,
}

impl HotpTransaction {
    pub fn begin(profile_id: Uuid, non_interactive: bool) -> Result<Self> {
        let lock = lock_profile(profile_id)?;
        let seed = read_locked(profile_id, Purpose::TokenSeed, non_interactive)?
            .filter(|seed| !seed.is_empty())
            .ok_or_else(|| Error::new(
                ErrorCode::AuthenticationRequired,
                "HOTP requires an explicitly saved seed in an unlocked, durable OS credential store. Save the seed with consent before authenticating; session-only counters are unsafe across processes.",
            ))?;
        Ok(Self {
            profile_id,
            seed,
            non_interactive,
            _lock: lock,
        })
    }

    /// The returned owner is zeroizing; begin already rejects an absent seed.
    pub fn seed(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(Some(self.seed.clone()))
    }

    /// Consume the guard to unlock after a durable write, or cancel with None.
    /// No opt-in is inferred here: begin requires the existing opted-in seed.
    pub fn commit(self, new_seed: Option<&str>) -> Result<()> {
        if let Some(seed) = new_seed {
            if seed.is_empty() {
                return Err(Error::invalid("The updated HOTP seed cannot be empty."));
            }
            write_locked(
                self.profile_id,
                Purpose::TokenSeed,
                seed,
                self.non_interactive,
            )?;
        }
        Ok(())
    }
}
