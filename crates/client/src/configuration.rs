use crate::{daemon, installation, private_fs, profiles::ProfileStore};
use directories::ProjectDirs;
use fs2::FileExt;
use ocvpn_model::{ConnectionState, Error, ErrorCode, Profile, Result, Settings, SettingsDocument};
use std::{fs::File, time::Duration};
use uuid::Uuid;

fn failed() -> Error {
    Error::new(
        ErrorCode::RuntimeFailure,
        "User configuration transaction failed",
    )
}
async fn lock(name: &'static str) -> Result<File> {
    let file = tokio::task::spawn_blocking(move || {
        let root = ProjectDirs::from("org", "OpenConnectGUI", "OpenConnectGUI")
            .ok_or_else(failed)?
            .data_local_dir()
            .join("operation-locks");
        private_fs::ensure_private_directory(&root)?;
        private_fs::open_private_lock(&root.join(name))
    })
    .await
    .map_err(|_| failed())??;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(Error::new(
                    ErrorCode::Busy,
                    "Another interface is changing this configuration; retry when it finishes",
                ));
            }
            Err(_) => return Err(failed()),
        }
    }
}

/// Keep this guard through the Reserve reply. Removal uses the same per-user lock.
pub(crate) async fn reserve_profile(profile: &Profile) -> Result<File> {
    let guard = lock("profile-use.lock").await?;
    let id = profile.id;
    let current =
        tokio::task::spawn_blocking(move || ProfileStore::open()?.resolve(&id.to_string()))
            .await
            .map_err(|_| failed())??;
    if &current != profile {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Profile changed before connection reservation. Reload it and retry.",
        ));
    }
    Ok(guard)
}

pub async fn remove_profile(id: Uuid, expected_revision: u64) -> Result<()> {
    let _guard = lock("profile-use.lock").await?;
    // An unavailable endpoint is not evidence that no tunnel owns this profile.
    let snapshot = daemon::snapshot().await?;
    let protected = if matches!(
        snapshot.state,
        ConnectionState::Authenticating
            | ConnectionState::Connecting
            | ConnectionState::Connected
            | ConnectionState::Reconnecting
            | ConnectionState::Disconnecting
    ) {
        snapshot.profile_id.into_iter().collect()
    } else {
        Vec::new()
    };
    tokio::task::spawn_blocking(move || {
        ProfileStore::open()?.remove(id, expected_revision, &protected)
    })
    .await
    .map_err(|_| failed())?
}

pub async fn save_settings(settings: Settings, expected_revision: u64) -> Result<SettingsDocument> {
    let _guard = lock("login-settings.lock").await?;
    let before = tokio::task::spawn_blocking(|| ProfileStore::open()?.settings())
        .await
        .map_err(|_| failed())??;
    if before.revision != expected_revision {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Settings changed; reload before saving",
        ));
    }
    if let Some(id) = settings.auto_connect_profile_id {
        tokio::task::spawn_blocking(move || ProfileStore::open()?.resolve(&id.to_string()))
            .await
            .map_err(|_| failed())??;
    }
    let desired = settings.start_at_login;
    let changed = desired != before.settings.start_at_login;
    let native_before = if changed {
        Some(installation::status().await?.login_registered)
    } else {
        None
    };
    if changed {
        installation::set_login_enabled(desired).await?;
    }
    // Join failure is a storage failure too: do not bypass native rollback.
    let saved = tokio::task::spawn_blocking(move || {
        ProfileStore::open()?.save_settings(settings, expected_revision)
    })
    .await
    .unwrap_or_else(|_| Err(failed()));
    if saved.is_err() {
        if let Some(previous) = native_before {
            let current = installation::status().await.map_err(|_| Error::new(ErrorCode::RecoveryRequired, "Settings were not saved and login registration could not be checked; review Login Items before retrying"))?;
            if current.login_registered != desired {
                return Err(Error::new(
                    ErrorCode::RecoveryRequired,
                    "Concurrent login registration change preserved; reload settings and review Login Items",
                ));
            }
            installation::set_login_enabled(previous).await.map_err(|_| Error::new(ErrorCode::RecoveryRequired, "Settings were not saved and login registration could not be restored; review Login Items"))?;
        }
    }
    saved
}
