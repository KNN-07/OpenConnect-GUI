use crate::{TransactionId, platform, secure};
use fs2::FileExt;
use ocvpn_model::{Error, ErrorCode, NetworkConfig, NetworkObservation, NetworkReason, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Key {
    pub kind: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mutation {
    pub key: Key,
    pub before: Option<Value>,
    pub intended: Option<Value>,
    pub applied: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    transaction: TransactionId,
    boot_id: String,
    config: NetworkConfig,
    mutations: Vec<Mutation>,
    /// A crash before observation must not silently treat an unexpected missing
    /// value as an administrator's intentional deletion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_operation: Option<usize>,
}
fn error() -> Error {
    Error::new(
        ErrorCode::RecoveryRequired,
        "Network transaction journal requires recovery",
    )
}
fn root() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(secure::journal_root())
    }
    #[cfg(windows)]
    {
        platform::journal_root()
    }
}
fn path(t: TransactionId) -> Result<PathBuf> {
    Ok(root()?.join(format!("{}-{}.json", t.service_instance_id, t.attempt_id)))
}
fn lock() -> Result<File> {
    secure::directory(&root()?)?;
    let file = secure::open(&root()?.join("lock"), true)?;
    file.lock_exclusive().map_err(|_| error())?;
    Ok(file)
}
fn load(t: TransactionId) -> Result<Option<Journal>> {
    let p = path(t)?;
    if !p.try_exists().map_err(|_| error())? {
        return Ok(None);
    }
    let file = secure::open(&p, false)?;
    if file.metadata().map_err(|_| error())?.len() > 16 * 1024 * 1024 {
        return Err(error());
    }
    let j: Journal = serde_json::from_reader(file.take(16 * 1024 * 1024)).map_err(|_| error())?;
    if j.version != 1
        || j.transaction != t
        || j.mutations.len() > 8192
        || j.pending_operation
            .is_some_and(|index| index >= j.mutations.len())
    {
        return Err(error());
    }
    j.config.validate()?;
    Ok(Some(j))
}
fn save(j: &Journal) -> Result<()> {
    let p = path(j.transaction)?;
    let tmp = p.with_extension("pending");
    let mut file = secure::open(&tmp, true)?;
    file.set_len(0).map_err(|_| error())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| error())?;
    serde_json::to_writer(&mut file, j).map_err(|_| error())?;
    if file.metadata().map_err(|_| error())?.len() > 16 * 1024 * 1024 {
        return Err(error());
    }
    file.flush()
        .and_then(|_| file.sync_all())
        .map_err(|_| error())?;
    #[cfg(unix)]
    std::fs::rename(&tmp, &p).map_err(|_| error())?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let a: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let b: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
        drop(file);
        if unsafe {
            MoveFileExW(
                a.as_ptr(),
                b.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(error());
        }
    }
    secure::sync_directory(&root()?)
}
fn equal(key: &Key, a: Option<&Value>, b: Option<&Value>) -> bool {
    platform::equivalent(key, a, b)
}
fn restore_one(j: &Journal, index: usize, same_boot: bool) -> Result<()> {
    let m = &j.mutations[index];
    if platform::vanished(&m.key)? {
        return Ok(());
    }
    let current = platform::read(&m.key)?;
    if equal(&m.key, current.as_ref(), m.before.as_ref()) {
        return Ok(());
    }
    if j.pending_operation == Some(index) && !equal(&m.key, current.as_ref(), m.intended.as_ref()) {
        return Err(Error::new(
            ErrorCode::RecoveryRequired,
            "Interrupted network mutation has unobserved state; preserved for explicit recovery",
        ));
    }
    if current.is_none() && m.intended.is_some() {
        return Ok(());
    }
    if !same_boot {
        if current.is_none() {
            return Ok(());
        }
        let persistent_owned = m.key.kind == "win-nrpt"
            && m.applied
                .as_ref()
                .and_then(|v| v.get("names"))
                .and_then(Value::as_array)
                .is_some_and(|names| !names.is_empty());
        if !persistent_owned {
            return Err(Error::new(
                ErrorCode::RecoveryRequired,
                "Network interface identity belongs to a previous OS boot; current state preserved",
            ));
        }
    }
    let owned = m.applied.as_ref().or(m.intended.as_ref());
    if !equal(&m.key, current.as_ref(), owned) {
        return Err(Error::new(
            ErrorCode::RecoveryRequired,
            "Concurrent network change preserved; retry service repair after resolving conflict",
        ));
    }
    #[cfg(unix)]
    platform::write(&m.key, m.before.as_ref())?;
    #[cfg(windows)]
    platform::restore(&m.key, m.before.as_ref(), current.as_ref())?;
    if !equal(&m.key, platform::read(&m.key)?.as_ref(), m.before.as_ref()) {
        return Err(error());
    }
    Ok(())
}
fn restore(j: &mut Journal) -> Result<Vec<Error>> {
    let mut warnings = Vec::new();
    let same_boot = j.boot_id == secure::boot_id()?;
    #[cfg(unix)]
    if same_boot {
        // Normal teardown executes the real pinned disconnect orchestration.
        // Each mutation site conditionally restores only journal-owned state.
        if let Err(e) = platform::apply_script(
            &j.config,
            NetworkReason::Disconnect,
            &j.mutations,
            |index| restore_one(j, index, same_boot),
        ) {
            warnings.push(e);
        }
    }
    // Also repair partial/crashed setup, including an unavailable script.
    // Reverse-order conditional recovery must not depend on shell completion.
    for index in (0..j.mutations.len()).rev() {
        if let Err(e) = restore_one(j, index, same_boot) {
            warnings.push(e);
        }
    }
    if warnings.is_empty() {
        std::fs::remove_file(path(j.transaction)?).map_err(|_| error())?;
        secure::sync_directory(&root()?)?;
    }
    Ok(warnings)
}
pub(crate) fn recover(t: TransactionId) -> Result<Vec<Error>> {
    secure::privileged()?;
    let _lock = lock()?;
    match load(t)? {
        Some(mut j) => restore(&mut j),
        None => Ok(Vec::new()),
    }
}
pub(crate) fn recover_all() -> Result<Vec<Error>> {
    secure::privileged()?;
    let _lock = lock()?;
    let mut warnings = Vec::new();
    for entry in std::fs::read_dir(root()?).map_err(|_| error())? {
        let entry = entry.map_err(|_| error())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(error());
        };
        if !name.ends_with(".json") {
            continue;
        }
        let stem = &name[..name.len() - 5];
        if stem.len() != 73 || stem.as_bytes()[36] != b'-' {
            return Err(error());
        }
        let t = TransactionId {
            service_instance_id: stem[..36].parse().map_err(|_| error())?,
            attempt_id: stem[37..].parse().map_err(|_| error())?,
        };
        if let Some(mut j) = load(t)? {
            warnings.extend(restore(&mut j)?);
        }
    }
    Ok(warnings)
}
pub(crate) fn lifecycle(
    t: TransactionId,
    input: crate::LifecycleInput,
) -> Result<Option<NetworkObservation>> {
    secure::privileged()?;
    let _lock = lock()?;
    if matches!(
        input.reason,
        NetworkReason::PreInit | NetworkReason::AttemptReconnect
    ) {
        return Ok(None);
    }
    if let Some(mut j) = load(t)? {
        let warnings = restore(&mut j)?;
        if !warnings.is_empty() {
            return Err(error());
        }
    }
    if input.reason == NetworkReason::Disconnect {
        return Ok(None);
    }
    for entry in std::fs::read_dir(root()?).map_err(|_| error())? {
        let entry = entry.map_err(|_| error())?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            return Err(error());
        }
    }
    let config = input
        .config
        .ok_or_else(|| crate::failure("Missing negotiated network configuration"))?;
    let mutations = platform::plan(&config, t)?;
    if mutations.len() > 8192 {
        return Err(crate::failure("Network transaction exceeds mutation limit"));
    }
    let mut j = Journal {
        version: 1,
        transaction: t,
        boot_id: secure::boot_id()?,
        config,
        mutations,
        pending_operation: None,
    };
    save(&j)?;
    #[cfg(unix)]
    let apply = (|| {
        for m in &j.mutations {
            if platform::read(&m.key)? != m.before {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "Network state changed after transaction planning",
                ));
            }
        }
        let config = j.config.clone();
        let inventory = j.mutations.clone();
        platform::apply_script(&config, input.reason, &inventory, |index| {
            // Full preflight intent is durable before the shell starts. Persist
            // each observed result BEFORE acknowledging its mutation site.
            j.pending_operation = Some(index);
            save(&j)?;
            j.mutations[index].applied = platform::apply_one(&config, &inventory[index])?;
            j.pending_operation = None;
            save(&j)
        })
    })();
    #[cfg(windows)]
    let apply = platform::apply_planned(&j.mutations);
    let verified = (|| {
        apply?;
        for index in 0..j.mutations.len() {
            let m = &j.mutations[index];
            let actual = platform::read(&m.key)?;
            if !equal(&m.key, actual.as_ref(), m.intended.as_ref()) {
                return Err(crate::failure(
                    "Applied network configuration did not match operating system state",
                ));
            }
            j.mutations[index].applied = actual;
        }
        save(&j)?;
        platform::observe(&j.config)
    })();
    match verified {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            let warnings = restore(&mut j)?;
            if warnings.is_empty() {
                Err(e)
            } else {
                Err(error())
            }
        }
    }
}
