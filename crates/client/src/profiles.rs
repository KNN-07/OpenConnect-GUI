//! Blocking per-user metadata storage. Call from a blocking worker, never a UI thread.
use crate::private_fs;
use directories::ProjectDirs;
use fs2::FileExt;
use ocvpn_model::{
    CertificatePin, Error, ErrorCode, PinsDocument, Profile, ProfileDocument, ProfileExport,
    Result, Settings, SettingsDocument,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct ProfileStore {
    directory: PathBuf,
}

fn failure(path: &Path, code: ErrorCode, message: &str) -> Error {
    let mut error = Error::new(code, message);
    error.details = Some(path.display().to_string());
    error
}
fn increment(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorCode::Conflict, "Metadata revision exhausted"))
}
fn stale(actual: u64, expected: u64) -> Result<()> {
    if actual != expected {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Metadata changed; reload before saving",
        ));
    }
    Ok(())
}
fn select<'a>(profiles: &'a [Profile], selector: &str) -> Result<&'a Profile> {
    let found = match Uuid::parse_str(selector) {
        Ok(id) => profiles.iter().find(|p| p.id == id),
        Err(_) => profiles.iter().find(|p| p.name == selector),
    };
    found.ok_or_else(|| Error::new(ErrorCode::NotFound, "Profile does not exist"))
}
fn validate_profiles(profiles: &[Profile]) -> Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for profile in profiles {
        profile.validate()?;
        if !ids.insert(profile.id) || !names.insert(&profile.name) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Duplicate profile ID or name",
            ));
        }
    }
    Ok(())
}

impl ProfileStore {
    pub fn open() -> Result<Self> {
        let directory = match std::env::var_os("OCVPN_CONFIG_DIR") {
            Some(path) => PathBuf::from(path),
            None => ProjectDirs::from("org", "OpenConnectGUI", "OpenConnectGUI")
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::RuntimeFailure,
                        "Cannot locate user configuration directory",
                    )
                })?
                .config_dir()
                .to_owned(),
        };
        Self::from_directory(directory)
    }
    /// Overrides unprivileged metadata only; never service or credential lock locations.
    pub fn from_directory(directory: PathBuf) -> Result<Self> {
        private_fs::ensure_private_directory(&directory)?;
        Ok(Self { directory })
    }
    fn lock(&self) -> Result<File> {
        private_fs::ensure_private_directory(&self.directory)?;
        let path = self.directory.join("metadata.lock");
        let file = private_fs::open_private_lock(&path)?;
        file.lock_exclusive()
            .map_err(|_| failure(&path, ErrorCode::RuntimeFailure, "Cannot lock metadata"))?;
        Ok(file)
    }
    fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.directory.join(name);
        let Some(file) = private_fs::open_private_read(&path)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure(&path, ErrorCode::RuntimeFailure, "Cannot read metadata"))?;
        decode(&bytes, &path).map(Some)
    }
    fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.directory.join(name);
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|_| failure(&path, ErrorCode::InvalidInput, "Cannot encode metadata"))?;
        if bytes.len() as u64 > LIMIT {
            return Err(failure(
                &path,
                ErrorCode::InvalidInput,
                "Metadata exceeds size limit",
            ));
        }
        private_fs::atomic_write(&path, &bytes, true)
    }
    fn profiles_unlocked(&self) -> Result<ProfileDocument> {
        let document = self.read("profiles.json")?.unwrap_or(ProfileDocument {
            schema_version: 1,
            revision: 0,
            profiles: vec![],
        });
        validate_profiles(&document.profiles).map_err(|_| {
            failure(
                &self.directory.join("profiles.json"),
                ErrorCode::CorruptStorage,
                "Invalid stored profiles; repair or restore this file",
            )
        })?;
        Ok(document)
    }
    fn commit(&self, document: &mut ProfileDocument) -> Result<()> {
        document.revision = increment(document.revision)?;
        self.write("profiles.json", document)
    }
    pub fn list(&self) -> Result<ProfileDocument> {
        let _lock = self.lock()?;
        self.profiles_unlocked()
    }
    pub fn resolve(&self, selector: &str) -> Result<Profile> {
        Ok(select(&self.list()?.profiles, selector)?.clone())
    }
    pub fn create(&self, mut profile: Profile) -> Result<Profile> {
        let _lock = self.lock()?;
        let mut document = self.profiles_unlocked()?;
        profile.revision = 1;
        profile.validate()?;
        document.profiles.push(profile.clone());
        validate_profiles(&document.profiles)?;
        self.commit(&mut document)?;
        Ok(profile)
    }
    pub fn update(&self, mut profile: Profile) -> Result<Profile> {
        let _lock = self.lock()?;
        let mut document = self.profiles_unlocked()?;
        profile.validate()?;
        let index = document
            .profiles
            .iter()
            .position(|p| p.id == profile.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "Profile does not exist"))?;
        stale(document.profiles[index].revision, profile.revision)?;
        profile.revision = increment(profile.revision)?;
        document.profiles[index] = profile.clone();
        validate_profiles(&document.profiles)?;
        self.commit(&mut document)?;
        Ok(profile)
    }
    pub fn duplicate(&self, selector: &str, name: &str) -> Result<Profile> {
        let _lock = self.lock()?;
        let mut document = self.profiles_unlocked()?;
        let mut profile = select(&document.profiles, selector)?.clone();
        profile.id = Uuid::new_v4();
        profile.revision = 1;
        profile.name = name.to_owned();
        document.profiles.push(profile.clone());
        validate_profiles(&document.profiles)?;
        self.commit(&mut document)?;
        Ok(profile)
    }
    pub fn remove(&self, id: Uuid, expected_revision: u64, protected: &[Uuid]) -> Result<()> {
        let _lock = self.lock()?;
        if protected.contains(&id) {
            return Err(Error::new(
                ErrorCode::Busy,
                "Cannot remove an active or pending profile",
            ));
        }
        let mut document = self.profiles_unlocked()?;
        let index = document
            .profiles
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "Profile does not exist"))?;
        stale(document.profiles[index].revision, expected_revision)?;
        increment(document.revision)?;
        crate::credentials::delete_profile_blocking(id)?;
        document.profiles.remove(index);
        self.commit(&mut document)
    }
    pub fn import_json(&self, bytes: &[u8]) -> Result<Vec<Profile>> {
        let mut imported: ProfileExport = decode(bytes, Path::new("<profile import>"))?;
        for profile in &mut imported.profiles {
            profile.revision = 1;
            profile.validate()?;
        }
        let _lock = self.lock()?;
        let mut document = self.profiles_unlocked()?;
        let mut ids: HashSet<_> = document.profiles.iter().map(|p| p.id).collect();
        let mut names: HashSet<_> = document.profiles.iter().map(|p| p.name.clone()).collect();
        let mut conflicts = Vec::new();
        for profile in &imported.profiles {
            if !ids.insert(profile.id) {
                conflicts.push(format!("duplicate ID {}", profile.id));
            }
            if !names.insert(profile.name.clone()) {
                conflicts.push(format!("duplicate name {}", profile.name));
            }
        }
        if !conflicts.is_empty() {
            let mut error = Error::new(
                ErrorCode::Conflict,
                "Import conflicts; no profiles were imported",
            );
            error.details = Some(conflicts.join("; "));
            return Err(error);
        }
        document.profiles.extend(imported.profiles.iter().cloned());
        self.commit(&mut document)?;
        Ok(imported.profiles)
    }
    pub fn export_json(&self, selector: Option<&str>) -> Result<Vec<u8>> {
        let document = self.list()?;
        let profiles = match selector {
            Some(s) => vec![select(&document.profiles, s)?.clone()],
            None => document.profiles,
        };
        serde_json::to_vec_pretty(&ProfileExport {
            schema_version: 1,
            profiles,
        })
        .map_err(|_| Error::new(ErrorCode::RuntimeFailure, "Cannot encode profile export"))
    }
    pub fn export_file(&self, selector: Option<&str>, path: &Path, force: bool) -> Result<()> {
        private_fs::atomic_write(path, &self.export_json(selector)?, force)
    }
    pub fn settings(&self) -> Result<SettingsDocument> {
        let _lock = self.lock()?;
        Ok(self.read("settings.json")?.unwrap_or(SettingsDocument {
            schema_version: 1,
            revision: 0,
            settings: Settings::default(),
        }))
    }
    pub fn save_settings(
        &self,
        settings: Settings,
        expected_revision: u64,
    ) -> Result<SettingsDocument> {
        let _lock = self.lock()?;
        let old: Option<SettingsDocument> = self.read("settings.json")?;
        let revision = old.map_or(0, |d| d.revision);
        stale(revision, expected_revision)?;
        if let Some(id) = settings.auto_connect_profile_id {
            if !self
                .profiles_unlocked()?
                .profiles
                .iter()
                .any(|p| p.id == id)
            {
                return Err(Error::new(
                    ErrorCode::NotFound,
                    "Auto-connect profile does not exist",
                ));
            }
        }
        let document = SettingsDocument {
            schema_version: 1,
            revision: increment(revision)?,
            settings,
        };
        self.write("settings.json", &document)?;
        Ok(document)
    }
    fn pins_unlocked(&self) -> Result<PinsDocument> {
        let document: PinsDocument = self.read("certificate-pins.json")?.unwrap_or(PinsDocument {
            schema_version: 1,
            revision: 0,
            pins: vec![],
        });
        let mut hosts = HashSet::new();
        for pin in &document.pins {
            let normalized = CertificatePin::new(&pin.host, pin.port, pin.fingerprint.clone())
                .map_err(|_| {
                    failure(
                        &self.directory.join("certificate-pins.json"),
                        ErrorCode::CorruptStorage,
                        "Invalid stored certificate pin",
                    )
                })?;
            if normalized != *pin || !hosts.insert((&pin.host, pin.port)) {
                return Err(failure(
                    &self.directory.join("certificate-pins.json"),
                    ErrorCode::CorruptStorage,
                    "Invalid or duplicate stored certificate pin",
                ));
            }
        }
        Ok(document)
    }
    pub fn pins(&self) -> Result<PinsDocument> {
        let _lock = self.lock()?;
        self.pins_unlocked()
    }
    pub fn save_pin(&self, pin: CertificatePin, expected_revision: u64) -> Result<PinsDocument> {
        let pin = CertificatePin::new(&pin.host, pin.port, pin.fingerprint)?;
        let _lock = self.lock()?;
        let mut document = self.pins_unlocked()?;
        stale(document.revision, expected_revision)?;
        if let Some(existing) = document
            .pins
            .iter_mut()
            .find(|p| p.host == pin.host && p.port == pin.port)
        {
            *existing = pin;
        } else {
            document.pins.push(pin);
        }
        document.revision = increment(document.revision)?;
        self.write("certificate-pins.json", &document)?;
        Ok(document)
    }
}
fn decode<T: DeserializeOwned>(bytes: &[u8], path: &Path) -> Result<T> {
    if bytes.len() as u64 > LIMIT {
        return Err(failure(
            path,
            ErrorCode::CorruptStorage,
            "Metadata exceeds size limit",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        failure(
            path,
            ErrorCode::CorruptStorage,
            "Malformed metadata; repair or restore this file",
        )
    })?;
    match value.get("schema_version").and_then(|v| v.as_u64()) {
        Some(1) => {}
        Some(v) if v > 1 => {
            return Err(failure(
                path,
                ErrorCode::NewerSchema,
                "Metadata requires a newer application version",
            ));
        }
        _ => {
            return Err(failure(
                path,
                ErrorCode::CorruptStorage,
                "Invalid metadata schema version",
            ));
        }
    }
    if value
        .get("revision")
        .is_some_and(|v| v.as_u64().is_none_or(|n| n == 0))
    {
        return Err(failure(
            path,
            ErrorCode::CorruptStorage,
            "Invalid metadata revision",
        ));
    }
    serde_json::from_value(value).map_err(|_| {
        failure(
            path,
            ErrorCode::CorruptStorage,
            "Invalid metadata document; repair or restore this file",
        )
    })
}
