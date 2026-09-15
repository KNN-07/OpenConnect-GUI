use ocvpn_client::profiles::ProfileStore;
use ocvpn_model::{ErrorCode, Profile, ProfileExport};
use uuid::Uuid;

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("ocvpn-profiles-{}", Uuid::new_v4())))
    }
    fn store(&self) -> ProfileStore {
        ProfileStore::from_directory(self.0.clone()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn profile(name: &str) -> Profile {
    Profile::new(
        name.to_owned(),
        "https://vpn.example.test/pulse".parse().unwrap(),
        "future-protocol".to_owned(),
    )
}

#[test]
fn stale_profile_edit_cannot_overwrite_another_store() {
    let fixture = Fixture::new();
    let first = fixture.store();
    let second = fixture.store();
    let mut saved = first.create(profile("Original")).unwrap();
    let mut stale = second.resolve(&saved.id.to_string()).unwrap();
    saved.name = "Current".to_owned();
    let current = first.update(saved).unwrap();
    stale.name = "Lost edit".to_owned();
    assert_eq!(second.update(stale).unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(second.resolve(&current.id.to_string()).unwrap(), current);
}

#[test]
fn conflicting_import_is_all_or_nothing() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let original = store.create(profile("Existing")).unwrap();
    let before = std::fs::read(fixture.0.join("profiles.json")).unwrap();
    let document = ProfileExport {
        schema_version: 1,
        profiles: vec![profile("New"), profile("Existing"), original],
    };
    assert_eq!(
        store
            .import_json(&serde_json::to_vec(&document).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        std::fs::read(fixture.0.join("profiles.json")).unwrap(),
        before
    );
    assert_eq!(store.resolve("New").unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn malformed_and_newer_files_remain_untouched() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.create(profile("Existing")).unwrap();
    let path = fixture.0.join("profiles.json");
    for (bytes, code) in [
        (b"{broken".as_slice(), ErrorCode::CorruptStorage),
        (b"{\"schema_version\":2}".as_slice(), ErrorCode::NewerSchema),
    ] {
        // Write into the existing private inode without changing its permissions.
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(store.create(profile("New")).unwrap_err().code, code);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn settings_revision_prevents_lost_edits() {
    let fixture = Fixture::new();
    let first = fixture.store();
    let second = fixture.store();
    let initial = first.settings().unwrap();
    let mut next = initial.settings.clone();
    next.close_to_tray = false;
    let saved = first.save_settings(next, initial.revision).unwrap();
    assert_eq!(
        second
            .save_settings(initial.settings, initial.revision)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(second.settings().unwrap(), saved);
}

#[test]
fn pin_bearing_metadata_is_neither_committed_nor_exported() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let original = store.create(profile("Existing")).unwrap();
    let path = fixture.0.join("profiles.json");
    let before = std::fs::read(&path).unwrap();
    let mut unsafe_profile = original.clone();
    unsafe_profile.secondary_key =
        Some("pkcs11:object=key?pin-source=file%3A%2Fprivate%2Fpin".into());
    assert_eq!(
        store.update(unsafe_profile.clone()).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    unsafe_profile.id = Uuid::new_v4();
    unsafe_profile.name = "Imported".into();
    assert_eq!(
        store.create(unsafe_profile.clone()).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    let import = ProfileExport {
        schema_version: 1,
        profiles: vec![profile("Safe"), unsafe_profile],
    };
    assert_eq!(
        store
            .import_json(&serde_json::to_vec(&import).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);

    // A file saved by an older build is retained for repair, not exported.
    let mut legacy: serde_json::Value = serde_json::from_slice(&before).unwrap();
    legacy["profiles"][0]["client_certificate"] = "pkcs11:object=cert?pin-value=123456".into();
    let legacy = serde_json::to_vec(&legacy).unwrap();
    std::fs::write(&path, &legacy).unwrap();
    assert_eq!(
        store.export_json(None).unwrap_err().code,
        ErrorCode::CorruptStorage
    );
    assert_eq!(std::fs::read(&path).unwrap(), legacy);
}
