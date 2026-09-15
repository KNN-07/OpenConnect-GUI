// SPDX-License-Identifier: GPL-3.0-only
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "profiles",
            "new_profile",
            "save_profile",
            "duplicate_profile",
            "remove_profile",
            "import_profiles",
            "export_profiles",
            "choose_certificate",
            "read_settings",
            "save_settings",
            "forget_credentials",
            "doctor",
            "manage_service",
            "approval_settings",
            "disconnect",
            "snapshot",
            "observe",
            "begin_connection",
            "cancel_connection",
            "auth_reply",
            "certificate_reply",
            "browser_reply",
            "browser_clipboard",
            "export_diagnostics",
            "quit_ui",
            "licenses",
        ]),
    ))
    .expect("could not prepare desktop assets and command permissions");
}
