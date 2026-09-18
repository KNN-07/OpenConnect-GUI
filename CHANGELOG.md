# Changelog

## 0.1.0

- Added the shared Rust OpenConnect engine, per-user profile/settings storage, opt-in OS credential storage, CLI, full-screen TUI, and native Tauri desktop.
- Added protocol-native forms, certificate decisions, token handling, GlobalProtect portal/gateway selection and independent authentication rounds, and isolated browser SSO. Embedded SSO rejects explicit pin policies that native webviews cannot enforce before credentials.
- Added a privileged service with machine-wide tunnel ownership, authenticated local IPC, journal-aware Unix script lifecycles, and transactional Linux/macOS/Windows networking backends.
- Added native package/source-install routes, protected service management, optional publisher signing, dependency/source/license inventories, and matching-platform release workflows.
- Added GitHub-hosted PR/branch CI and release preflight gates for matching versions, workspace tests, frontend builds, and native protocol fixtures. Releases retain native installation gates and publish only after draft asset upload/download checksum verification; interrupted drafts can be resumed without overwriting published releases.
- Added real native protocol/browser fixtures and an isolated dual-stack ocserv lab covering packet traffic, DNS, route policy, crash recovery, typed event subscriptions, and quiet Linux keyring behavior.
- Corrected native integration failures found during execution: Debian lifecycle dispatch, restrictive-umask runtime-directory repair, openresolv 3.12/3.17 absent-record handling, systemd resolver write access, stale dialog errors, duplicated observation delivery, native dialog prerequisites, and TUI state/filter presentation.

Linux native, package, UI, and VPN observations are recorded in [native/VERIFICATION.md](native/VERIFICATION.md). Native macOS/Windows and authorized vendor-appliance interoperability remain explicitly unverified rather than inferred from source or compilation.
