# Changelog

## 0.1.0

- Added the shared Rust OpenConnect engine, per-user profile/settings storage, opt-in OS credential storage, CLI, full-screen TUI, and native Tauri desktop.
- Added protocol-native forms, certificate decisions, token handling, GlobalProtect portal/gateway selection and independent authentication rounds, and isolated browser SSO. Embedded SSO rejects explicit pin policies that native webviews cannot enforce before credentials.
- Added a privileged service with machine-wide tunnel ownership, authenticated local IPC, journal-aware Unix script lifecycles, and transactional Linux/macOS/Windows networking backends.
- Added native package/source-install routes, protected service management, optional publisher signing, dependency/source/license inventories, and matching-platform release workflows.
- Added GitHub-hosted PR/branch CI and release preflight gates for matching versions, workspace tests, frontend builds, and native protocol fixtures. Releases retain native installation gates and publish only after draft asset upload/download checksum verification; interrupted drafts can be resumed without overwriting published releases.
- Made macOS release acceptance explicit: verified installation, code signatures, bundled protocols and a healthy pending-approval state; no automatic OS-consent bypass or claim of service startup/uninstall. Linux/Windows retain full idle lifecycle gates.
- Corrected hosted native build failures and Windows UTF-8 package metadata handling, pinned and bundled Windows pthreads, and moved macOS control/network-monitor endpoints beneath protected `/private/var/db` ancestors.
- Prepared Windows install roots before Tauri creates them, made silent installer failures abort without modal dialogs, and waited for the NSIS uninstaller's full process tree during native acceptance.
- Used authoritative draft-creation responses and portable Windows asset names to preserve GitHub publication and checksum invariants.
- Added real native protocol/browser fixtures and an isolated dual-stack ocserv lab covering packet traffic, DNS, route policy, crash recovery, typed event subscriptions, and quiet Linux keyring behavior.
- Corrected native integration failures found during execution: Debian lifecycle dispatch, restrictive-umask runtime-directory repair, openresolv 3.12/3.17 absent-record handling, systemd resolver write access, stale dialog errors, duplicated observation delivery, native dialog prerequisites, and TUI state/filter presentation.

Native observations and release acceptance boundaries are recorded in [native/VERIFICATION.md](native/VERIFICATION.md). macOS service approval/startup/uninstall and authorized platform/vendor-appliance interoperability are not inferred from source, compilation or idle installation checks.
