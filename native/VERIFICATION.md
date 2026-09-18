# Verification and acceptance boundaries

This file distinguishes source/build checks, local native fixtures, actual VPN traffic, native interfaces, and authorized appliance interoperability. A protocol appearing in `ocvpn protocols`, a successful compilation, or a TLS/authentication fixture is not a successful VPN connection.

## Exercised Linux behavior

The development runner is Linux x86_64. Its development binaries use the host GLIBC and are not portable release artifacts. Separate release packages were built inside the pinned Ubuntu 22.04 / GLIBC 2.35 baseline image.

| Surface | Observed proof |
|---|---|
| Shared engine | All seven protocol IDs are discovered from the bundled native OpenConnect library. Native authentication fixtures cover AnyConnect, Network Connect, Pulse, GlobalProtect, F5, and Fortinet; Array has negative TLS coverage only. |
| TLS and native ownership | Strict certificate/peer-policy cases, descriptor ownership, and SIGPIPE/EPIPE handling were exercised against native fixtures. |
| HOTP | Native request observation verifies that an OTP is withheld when counter persistence fails and that successful counter advancement precedes submission. |
| Browser SSO | Native Tauri/WebKit browser fixtures exercise same-account/different-account isolation, independent GlobalProtect portal/gateway rounds, callback isolation, and rejection without password fallback. These are local fixtures, not identity-provider certification. |
| Actual VPN | Isolated ocserv establishes real Linux tunnels. Both split and full routes carry IPv4 and IPv6 HTTP traffic; the system resolver resolves the internal dual-stack DNS name; observed RX/TX byte counters increase during transfers. Disconnect restores the exact captured route/address/MTU/DNS baseline. |
| Failure recovery | Actual worker and daemon termination exercise owned-script/journal recovery while preserving an unrelated route. A real server outage is observable. When an ocserv restart invalidates the cookie, the client reports authentication required rather than inventing reconnect success. |
| Shared interfaces | A native desktop edit changed the same profile/revision observed by CLI and TUI. A stale update failed with `conflict`. A native desktop-authenticated tunnel appeared in TUI with the same session UUID and negotiated addresses. |
| UI lifetime | Actual GUI close and TUI `q` left the established service-owned tunnel and VPN-only HTTP working. TUI disconnect removed the route and made the internal endpoint unreachable. |
| TUI terminal | Actual PTY navigation, native authentication, bracketed secret paste, log filtering/scrolling, narrow/normal layouts, and `NO_COLOR` were exercised. Terminal attributes were identical after exit; the captured terminal stream left the alternate screen and restored the cursor without containing the lab password. |
| Desktop layout | The actual native desktop was inspected at its 760×560 minimum size, including dark theme, profile editing, credentials, authentication, and connected state. Browser-only frontend previews are not counted as this proof. |
| Quiet Linux keyring | A real private Secret Service/keyring session created and read a stored password without a Prompt call, negotiated the encrypted DH session, and failed closed with `authentication_required` / exit 3 when the collection was locked. No Plain session fallback was observed. |
| Baseline package | A clean Ubuntu 22.04 systemd container, without preinstalled OpenConnect or host mounts, installed the real GUI `.deb`; installed protocols and doctor reported the real engine and registered/running service. The guarded same-version package upgrade also completed. |
| Interrupted installation | Native service repair recreated an absent fixed runtime directory under a restrictive umask and started the actual systemd service. Existing untrusted directory permissions are not silently changed. |
| Baseline resolver | The upgraded systemd package established a real tunnel with Ubuntu 22.04's openresolv 3.12. This separately exercises its absent-record exit status and the service's writable resolver policy; the development lab uses a newer resolver. |
| Active package removal | The real GUI `.deb` carried IPv4/IPv6 HTTP and system DNS traffic with increasing RX/TX counters. `dpkg --remove` while connected stopped the service, removed package files, and exactly restored networking. |
| CLI interruption | The installed CLI returned exit 130 and exactly restored networking for Ctrl-C on a connected foreground session, in an actual authentication PTY, and while its verified native network helper was paused during `connecting`. |
| Source installation | The standalone CLI source installer registered the real systemd service, passed installed doctor, carried dual-stack traffic, and exactly restored networking when uninstalled while connected. |
| Fedora RPM | The baseline CLI RPM installed on a clean Fedora 42 systemd reference without a preinstalled OpenConnect client or GTK/WebKit. Installed discovery reported all seven protocols; doctor reported a running service. Actual RPM removal stopped the service and removed the package. |
| Native file dialogs | The native GTK portal imported a new profile that the CLI could read, and exported valid selected-profile metadata without the private lab password. Invalid imported JSON produced an actionable error without replacing stored profiles. |
| Typed observation streams | The real native regression failed before the fix because status subscribers received log events. After the shared-client fix, status and log consumers received only their requested event kinds; the actual TUI displayed each log once. |
| Desktop finishing checks | Actual 2× native dark-mode rendering, installed About/license inventory, first-close messaging, and new-dialog error reset were exercised. GUI close retained the same connected session and working VPN HTTP traffic. |

Generated execution evidence was collected under `target/ocvpn-lab/`, `target/browser-verification/`, and `target/release-proof/`. Temporary build/lab data is removed during cleanup; representative actual screenshots are retained in `native/screenshots/`. Re-run the commands below to generate fresh evidence.

The earlier local full-workspace run was interrupted by disk exhaustion. Subsequent [GitHub-hosted CI](https://github.com/KNN-07/OpenConnect-GUI/actions/runs/35336709177) completed the locked full-workspace tests, Clippy, frontend build and native protocol fixtures, plus native Windows/MSVC and macOS Intel/ARM Rust compilation. Each release requires a fresh successful CI run.

## Reproducible entrypoints

See [packaging/README.md](../packaging/README.md) for native prerequisites and matching-target builds. From the repository root:

```sh
cargo xtask native build --target host
cargo xtask build --target host
cargo test -p ocvpn-model -p ocvpn-engine -p ocvpn-client -p ocvpn-service -p ocvpn-net
cargo xtask verify protocols
cargo xtask verify browser
cargo xtask lab up
cargo xtask verify tunnel --profile lab
cargo xtask lab down
```

The Linux lab owns a labeled container and refuses to operate on a mismatched ownership record. It has no host network or host filesystem mounts. Host networking is not used as a disposable test environment. Lab image identities and recipe hashes are locked; if the recipe changes, preserve the evidence and explicitly remove the old lock before rebuilding it.

The quiet-keyring scenario is part of the tunnel verifier. Its standalone helper refuses to run outside the expected unprivileged lab user and supervisor. It never locks the developer's login keyring.

For native installation smoke checks on an explicitly disposable matching OS runner:

```sh
OCVPN_DISPOSABLE_RUNNER=1 python3 packaging/smoke.py PACKAGE
```

Without additional options, that command requires installed protocols/doctor/service state and idle uninstall, not GUI behavior or live-tunnel removal. GitHub-hosted macOS release checks explicitly use `--allow-macos-pending-approval`: installation, code signatures, bundled protocols and a healthy registered/pending-approval state are required, but OS approval, service startup and uninstall remain manual acceptance. Engine, driver and endpoint-trust errors are not accepted as pending approval. Linux/Windows retain full idle lifecycle checks. Publication is gated on these stated boundaries in `.github/workflows/release.yml`.

## Native platform boundaries

| Platform | Status |
|---|---|
| Linux x86_64 | Native development application, local protocol/browser fixtures, isolated ocserv traffic/recovery, and Ubuntu 22.04 baseline package execution exercised as described above. |
| macOS Intel | Native Rust compilation, source-built packages, installed bundled CLI/protocol discovery, code-signature verification and registered/pending-approval state exercised on GitHub-hosted macOS 15. Explicit Login Items approval, service startup/uninstall, utun/DNS recovery, keychain, desktop and tunnel acceptance remain manual. |
| macOS Apple Silicon | The same build, installation and bundled-engine observations were independently exercised on GitHub-hosted ARM macOS 15, not inferred from Intel. The same manual-acceptance boundaries apply. |
| Windows x86_64 | Native Windows/MSVC Rust compilation and MinGW OpenConnect compilation exercised. Publication additionally requires actual native package installation, installed doctor/service checks and idle uninstall. Wintun/NRPT networking, desktop and tunnel acceptance are not inferred from those idle checks. |

Unsigned application builds retain the same functionality. OS warnings, explicit native approval, administrator authorization, and organizational policy remain real requirements; they are not bypassed to obtain a test pass.

## Authorized vendor matrix

Generate a fresh matrix without contacting any appliance:

```sh
python3 native/lab/lab.py matrix
```

It creates `target/ocvpn-lab/vendor-matrix.json` with 28 protocol/OS combinations. Every row starts **unverified**, with separate authentication, tunnel, IPv4, IPv6, DNS, and reconnect outcomes, plus authorization reference, appliance version, authentication type, evidence, and limitations. The command refuses to overwrite existing evidence.

Only an authorized operator with actual appliance observations should record an attestation:

```sh
python3 native/lab/vendor.py --protocol gp --os linux \
  --authorization-reference CHANGE-REFERENCE \
  --appliance-version OBSERVED-VERSION \
  --authentication-type OBSERVED-AUTH-TYPE \
  --evidence outcomes.json \
  --limitation 'Nonsecret observed limitation'
```

`outcomes.json` must contain exactly `authentication`, `tunnel`, `ipv4`, `ipv6`, `dns`, and `reconnect`, each set to `passed`, `failed`, or `unverified`. The tool labels the result **operator-attested**, stores the evidence hash, and does not infer an appliance test from a fixture. Repeat `--limitation` for additional limitations. Never include passwords, cookies, private endpoints, or callback URLs.

No authorized vendor appliance/version/account was supplied for this implementation run. All 28 vendor/OS rows therefore remain unverified, including Cisco/AnyConnect: successful ocserv traffic is not a Cisco appliance result.

## Deliberate limits

- Embedded browser mode fails closed for explicit TLS pins because native webview hooks cannot enforce those pins before every credential-bearing request. System/manual alternatives require an explicit choice; the system browser owns its own trust policy.
- The verified Linux native dependency build omits GSSAPI. Kerberos/Negotiate interoperability is not claimed.
- A VPN server that requires proprietary posture/HIP/compliance software may reject an otherwise supported protocol. No compliance report is fabricated.
- Server restart may invalidate a VPN cookie. Authentication-required is a legitimate observed outcome, not proof of successful session resumption.
- Only one service-owned machine-wide tunnel is supported at a time.
- Linux tray support and native portal dialogs depend on a suitable desktop session and installed backend. A headless runner cannot establish their availability on another desktop environment.
