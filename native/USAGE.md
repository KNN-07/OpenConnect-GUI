# OpenConnect GUI

A Rust VPN client with a Tauri desktop, the `ocvpn` command-line interface, and a full-screen TUI. All three use the same per-user profiles and authentication client. A privileged native service owns the machine-wide tunnel, routing, and DNS; the desktop never runs as administrator.

Original application code is GPL-3.0-only. There is no activation service, subscription, telemetry backend, or signing-based feature restriction. See [native packaging and licenses](../packaging/README.md) for bundled components and source distribution.

## Protocols and verification

The bundled OpenConnect 9.21 engine exposes these upstream protocols:

| ID | Protocol |
|---|---|
| `anyconnect` | Cisco AnyConnect / ocserv |
| `nc` | Juniper Network Connect |
| `pulse` | Ivanti / Pulse Connect Secure |
| `gp` | Palo Alto GlobalProtect |
| `f5` | F5 BIG-IP |
| `fortinet` | Fortinet FortiGate |
| `array` | Array Networks |

Protocol availability is not a vendor interoperability claim. Native authentication fixtures cover Cisco, Juniper, Pulse, GlobalProtect, F5, and Fortinet. Array has TLS-rejection coverage, not successful appliance authentication. Actual Linux packet, DNS, and recovery verification uses isolated ocserv—not the authentication fixtures.

Native macOS/Windows execution and authorized vendor-appliance testing require their own runners and accounts. A Linux cross-compilation check does not establish either. See [verification and limitations](VERIFICATION.md) for the exercised surfaces and remaining acceptance boundaries.

## Install

Use the matching native package; install either the desktop flavor or the CLI/TUI flavor, not both. Both include the engine, privileged service, networking helper, and callback receiver. The CLI/TUI flavor does not require a desktop; embedded browser SSO does.

Release targets are Linux x86_64 (Ubuntu 22.04+ / Fedora 42+ reference baselines), macOS 13+ on Intel and Apple Silicon, and Windows 10 22H2+ / Windows 11 x86_64. Package formats, source-install routes, build prerequisites, optional signing, and OS authorization are documented in [packaging/README.md](../packaging/README.md).

After installation:

```sh
ocvpn protocols
ocvpn doctor
ocvpn service status
```

`doctor` checks the actual bundled engine and service. Missing service access is reported as unavailable, never as a disconnected VPN. Installation and repair require native OS authorization; normal GUI, CLI, and TUI operations do not.

```sh
ocvpn service install
ocvpn service repair
ocvpn gui
ocvpn tui
```

Uninstalling the service disconnects the tunnel but does not remove the application package or user profiles. Use the package manager to remove its files. Do not mix package-manager and source-install ownership.

## Profiles and CLI

Create a profile without putting credentials in arguments:

```sh
ocvpn profile add --name work --server https://vpn.example.com/custom/path --protocol anyconnect
ocvpn profile list
ocvpn profile show work
ocvpn connect work
ocvpn status
ocvpn disconnect
```

A selector may be a profile name or UUID. Server paths and non-default ports are preserved. `connect` returns only after the service reports a real connected tunnel; the service keeps it running afterward.

For advanced metadata, supply a JSON object with `--file`:

```json
{
  "username": "alice",
  "ca_file": "/absolute/path/organization-ca.pem",
  "browser_mode": "system",
  "remember_password": false,
  "reconnect_timeout_secs": 300
}
```

```sh
ocvpn profile add --name work-sso --server https://vpn.example.com --protocol gp --file advanced.json
```

Explicit name/server/protocol arguments override those three fields in the file. The desktop editor exposes the same schema: authentication group and gateway, CA and primary/secondary certificate/key references, proxy, token mode, browser mode, SNI, user agent, reported OS, MTU, DTLS/IPv6 preferences, and reconnect timeout. Unsupported capabilities fail explicitly rather than being silently ignored.

To update a profile, save the complete output of `profile show`, edit the metadata, then use `profile update SELECTOR --file edited.json`. Preserve its ID and revision. A stale revision returns `conflict` instead of overwriting another interface's changes. The CLI never launches an implicit shell editor.

```sh
ocvpn profile duplicate work --name work-copy
ocvpn profile export work --output work-export.json
ocvpn profile import work-export.json
ocvpn profile remove work-copy
```

Omitting the export selector exports all profiles. Export is atomic and refuses to overwrite an existing file unless `--force` is supplied. Exports contain metadata, not saved passwords, token seeds, PINs, or session cookies.

### Automation and observation

```sh
ocvpn --json status
ocvpn status --watch
ocvpn logs --follow
ocvpn connect work --foreground
ocvpn connect work --non-interactive --password-stdin
ocvpn completions bash
```

Feed `--password-stdin` through a private pipe or protected input file; do not type the password into the command line. Input is limited to 64 KiB. `--cookie-stdin` is a separate advanced option for a complete validated authentication-handoff JSON document, not a raw-cookie shortcut. The two stdin modes are mutually exclusive.

Noninteractive mode does not open a browser or wait for terminal/keyring prompts. If required credentials are unavailable or the keyring is locked, it returns an actionable authentication error. `--foreground` follows the session; Ctrl-C disconnects and waits for cleanup. Interrupting authentication cancels the pending attempt.

JSON responses use `schema_version: 1` with either `data` or `error`. Errors contain stable `code`, readable `message`, and optional nonsecret `details`. Watch/follow commands emit successive JSON records rather than one JSON array.

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Connection/runtime failure |
| 2 | Invalid input |
| 3 | Authentication, keyring, or certificate failure; interaction required |
| 4 | Service unavailable or authorization denied |
| 5 | Busy or revision conflict |
| 130 | Interrupted/cancelled |

## Desktop and TUI

The desktop shows actual service state, negotiated addresses/routes/DNS, transport, cumulative traffic, and rates calculated from observed samples. Profile changes do not mutate an already established session. Diagnostics and logs expose sanitized state; native dialogs handle file selection and export.

Desktop shortcuts: Ctrl/Cmd+N adds a profile; Ctrl/Cmd+K focuses search; Escape cancels a dialog or authentication attempt. Settings control system/light/dark theme, login behavior, close-to-tray, and saved-credential removal. Closing or quitting the UI leaves an established tunnel running; **Disconnect and quit** stops both. Tray availability depends on the desktop environment.

TUI controls:

| Key | Action |
|---|---|
| Arrows / `j` / `k` | Navigate profiles or scroll logs |
| Tab | Change focus |
| `c` / `d` | Connect / disconnect |
| `n` / `e` / Delete | Add / edit / confirm removal |
| `a` | Profile actions, including import/export/duplicate |
| `/` | Filter the focused profile list or logs |
| `s` / `l` / `?` | Settings / logs / help |
| Ctrl+S | Submit the current form |
| Escape | Cancel the current dialog/authentication |
| `q` | Quit TUI, retaining an established tunnel |
| `Q` | Disconnect and quit |

Text editing suspends global letter shortcuts. Password fields are masked; Unicode and bracketed paste are supported. The TUI adapts below 80 columns and honors `NO_COLOR`.

```sh
ocvpn settings show
ocvpn settings set theme dark
ocvpn settings set auto_connect_profile_id work
ocvpn settings set start_at_login true
```

Auto-connect is opt-in and runs in the user session, separately from system service registration. It fails closed when credentials or interaction are unavailable. Set `auto_connect_profile_id` to `none` to disable it.

## Authentication and trust

- Saved secrets use the operating system credential store, only with opt-in. There is no plaintext credential fallback. Generic challenge responses and one-time codes are not captured as saved passwords.
- Profiles reject secret-bearing certificate/PKCS#11 references, including embedded PIN values and PIN-source references. Enter passphrases/PINs through the appropriate authentication interaction instead.
- HOTP counter updates are committed before an OTP can be submitted; a failed commit prevents sending that OTP.
- TLS decisions are host-scoped. Changed certificates do not inherit a prior acceptance for another host.
- Embedded SSO fails closed when its certificate policy contains explicit pins, including attempt-local certificate acceptances. Native webview hooks cannot guarantee pre-request enforcement for a CA-trusted replacement certificate. Choose system/manual browser mode explicitly, or use normal organization-CA provisioning without a conflicting pin.
- System browsers use their own trust store. The application does not silently install organization or lab CAs globally.
- Browser callbacks are attempt-bound and reject replay/stale replies. Remote authentication pages do not receive application command permissions.
- One machine-wide tunnel is supported at a time. Privileged operations validate ownership; stopping, replacing, or recovering a tunnel does not erase unrelated network changes.

Upstream protocol support is not a promise to emulate proprietary posture agents, HIP/compliance checks, or every vendor-only feature. Such server requirements remain explicit interoperability limitations.

## Build and verify

Use the pinned Rust toolchain and the native prerequisites in [the build guide](../packaging/README.md). Run from the repository root:

```sh
npm ci --prefix apps/desktop
cargo xtask native build --target host
cargo xtask build --target host
cargo test -p ocvpn-model -p ocvpn-engine -p ocvpn-client -p ocvpn-service -p ocvpn-net
cargo xtask verify protocols
cargo xtask verify browser
cargo xtask lab up
cargo xtask verify tunnel --profile lab
cargo xtask lab down
cargo xtask package --target host
```

The Linux lab uses an owned, network-isolated container and fresh local credentials; it does not replace the developer host's default route. Preserve its private evidence before changing a locked lab image recipe. Packaging requires the baseline/native dependency sources and source inventory described in the build guide; a successful local development build is not automatically a portable release.
