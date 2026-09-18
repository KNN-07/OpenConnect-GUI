# Native packages and source installation

These entrypoints produce real native packages; a successful build is **not** an
installation, GUI, tunnel, reconnect or vendor interoperability pass. There is no
application activation, license server, subscription, telemetry or signing-based
feature gate. Application code and the combined OpenConnect/bridge library are
GPL-3.0-only. Unmodified upstream OpenConnect is LGPL-2.1-only; retain its notices,
the vpnc-script GPL-2.0-or-later notice and the separate upstream Wintun binary
redistribution license.

## Commands and output

Run on the matching native Rust host:

```sh
cargo xtask native build --target host
cargo xtask build --target host
cargo xtask package --target host
cargo xtask build --target host --headless
cargo xtask package --target host --headless
```

Explicit targets are `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`,
`aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`. Cross-target runs fail instead
of treating compilation on Linux as a Windows/macOS pass. `--dependency-prefix`
selects a **build input**, never an installed runtime override. Headless builds
select only CLI, daemon/installer and networking crates; they do not compile the
Tauri desktop or install npm dependencies. CLI packages retain the full shared
engine, networking helper, service manager and callback receiver. Embedded SSO
requires the desktop package; forms, certificates, system/manual SSO and TUI do
not require a desktop.

A full package run also produces the headless flavor. The flavors own the same
machine-wide service and install location; install **one flavor**, not both.
Outputs are in `target/packages/<target>/`:

* Linux: `.deb`, `.rpm` and standalone source-install `.tar.gz` for each flavor.
* macOS: separate native architecture `.pkg` and protected-layout `.tar.gz`.
* Windows: Tauri NSIS GUI setup, independent NSIS CLI setup and standalone ZIPs.
* Corresponding source archive, per-target `SHA256SUMS-<target>` and JSON license
  inventory. Source archives include Cargo-vendored dependencies, Cargo/npm
  locks, pinned OpenConnect source/signature/key, patches, and native dependency
  source archives plus their recipe/inventory. In an extracted source archive,
  use `cargo --config .cargo/vendor-config.toml ...` to select the vendored Cargo
  sources (or merge that configuration with the existing xtask alias).
  `source-inputs.json` records source hashes and the archive epoch, so rebuilding
  from an extracted archive does not require Git metadata.

Git checkouts package tracked source files with their current contents; stage new
source files before packaging. Untracked files are not swept into source releases.
Without Git, `source-inputs.json` supplies explicit source membership and the
archive epoch. Update that inventory deliberately when adding source files; do
not recursively inventory private workstation or lab data.

The legal inventory is also installed below the engine's `share/licenses`, which
is the actual About/license-reader location. Debian distro notices are reduced
to owners of the bundled dependency closure, not every package on the build
machine. Packaging rejects an inventory exceeding the reader's 2,048-file,
2 MiB/file, 32 MiB-total and depth-eight-directory limits; it never silently drops
notices to fit. Every bundled source is also retained in the source artifact.

## Linux baseline and prerequisites

The public Linux baseline is **Ubuntu 22.04 / GLIBC 2.35**, with Ubuntu 22.04+
and Fedora 42+ reference installation jobs. The development host's GLIBC 2.43
binaries are **not portable baseline artifacts**. Packaging examines every ELF in
the payload and refuses a GLIBC symbol requirement newer than 2.35. Rebuild both
Rust and the native dependency closure inside the baseline image:

```sh
docker build -f packaging/Dockerfile.release -t ocvpn-release-baseline .
docker run --rm -v "$PWD:/workspace" -w /workspace ocvpn-release-baseline sh packaging/ci-linux.sh
```

This explicit command mounts the source checkout for build outputs, not for a
running VPN or route mutation. The Docker image pins Ubuntu by digest and the APT
repositories to the signed `20260901T000000Z` snapshot. The script pins Node
22.19.0 with SHA-256, npm 11.19.0 and the repository Rust toolchain. APT source
packages are downloaded at the exact installed source versions for the bundled
library closure, recorded with hashes and included in the source release.
`freeze-linux-sources.py` requires matching authenticated `deb-src` indexes; it
does not install packages. On a normal source builder, provide those indexes or
set `OCVPN_DEPENDENCY_SOURCES` to a previously frozen corresponding-source
directory with `sources.json`. A binary-only prefix is insufficient for release.

The image installs the native compiler/autotools/GnuTLS/XML/token dependencies,
Python with the tarfile security backport, `dpkg-deb`, `rpmbuild`, and Tauri GTK /
WebKitGTK 4.1 prerequisites. Runtime GUI packages depend on a working
`xdg-desktop-portal` and a desktop backend (GTK, or KDE on Debian), plus `zenity`
for native message/confirmation dialogs. Native file import/export dialogs cannot
function with only a frontend browser. Linux tray availability remains
desktop-dependent. Headless packages do not depend on GTK,
WebKitGTK or a portal backend.

Installed paths are fixed:

* `/usr/bin/{ocvpn,ocvpn-gui,ocvpn-auth-callback}` (no GUI in the CLI flavor).
* `/usr/lib/openconnect-gui/{lib,share,...}` — **not** an extra `native/` level.
* `/usr/libexec/openconnect-gui/{ocvpnd,ocvpn-net,ocvpn-installer,vpnc-script}`.
* `/usr/lib/systemd/system/ocvpnd.{service,socket}`.
* Root-owned `/run/openconnect-gui` mode 0755 and
  `/var/lib/openconnect-gui{,/network}` mode 0700. Runtime lease files and the
  runtime directory are preserved across restart and package management.

Package preparation/removal executes the fixed installed native helper and
requires a zero exit plus `registered:false, approval_required:false`. Native
cleanup must establish worker/mutator quiescence and journal recovery. Failure
aborts before payload deletion. Install enables the service only after protected
assets/directories are in place. Profile/keyring data is never package-owned.
Polkit authorizes only the fixed protected `ocvpn-installer` path. No login
registration runs as root; the user opts in through settings or `ocvpn` later.

### Source-install and foreground supervision

On other Linux systems, extract the matching standalone source-install archive
and explicitly invoke its installer with administrator authorization:

```sh
sudo python3 source-install.py install
sudo python3 source-install.py uninstall
```

It verifies payload hashes, refuses untrusted/symlinked destination ancestors and
foreign existing files, records an administrator-only ownership manifest, and
removes only unchanged owned files after native cleanup. Do not mix it with
`.deb`/`.rpm` ownership. The normal source-install route uses systemd and the same
native lifecycle checks as distribution packages.

A fresh non-systemd installation can stage protected files without service
registration:

```sh
sudo python3 source-install.py install --foreground
sudo /usr/libexec/openconnect-gui/ocvpnd --foreground
```

Use an administrator-owned supervisor for that foreground command; never run a
GUI/browser as root. It is the real daemon, not a mock, and its TERM/INT shutdown
owns worker cancellation/recovery. Do not concurrently enable systemd for that
instance. Preserve the control directory and lifetime-lock inodes. An external
supervisor's stopped PID or absent socket is **not** sufficient removal proof.
The current native service-management entrypoint is systemd/cgroup-v2-oriented;
automated source update/removal fails closed when external-supervisor
quiescence/recovery cannot be established. Do not bypass this by deleting files
or journals. Migrate through a verified administrator-supervised recovery and
native service-management path before package removal.

## macOS and Windows pinned native source builds

`native/dependency-sources.json` pins archive versions and actual SHA-256 digests
for GMP, nettle/hogweed, libffi, p11-kit, zlib, GNU libiconv, libxml2, GnuTLS,
stoken and OATH/libpskc. Windows additionally builds the pinned MinGW-w64
winpthreads runtime, including its license and corresponding sources, rather than
depending on an ambient MSYS2 DLL. GNU libiconv avoids macOS's lossy system conversion.
`native/build-dependencies.py` is the executable generation recipe:

```sh
python3 native/build-dependencies.py --target host
cargo xtask package --target host
```

The package command automatically builds/reuses that verified prefix when no
explicit prefix is supplied on macOS/Windows. The source recipe uses included
GnuTLS libtasn1/unistring sources and excludes unrelated optional compression,
DANE, TPM and GUI libraries; OpenConnect HPKE still requires and checks GnuTLS
HKDF plus nettle/hogweed/GMP. It copies full notices, records prefix file hashes,
and refuses changed/incomplete cached prefixes. Native system PCSC/WinSCard is
used outside Linux. `--fetch-only` downloads pinned archives without compiling.
Native compile/install acceptance of these recipes remains **unverified** until
executed on each native runner.

Prerequisites: compiler, `make`, `pkg-config`, Meson/Ninja, gettext, m4, Perl,
`help2man`, Texinfo, Python
3.10+ with `tarfile.data_filter`, and the OpenConnect autotools/GnuPG/GNU patch tools.
macOS needs Xcode command-line tools and a login session. Windows needs a native
MSVC Rust host together with an MSYS2 MinGW-w64 C build environment exposing
`x86_64-w64-mingw32-{gcc,g++}`, native `ar`, `ranlib`, `windres`, `strip`,
`cygpath`, shell tools and native Windows Python; the Rust application is not
built with MinGW. Dependency sources use GNU C11 rather than compiler defaults.
Install NSIS `makensis` for the independent headless installer. Compiler/tool versions
are build prerequisites, not a claim of bit-identical binaries across SDKs.

Ordinary `native build` still accepts the existing distro/Brew/explicit-prefix
bootstrap workflow. Such a mutable bootstrap is **not** a frozen release input.
For a prebuilt source-derived prefix, `packaging/frozen-prefix.py` can intake an
HTTPS archive pinned by `OCVPN_PREFIX_URL` and `OCVPN_PREFIX_SHA256`. Its required
layout is `prefix/` and `sources/`, with a verified source inventory and executable
`build.py` recipe. This is optional caching, not an opaque required publisher
artifact. Set `OCVPN_DEPENDENCY_SOURCES` when using `--dependency-prefix`.

## macOS packaging, consent and removal

The protected app is `/Applications/OpenConnect GUI.app`; CLI/daemon/network /
installer executables live in `Contents/MacOS`. The runtime lives in
`Contents/Resources/native`, and `vpnc-script` in `Contents/Resources`.
The callback is the nested `Contents/Helpers/OpenConnect Callback.app`.
`/usr/local/bin/ocvpn` is a symlink to the protected app CLI. Existing unrelated
CLI paths are not overwritten. CLI-only packages still contain the app bundle
metadata and service/login-agent resources required by SMAppService.

The `.pkg` is startup-volume-only and nonrelocatable. Its scripts run service
management as the non-root console user with `launchctl asuser`; native
Authorization Services supplies administrator consent, not a root GUI. No
console session means an actionable failure. The daemon and optional login
agent use their `Contents/Library/{LaunchDaemons,LaunchAgents}` BundleProgram
plists. Installation can legitimately return approval-required; approve it in
System Settings > General > Login Items before claiming service readiness.
Updates and removal require clean unregister **and** completed quiescence, not
just a successful installer process. Approval-required removal preserves files.

```sh
sudo '/Applications/OpenConnect GUI.app/Contents/Resources/uninstall'
```

The uninstaller separately disables the console user's login registration,
quiesces/unregisters the daemon and only then removes the protected app and exact
CLI symlink. User profiles remain. The tar archive is a protected-layout artifact,
not a relocatable app or permission to overwrite a running installation; use the
`.pkg` for installation/update.

Signing variables are optional publisher inputs:

* `OCVPN_APP_SIGN_IDENTITY`: installed Developer ID Application identity.
* `OCVPN_INSTALLER_SIGN_IDENTITY`: installed Developer ID Installer identity.
* `OCVPN_NOTARY_PROFILE`: existing `notarytool` keychain profile.

Nested Mach-O code is signed inside-out, then callback/main bundles; native
manifest hashes are refreshed before sealing the bundle. `pkgbuild` signs the
package when requested, and notarization waits and staples when configured.
Without identities, the build uses ad-hoc code signing and an unsigned `.pkg`.
This preserves code/features but **does not promise Gatekeeper or SMAppService
acceptance**. macOS may reject unsigned/ad-hoc service registration. Verify on
both native architectures with the intended distribution identity and approval
workflow; a successful unsigned build is not sufficient evidence. Notarization
is a publisher trust mechanism, never application licensing.

## Windows packaging and source installation

The sole install root is the OS Known Folder **Program Files/OpenConnect GUI**;
there is no `C:` assumption. Executables are at root, native closure in `native`,
the upstream signed `wintun.dll` is also at executable root, and `nrpt.ps1` is in
`resources`. The installer is per-machine/UAC and rejects alternate roots or OS
builds older than Windows 10 22H2. Tauri's NSIS offline WebView2 installer mode
performs runtime detection and includes installation for offline machines.
The independent headless NSIS package has no Tauri/WebView2 dependency.

NSIS embeds a small native Win32 ACL guard from `guard.c` and calls the fixed
installed service manager directly. Mandatory installation does not require
PowerShell script execution or a policy change. The guard validates the entire
old install before executing any installed code and creates/protects the fixed
Known Folder paths. Pre-update/pre-uninstall hooks require native helper JSON
confirmation; nonzero failures abort the parent installer. Installed helper and
state ACLs permit writes only by SYSTEM/Administrators. Login and callback registrations
are not made in the elevated account. PATH is default-off, explicitly offered
for interactive installation, and removes only an entry this package added.
Changed machine PATH entries are preserved; sign in again to observe changes.
All fixed PowerShell scripts use `-NoProfile -NonInteractive -File`, never
execution-policy bypass. Organizational script policy can refuse optional PATH
changes, ZIP/source installation or NRPT; that is an explicit failure, not
silently disabled security. PATH removal is skipped if it was never opted into.

The GUI package emits an early NSIS section so its native guard creates the
protected root before Tauri's normal `SetOutPath`; the usual Tauri pre-install
hook runs too late for that invariant. Silent failures retain their nonzero
exit status without waiting for a modal acknowledgment. Windows reference
smoke checks use the runner's PowerShell `Start-Process -Wait` to wait for the
NSIS uninstaller and its temporary child, not just the launcher.

For a standalone ZIP, extract it and run `resources/source-install.ps1 install`
from an administrator PowerShell. It installs only into the same protected
Known Folder, verifies a file manifest and calls the native service manager.
Use that script's `uninstall` for that ownership model; do not mix ZIP/source
installation with NSIS ownership. Uninstall validates unchanged owned files and
leaves other files/profile data intact. This is an installation archive, not a
portable executable that can load an untrusted runtime from Downloads.

`OCVPN_WINDOWS_CERT_THUMBPRINT` optionally signs application executables and
installers with a certificate already provisioned in the runner store through
`signtool`/Tauri. It never changes the upstream Wintun signature. Unsigned
community applications have identical behavior, subject to normal OS warnings /
organization policy. No developer driver certificate is necessary: the pinned
Wintun 0.14.1 archive already contains the upstream signed DLL and its license.

Callback capability resources are inert until the unprivileged client's explicit
association-consent flow. Linux ships the desktop template outside the global
MIME-handler search path; the client writes/selects its private XDG entry.
macOS embeds the callback app without running a registration command from the
package installer. Windows uses the existing per-user capabilities/Default Apps
flow instead of overwriting another application's protocol association.

## Release workflow and acceptance boundaries

`.github/workflows/ci.yml` runs on pull requests, every branch push, manual
dispatch, and calls from the release workflow. Its GitHub-hosted Ubuntu 22.04
job checks workflow syntax with checksum-pinned actionlint, Rust formatting,
Python syntax, canonical model export, the locked frontend production build,
locked full-workspace tests, Clippy, and native loopback protocol fixtures.
Additional GitHub-hosted macOS Intel/ARM and Windows jobs compile the full Rust
workspace and test targets, so platform-specific Rust errors fail before release
dependency builds. CI does not run privileged tunnel labs or claim interactive
browser acceptance. The final `checks` job fails if any prerequisite fails, is
cancelled, or is skipped. Select that CI check in branch protection after its
first successful run. PR CI receives no release secrets and never uses self-hosted runners.

`.github/workflows/release.yml` first checks that the Cargo workspace, desktop
package, package-lock root/top-level versions, and Tauri version agree. Tag
pushes must match that version exactly (`v0.1.0` for the current manifests).
It then requires the reusable CI workflow before building Linux inside the
baseline container and macOS Intel/ARM plus Windows x86_64 on GitHub-hosted
native runners. The local composite actions install build tools; native library
dependencies still come from the pinned source recipes, not moving Brew/MSYS
library packages.

### GitHub setup and publishing

Commit and push the workflow/helper changes before invoking them. Actions must
be enabled with permission to use the SHA-pinned actions in the workflows.
PR/branch CI needs no repository secrets. Publication uses the automatic
`GITHUB_TOKEN`; only the publish job receives `contents: write`, not a PAT.

Create the `native-release` environment with deployment rules permitting the
trusted `main` branch and `v*` tags. Native build/installation jobs and publication
use that environment. Restrict who can update `main` and create release tags,
and add required environment reviewers if appropriate for your publishing policy.

No self-hosted runner registration is required:

| Purpose | GitHub-hosted runner |
|---|---|
| Linux baseline build / Ubuntu installation | `ubuntu-22.04` |
| Fedora 42 installation | Isolated systemd container on `ubuntu-24.04` |
| macOS Intel build / installation | `macos-15-intel` |
| macOS ARM build / installation | `macos-15` |
| Windows MSVC build / installation | `windows-2022` |

Installation runs use disposable hosted machines. Fedora's privileged container
has its own cgroup/network namespaces and no host bind mounts. No preinstalled
OpenConnect is permitted. Linux and Windows require installed doctor/service
checks and idle uninstall. macOS verifies installation, code signatures and the
bundled engine; `--allow-macos-pending-approval` also accepts a healthy, registered
service explicitly awaiting Login Items approval. Engine, driver, endpoint-trust
and other errors still fail. This boundary is recorded in the job summary and
release notes: it does not bypass consent or claim macOS service startup or
uninstall. Without that option, `packaging/smoke.py` retains the full lifecycle
requirement. These hosted OS versions do not prove acceptance on macOS 13 or Windows 10.

Optional environment secrets are `OCVPN_APP_SIGN_IDENTITY`,
`OCVPN_INSTALLER_SIGN_IDENTITY`, `OCVPN_NOTARY_PROFILE`, and
`OCVPN_WINDOWS_CERT_THUMBPRINT`. They reference identities/profiles already
provisioned on the native build runners; setting a name does not install a
certificate. The OS approval/signing limitations above still apply.

After the workflows are on `main`, a manual full build/installation rehearsal
uploads Actions artifacts but never publishes a GitHub Release:

```sh
gh workflow run release.yml --ref main
```

To publish, update all version manifests/locks and the changelog together, merge
the reviewed changes, then tag that exact commit:

```sh
git tag -a v0.1.0 -m "OpenConnect GUI 0.1.0"
git push origin v0.1.0
```

Only a matching version-tag **push** publishes, after CI, every native package
build, Linux/Windows installation and idle uninstall, and the explicit macOS
installation/approval-state checks succeed.
A manual dispatch on a tag is still a rehearsal. A version containing a SemVer prerelease
suffix is published as a prerelease and must match all manifests too.

`.github/scripts/release.py` requires all four target artifact directories,
unique asset names, and complete valid per-target SHA-256 manifests. It preserves
the original filenames, including Windows installer spaces. Publication creates
or resumes a **draft**, uploads the packages/source/checksums/license inventories,
downloads them to verify their bytes, and only then publishes. Failed uploads
leave a draft; rerun the failed job to resume it. Unexpected existing draft
assets require explicit operator review. Published releases are never
overwritten by a rerun. Runs for the same ref are serialized without cancelling
an in-flight release.

### Installation checks

The executable installation check is:

```sh
OCVPN_DISPOSABLE_RUNNER=1 python3 packaging/smoke.py PACKAGE
```

It installs the real package, runs the installed `ocvpn protocols`, `doctor` and
service status, and performs idle uninstall. It does **not** claim GUI operation,
live-tunnel uninstall, route/DNS recovery under failure, or vendor compatibility.
All those acceptance rows remain unverified until exercised on each OS. The lab
entrypoints are wired without replacing existing protocol/browser verification:

```sh
cargo xtask verify protocols
cargo xtask verify browser
cargo xtask lab up
cargo xtask verify tunnel --profile lab
cargo xtask lab down
```

On Linux the lab's isolated container uses real installed service/CLI binaries;
its host override for development GLIBC must not be confused with the baseline
release. Native macOS/Windows VM acceptance needs the exact authorized isolated
lab endpoint and CA, including `OCVPN_LAB_SERVER`/`OCVPN_LAB_CA` and the additional
native lab harness isolation/network-baseline contract. Use
`python3 native/lab/lab.py exec -- ocvpn tui` or `... gui` for the actual lab
surfaces. Keep the approved GUI/CLI/TUI shared-state, live upgrade/uninstall,
network failure/recovery and vendor appliance matrix separate from fixture /
package-build checks. No native macOS/Windows host or vendor credentials have
been assumed by this implementation.

References: [Tauri installers](https://v2.tauri.app/distribute/windows-installer/),
[Tauri resource mapping](https://v2.tauri.app/develop/resources/),
[SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice),
[Wintun](https://www.wintun.net/),
[Ubuntu snapshots](https://snapshot.ubuntu.com/).
