#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Native package production. Never installs into the build host.

Only release outputs and the authenticated ABI-4 native stage are consumed.
Linux artifacts are rejected if any ELF needs GLIBC newer than 2.35.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
VERSION = json.loads((ROOT / 'apps/desktop/src-tauri/tauri.conf.json').read_text(encoding='utf-8'))['version']
BINARIES = ['ocvpn', 'ocvpnd', 'ocvpn-net', 'ocvpn-installer', 'ocvpn-auth-callback']


def run(args, **kw):
    return subprocess.run([str(x) for x in args], check=True, **kw)


def capture(args, **kw):
    return run(args, stdout=subprocess.PIPE, **kw).stdout


def copy(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not source.is_file():
        raise RuntimeError(f'Missing required package input: {source}')
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def text(path, value, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding='utf-8')
    path.chmod(mode)


def tree(source, destination):
    for path in sorted(source.rglob('*')):
        if path.is_file():
            # Resolve native SONAME links into regular files: no escaping links.
            if not path.resolve().is_relative_to(source.resolve()):
                raise RuntimeError(f'Escaping package input: {path}')
            copy(path, destination / path.relative_to(source), 0o755 if os.access(path, os.X_OK) else 0o644)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hashlib.sha256(stream.read()).hexdigest()


def archive(source, destination, epoch):
    with destination.open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode='w') as tar:
        for path in sorted(source.rglob('*')):
            info = tar.gettarinfo(str(path), str(path.relative_to(source)))
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mtime = epoch
            if info.isfile():
                with path.open('rb') as data:
                    tar.addfile(info, data)
            else:
                tar.addfile(info)


def legal(destination, headless):
    copy(ROOT / 'LICENSE', destination / 'LICENSE')
    copy(ROOT / 'native/NOTICE', destination / 'NOTICE')
    tree(ROOT / 'native/licenses', destination / 'native')
    metadata = json.loads(capture(['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=ROOT))
    inventory = []
    for package in metadata['packages']:
        base = Path(package['manifest_path']).parent
        name = f"{package['name']}-{package['version']}"
        files = set()
        if package.get('license_file'):
            files.add(base / package['license_file'])
        for pattern in ['LICENSE*', 'LICENCE*', 'COPYING*', 'NOTICE*', 'UNLICENSE*']:
            files.update(base.glob(pattern))
        for path in sorted(files):
            if path.is_file():
                copy(path, destination / 'rust' / name / path.name)
        inventory.append({'ecosystem': 'cargo', 'name': package['name'], 'version': package['version'], 'license': package.get('license'), 'source': package.get('source'), 'license_files': sorted(p.name for p in files if p.is_file())})
    if not headless:
        lock = json.loads((ROOT / 'apps/desktop/package-lock.json').read_text(encoding='utf-8'))
        for relative, item in sorted(lock['packages'].items()):
            if not relative:
                continue
            base = ROOT / 'apps/desktop' / relative
            if not (base / 'package.json').is_file() and item.get('optional'):
                continue  # npm omits other platforms' optional build packages.
            manifest = json.loads((base / 'package.json').read_text(encoding='utf-8'))
            files = [p for p in base.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'UNLICENSE'))]
            name = manifest['name'].replace('/', '_') + '-' + manifest['version']
            for path in files:
                copy(path, destination / 'npm' / name / path.name)
            inventory.append({'ecosystem': 'npm', 'name': manifest['name'], 'version': manifest['version'], 'license': manifest.get('license'), 'integrity': item.get('integrity'), 'license_files': [p.name for p in files]})
    text(destination / 'inventory.json', json.dumps({'schema_version': 1, 'packages': inventory}, indent=2) + '\n')


def native_input(target):
    stage = ROOT / 'target/native' / target / 'stage/ocvpn-native'
    manifest = json.loads((stage / 'native-manifest.json').read_text(encoding='utf-8'))
    if manifest['target'] != target or manifest['bridge_abi'] != 4 or manifest['hpke'] is not True:
        raise RuntimeError('Native target/ABI/HPKE manifest mismatch; rebuild pinned native sources')
    for relative, expected in manifest['files'].items():
        path = stage / relative
        if not path.resolve().is_relative_to(stage.resolve()) or digest(path) != expected:
            raise RuntimeError(f'Native manifest integrity failure: {relative}')
    return stage


def baseline(payload):
    for path in payload.rglob('*'):
        if not path.is_file():
            continue
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        symbols = capture(['readelf', '--version-info', path]).decode()
        for major, minor in re.findall(r'GLIBC_(\d+)\.(\d+)', symbols):
            if (int(major), int(minor)) > (2, 35):
                raise RuntimeError(f'{path.name} needs GLIBC {major}.{minor}; rebuild Rust AND native dependencies on Ubuntu 22.04, not the development host')


def linux_payload(payload, release, native, licenses, headless):
    for name in BINARIES + ([] if headless else ['ocvpn-gui']):
        directory = 'usr/bin' if name in ['ocvpn', 'ocvpn-gui', 'ocvpn-auth-callback'] else 'usr/libexec/openconnect-gui'
        copy(release / name, payload / directory / name, 0o755)
    tree(native, payload / 'usr/lib/openconnect-gui')
    tree(licenses, payload / 'usr/share/doc/openconnect-gui')
    for unit in ['ocvpnd.service', 'ocvpnd.socket']:
        copy(ROOT / 'packaging/linux' / unit, payload / 'usr/lib/systemd/system' / unit)
    copy(ROOT / 'packaging/common/vpnc-script', payload / 'usr/libexec/openconnect-gui/vpnc-script', 0o755)
    copy(ROOT / 'packaging/linux/lifecycle', payload / 'usr/libexec/openconnect-gui/package-lifecycle', 0o755)
    copy(ROOT / 'packaging/linux/org.openconnectgui.policy', payload / 'usr/share/polkit-1/actions/org.openconnectgui.policy')
    copy(ROOT / 'packaging/linux/ocvpn-tmpfiles.conf', payload / 'usr/lib/tmpfiles.d/openconnect-gui.conf')
    # Keep callback capability inert. The client installs/selects the user's
    # XDG entry only after consent; a global MIME handler can become a default.
    copy(ROOT / 'packaging/linux/org.openconnectgui.Callback.desktop', payload / 'usr/share/openconnect-gui/org.openconnectgui.Callback.desktop')
    if not headless:
        copy(ROOT / 'packaging/linux/org.openconnectgui.App.desktop', payload / 'usr/share/applications/org.openconnectgui.App.desktop')
        copy(ROOT / 'apps/desktop/src-tauri/icons/icon.png', payload / 'usr/share/icons/hicolor/128x128/apps/openconnect-gui.png')
    for directory, mode in [('var/lib/openconnect-gui', 0o700), ('var/lib/openconnect-gui/network', 0o700)]:
        (payload / directory).mkdir(parents=True, exist_ok=True)
        (payload / directory).chmod(mode)
    baseline(payload)


def linux_packages(payload, output, work, headless, epoch):
    name = 'openconnect-cli' if headless else 'openconnect-gui'
    other = 'openconnect-gui' if headless else 'openconnect-cli'
    deb = work / 'deb'
    shutil.copytree(payload, deb)
    dependencies = 'libc6 (>= 2.35), libgcc-s1, libstdc++6, libdbus-1-3, systemd, python3, iproute2, procps, pkexec | policykit-1, xdg-utils'
    if not headless:
        dependencies += ', libwebkit2gtk-4.1-0, libgtk-3-0, libayatana-appindicator3-1, xdg-desktop-portal, xdg-desktop-portal-gtk | xdg-desktop-portal-kde, zenity'
    text(deb / 'DEBIAN/control', f'Package: {name}\nVersion: {VERSION}\nArchitecture: amd64\nMaintainer: OpenConnect GUI contributors\nSection: net\nPriority: optional\nLicense: GPL-3.0-only\nDepends: {dependencies}\nConflicts: {other}\nReplaces: {other}\nDescription: OpenConnect VPN client, CLI, TUI and privileged native service\n')
    lifecycle = (ROOT / 'packaging/linux/lifecycle').read_text(encoding='utf-8')
    for script, command in [('preinst', 'prepare'), ('postinst', 'install'), ('prerm', 'remove')]:
        text(deb / 'DEBIAN' / script, f'#!/bin/sh\nOCVPN_PACKAGE_ACTION={command}\nexport OCVPN_PACKAGE_ACTION\n{lifecycle}', 0o755)
    run(['dpkg-deb', '--root-owner-group', '--build', deb, output / f'{name}_{VERSION}_amd64.deb'], env={**os.environ, 'SOURCE_DATE_EPOCH': str(epoch)})
    rpm = work / 'rpmbuild'
    for directory in ['BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS']:
        (rpm / directory).mkdir(parents=True)
    archive(payload, rpm / 'SOURCES/payload.tar.gz', epoch)
    requirements = 'glibc >= 2.35, libgcc, libstdc++, dbus-libs, systemd, python3, iproute, procps-ng, polkit, xdg-utils'
    if not headless:
        requirements += ', webkit2gtk4.1, gtk3, libappindicator-gtk3, xdg-desktop-portal, xdg-desktop-portal-gtk, zenity'
    spec = f'''Name: {name}
Version: {VERSION}
Release: 1
Summary: OpenConnect VPN client and native service
License: GPL-3.0-only AND LGPL-2.1-only
URL: https://github.com/openconnect-gui/openconnect-gui
Source0: payload.tar.gz
BuildArch: x86_64
Requires: {requirements}
Conflicts: {other}
AutoReqProv: no
%description
Open-source OpenConnect CLI/TUI and protected tunnel service.
%prep
%build
%install
mkdir -p %{{buildroot}}
tar -xzf %{{SOURCE0}} -C %{{buildroot}}
%pre
OCVPN_PACKAGE_ACTION=prepare
export OCVPN_PACKAGE_ACTION
{lifecycle}
%post
/usr/libexec/openconnect-gui/package-lifecycle install
%preun
if [ "$1" = 0 ]; then
  /usr/libexec/openconnect-gui/package-lifecycle remove || exit 1
fi
%postun
/usr/bin/systemctl daemon-reload || exit 1
%files
%defattr(-,root,root,-)
/usr/bin/*
/usr/libexec/openconnect-gui
/usr/lib/openconnect-gui
/usr/lib/systemd/system/ocvpnd.service
/usr/lib/systemd/system/ocvpnd.socket
/usr/lib/tmpfiles.d/openconnect-gui.conf
/usr/share/doc/openconnect-gui
/usr/share/polkit-1/actions/org.openconnectgui.policy
/usr/share/openconnect-gui
{('/usr/share/applications/org.openconnectgui.App.desktop' if not headless else '')}
{('/usr/share/icons/hicolor/128x128/apps/openconnect-gui.png' if not headless else '')}
%dir %attr(0700,root,root) /var/lib/openconnect-gui
%dir %attr(0700,root,root) /var/lib/openconnect-gui/network
'''
    text(rpm / 'SPECS/package.spec', spec)
    run(['rpmbuild', '-bb', '--define', f'_topdir {rpm}', '--define', '_build_id_links none', '--define', '__os_install_post %{nil}', rpm / 'SPECS/package.spec'])
    for package in (rpm / 'RPMS').rglob('*.rpm'):
        copy(package, output / package.name)


def plist(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))


def mac_payload(payload, release, native, licenses, headless):
    app = payload / 'Applications/OpenConnect GUI.app'
    contents = app / 'Contents'
    for name in BINARIES[:-1] + ([] if headless else ['ocvpn-gui']):
        copy(release / name, contents / 'MacOS' / name, 0o755)
    callback = contents / 'Helpers/OpenConnect Callback.app/Contents'
    copy(release / 'ocvpn-auth-callback', callback / 'MacOS/ocvpn-auth-callback', 0o755)
    plist(callback / 'Info.plist', {'CFBundleIdentifier': 'org.openconnectgui.callback', 'CFBundleName': 'OpenConnect Callback', 'CFBundleExecutable': 'ocvpn-auth-callback', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': VERSION, 'LSUIElement': True, 'CFBundleURLTypes': [{'CFBundleURLName': 'OpenConnect authentication', 'CFBundleURLSchemes': ['globalprotectcallback']}], 'LSMinimumSystemVersion': '13.0'})
    plist(contents / 'Info.plist', {'CFBundleIdentifier': 'org.openconnectgui.app', 'CFBundleName': 'OpenConnect GUI', 'CFBundleExecutable': 'ocvpn' if headless else 'ocvpn-gui', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': VERSION, 'CFBundleShortVersionString': VERSION, 'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True})
    for source, directory in [('org.openconnectgui.daemon.plist', 'LaunchDaemons'), ('org.openconnectgui.autoconnect.plist', 'LaunchAgents')]:
        copy(ROOT / 'packaging/macos' / source, contents / 'Library' / directory / source)
    tree(native, contents / 'Resources/native')
    tree(licenses, contents / 'Resources/licenses')
    copy(ROOT / 'packaging/common/vpnc-script', contents / 'Resources/vpnc-script', 0o755)
    copy(ROOT / 'packaging/macos/uninstall', contents / 'Resources/uninstall', 0o755)
    copy(ROOT / 'packaging/macos/lifecycle', contents / 'Resources/package-lifecycle', 0o755)
    (payload / 'usr/local/bin').mkdir(parents=True)
    (payload / 'usr/local/bin/ocvpn').symlink_to('/Applications/OpenConnect GUI.app/Contents/MacOS/ocvpn')
    identity = os.environ.get('OCVPN_APP_SIGN_IDENTITY') or '-'
    # Sign inside-out, not --deep (which masks incorrectly nested components).
    # Signing a bundle's main executable also signs its containing bundle.
    # Leave both entry points to the explicit bundle passes after every helper.
    entry_points = {contents / 'MacOS' / ('ocvpn' if headless else 'ocvpn-gui'),
                    callback / 'MacOS/ocvpn-auth-callback'}
    for path in sorted(contents.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        if path not in entry_points and path.is_file() and (path.parent.name == 'MacOS' or path.suffix == '.dylib' or '.dylib.' in path.name):
            run(['codesign', '--force', '--options', 'runtime', '--timestamp=none' if identity == '-' else '--timestamp', '--sign', identity, path])
    native_root = contents / 'Resources/native'
    manifest_path = native_root / 'native-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest['files'] = {p.relative_to(native_root).as_posix(): digest(p) for p in sorted(native_root.rglob('*')) if p.is_file() and p != manifest_path}
    text(manifest_path, json.dumps(manifest, indent=2) + '\n')
    run(['codesign', '--force', '--options', 'runtime', '--sign', identity, callback.parent])
    run(['codesign', '--force', '--options', 'runtime', '--sign', identity, app])
    return app


def mac_package(payload, output, work, headless):
    scripts = work / 'pkg-scripts'
    for name in ['preinstall', 'postinstall', 'lifecycle']:
        copy(ROOT / 'packaging/macos' / name, scripts / name, 0o755)
    name = 'openconnect-cli' if headless else 'openconnect-gui'
    package = output / f'{name}-{VERSION}-{platform.machine()}.pkg'
    components = work / 'components.plist'
    run(['pkgbuild', '--analyze', '--root', payload, components])
    component_data = plistlib.loads(components.read_bytes())
    for component in component_data:
        component['BundleIsRelocatable'] = False
        component['BundleHasStrictIdentifier'] = True
        component['BundleOverwriteAction'] = 'upgrade'
    components.write_bytes(plistlib.dumps(component_data))
    args = ['pkgbuild', '--root', payload, '--component-plist', components, '--identifier', 'org.openconnectgui.package', '--version', VERSION, '--install-location', '/', '--ownership', 'recommended', '--scripts', scripts]
    if os.environ.get('OCVPN_INSTALLER_SIGN_IDENTITY'):
        args += ['--sign', os.environ['OCVPN_INSTALLER_SIGN_IDENTITY']]
    run(args + [package])
    if os.environ.get('OCVPN_NOTARY_PROFILE'):
        if not os.environ.get('OCVPN_INSTALLER_SIGN_IDENTITY') or not os.environ.get('OCVPN_APP_SIGN_IDENTITY'):
            raise RuntimeError('Notarization requires Developer ID Application and Installer identities')
        run(['xcrun', 'notarytool', 'submit', package, '--keychain-profile', os.environ['OCVPN_NOTARY_PROFILE'], '--wait'])
        run(['xcrun', 'stapler', 'staple', package])


def windows_payload(payload, release, native, licenses, headless):
    for name in BINARIES + ([] if headless else ['ocvpn-gui']):
        copy(release / (name + '.exe'), payload / (name + '.exe'), 0o755)
    tree(native, payload / 'native')
    copy(native / 'lib/wintun.dll', payload / 'wintun.dll')
    tree(licenses, payload / 'licenses')
    for name in ['nrpt.ps1', 'package-lifecycle.ps1', 'cli-path.ps1', 'source-install.ps1', 'check-install-root.ps1']:
        copy(ROOT / 'packaging/windows' / name, payload / 'resources' / name)
    if os.environ.get('OCVPN_WINDOWS_CERT_THUMBPRINT'):
        for binary in payload.glob('*.exe'):
            windows_sign(binary)


def windows_sign(path):
    thumbprint = os.environ.get('OCVPN_WINDOWS_CERT_THUMBPRINT')
    if thumbprint:
        run(['signtool', 'sign', '/sha1', thumbprint, '/fd', 'SHA256', '/tr', 'https://timestamp.digicert.com', '/td', 'SHA256', path])


def windows_package(payload, output, work, target, headless):
    guard = work / 'ocvpn-package-guard.exe'
    run(['x86_64-w64-mingw32-gcc', '-Os', '-municode', '-static-libgcc', '-o', guard, ROOT / 'packaging/windows/guard.c', '-ladvapi32', '-lole32', '-lshell32', '-luuid'])
    windows_sign(guard)
    if headless:
        removals = ['Delete "$INSTDIR\\' + p.relative_to(payload).as_posix().replace('/', '\\') + '"' for p in sorted(payload.rglob('*')) if p.is_file()]
        removals += ['RMDir "$INSTDIR\\' + p.relative_to(payload).as_posix().replace('/', '\\') + '"' for p in sorted(payload.rglob('*'), key=lambda p: len(p.parts), reverse=True) if p.is_dir()]
        text(payload / 'remove-files.nsh', '\n'.join(removals) + '\n')
    text(payload / 'payload-manifest.json', json.dumps({p.relative_to(payload).as_posix(): digest(p) for p in sorted(payload.rglob('*')) if p.is_file()}, indent=2))
    if headless:
        # Real NSIS headless installer: no Tauri/WebView2 build or dependency.
        script = ROOT / 'packaging/windows/cli.nsi'
        run(['makensis', f'/DVERSION={VERSION}', f'/DOCVPN_GUARD={guard}', f'/DPAYLOAD={payload}', f'/DOUTPUT={output / ("openconnect-cli-" + VERSION + "-setup.exe")}', script], cwd=script.parent)
        windows_sign(output / ("openconnect-cli-" + VERSION + "-setup.exe"))
        return
    resources = {}
    for path in sorted(payload.rglob('*')):
        if path.is_file() and path.name != 'ocvpn-gui.exe':
            resources[os.path.relpath(path, ROOT / 'apps/desktop/src-tauri').replace('\\', '/')] = path.relative_to(payload).as_posix()
    hooks = work / 'hooks.nsh'
    # Tauri's normal PREINSTALL hook runs after SetOutPath has already created
    # an unprotected install root. An earlier section lets our native guard
    # create/validate that root first, without weakening checks on old installs.
    text(hooks, f'!define OCVPN_GUARD "{guard}"\n!include "{ROOT / "packaging/windows/hooks.nsh"}"\n'
               'Section "-Protect machine installation"\n'
               '  !insertmacro OCVPN_PREINSTALL\n'
               'SectionEnd\n')
    config = {'bundle': {'active': True, 'targets': ['nsis'], 'resources': resources, 'windows': {'webviewInstallMode': {'type': 'offlineInstaller'}, 'nsis': {'installMode': 'perMachine', 'installerHooks': str(hooks), 'displayLanguageSelector': False}}}}
    if os.environ.get('OCVPN_WINDOWS_CERT_THUMBPRINT'):
        config['bundle']['windows'].update({'certificateThumbprint': os.environ['OCVPN_WINDOWS_CERT_THUMBPRINT'], 'digestAlgorithm': 'sha256', 'timestampUrl': 'https://timestamp.digicert.com', 'tsp': True})
    config_path = work / 'tauri.package.json'
    text(config_path, json.dumps(config, indent=2))
    npm = shutil.which('npm')
    if os.name == 'nt':
        npm_cli = Path(shutil.which('node')).parent / 'node_modules/npm/bin/npm-cli.js'
        args = ['node', npm_cli]
    else:
        args = [npm]
    run(args + ['run', 'tauri', '--', 'build', '--target', target, '--bundles', 'nsis', '--config', config_path, '--', '--locked'], cwd=ROOT / 'apps/desktop')
    packages = list((ROOT / 'target' / target / 'release/bundle/nsis').glob('*.exe'))
    if not packages:
        raise RuntimeError('Tauri did not produce an NSIS installer')
    for path in packages:
        copy(path, output / path.name)


def distribution_native(stage, destination, licenses, target):
    tree(stage, destination)
    legal_root = destination / 'share/licenses'
    if 'linux' in target:
        # The development prefix deliberately collects broad distro notices.
        # Ship only owners of the actual bundled ELF closure, not the build host.
        listing = capture(['/sbin/ldconfig', '-p']).decode()
        locations = {}
        for line in listing.splitlines():
            match = re.match(r'\s*(\S+)\s+\(.*\) => (\S+)', line)
            if match:
                path = Path(match[2])
                locations[match[1]] = path
                locations[path.resolve().name] = path
        owners = {'common-licenses', 'distro-packages.txt'}
        for library in (stage / 'lib').iterdir():
            if not library.is_file() or '.so' not in library.name or 'openconnect' in library.name:
                continue
            original = locations[library.name].resolve()
            for candidate in [original, Path(str(original).replace('/usr/lib/', '/lib/'))]:
                result = subprocess.run(['dpkg-query', '-S', str(candidate)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                if result.returncode == 0:
                    owners.add(result.stdout.split(': ', 1)[0].split(':', 1)[0])
                    break
            else:
                raise RuntimeError(f'Cannot identify license owner for {library.name}')
        for path in (legal_root / 'dependencies').iterdir():
            if path.name not in owners:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
    tree(licenses, legal_root / 'application')
    files = [p for p in legal_root.rglob('*') if p.is_file()]
    if len(files) > 2048 or sum(p.stat().st_size for p in files) > 32 * 1024 * 1024 or any(p.stat().st_size > 2 * 1024 * 1024 or len(p.relative_to(legal_root).parts) > 9 for p in files):
        raise RuntimeError('Legal inventory exceeds the installed reader bounds; consolidate license notices without dropping attribution before release')
    for path in files:
        path.read_text(encoding='utf-8')  # The installed reader is UTF-8, not a binary file browser.
    manifest = json.loads((destination / 'native-manifest.json').read_text(encoding='utf-8'))
    manifest['source_native_manifest_sha256'] = digest(stage / 'native-manifest.json')
    manifest['files'] = {p.relative_to(destination).as_posix(): digest(p) for p in sorted(destination.rglob('*')) if p.is_file() and p.name != 'native-manifest.json'}
    text(destination / 'native-manifest.json', json.dumps(manifest, indent=2) + '\n')
    return destination


def source_archive(output, work, epoch, native, target):
    source = work / 'source'
    source.mkdir()
    # Tracked source plus current working-tree contents: includes reviewable patches,
    # never target, private lab files, credentials, node_modules or workstation paths.
    if (ROOT / '.git').exists():
        tracked = capture(['git', 'ls-files', '--cached', '-z'], cwd=ROOT).decode().split('\0')
    else:
        tracked = json.loads((ROOT / 'source-inputs.json').read_text(encoding='utf-8'))['files']
    roots = {'apps', 'crates', 'native', 'packaging', 'xtask', '.cargo', '.github', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', 'README.md', 'CHANGELOG.md', '.gitignore'}
    for relative in sorted(set(tracked)):
        if Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise RuntimeError('Unsafe source archive file inventory')
        if relative and Path(relative).parts[0] in roots and not any(part.startswith('.env') for part in Path(relative).parts) and (ROOT / relative).is_file():
            copy(ROOT / relative, source / relative, 0o755 if os.access(ROOT / relative, os.X_OK) else 0o644)
    # Cargo vendor uses Cargo.lock and preserves upstream source/license notices.
    config = capture(['cargo', 'vendor', '--locked', '--versioned-dirs', source / 'vendor/cargo'], cwd=ROOT).decode()
    config = re.sub(r'^directory = .*$', 'directory = "vendor/cargo"', config, flags=re.MULTILINE)
    text(source / '.cargo/vendor-config.toml', config)
    sources = os.environ.get('OCVPN_DEPENDENCY_SOURCES')
    if sources:
        dependencies = Path(sources).resolve()
    elif platform.system() == 'Linux':
        dependencies = work / 'dependency-sources'
        run(['python3', ROOT / 'packaging/freeze-linux-sources.py', '--prefix', native, '--output', dependencies])
    else:
        raise RuntimeError('Set OCVPN_DEPENDENCY_SOURCES to the frozen prefix corresponding-source directory; a binary-only prefix cannot produce a redistributable source release')
    manifest = json.loads((dependencies / 'sources.json').read_text(encoding='utf-8'))
    if manifest.get('schema_version') != 1 or not manifest.get('packages') or not manifest.get('files'):
        raise RuntimeError('Dependency source manifest is incomplete')
    for relative, expected in manifest['files'].items():
        path = dependencies / relative
        if not path.resolve().is_relative_to(dependencies) or digest(path) != expected:
            raise RuntimeError('Corresponding dependency source integrity failure')
    tree(dependencies, source / 'vendor/native-dependencies')
    text(source / 'source-inputs.json', json.dumps({'schema_version': 1, 'source_date_epoch': epoch, 'files': {p.relative_to(source).as_posix(): digest(p) for p in sorted(source.rglob('*')) if p.is_file()}}, indent=2) + '\n')
    archive(source, output / f'openconnect-gui-{VERSION}-{target}-source.tar.gz', epoch)


def main():
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--headless', action='store_true')
    args = parser.parse_args()
    host = next(line[6:] for line in capture(['rustc', '-vV'], cwd=ROOT).decode().splitlines() if line.startswith('host: '))
    target = host if args.target == 'host' else args.target
    if target != host:
        raise RuntimeError('Packaging requires the matching native Rust host')
    native = native_input(target)
    release = ROOT / 'target' / target / 'release'
    if os.environ.get('SOURCE_DATE_EPOCH'):
        epoch = int(os.environ['SOURCE_DATE_EPOCH'])
    elif (ROOT / 'source-inputs.json').is_file():
        epoch = int(json.loads((ROOT / 'source-inputs.json').read_text(encoding='utf-8'))['source_date_epoch'])
    else:
        epoch = int(capture(['git', 'log', '-1', '--format=%ct'], cwd=ROOT).decode().strip())
    output = ROOT / 'target/packages' / target
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='package-', dir=output.parent) as temporary:
        work = Path(temporary)
        licenses = work / 'licenses'
        legal(licenses, args.headless)
        native = distribution_native(native, work / 'runtime', licenses, target)
        for headless in ([True] if args.headless else [False, True]):
            flavor = 'cli' if headless else 'gui'
            payload = work / flavor / 'payload'
            payload.mkdir(parents=True)
            area = work / flavor
            if 'linux' in target:
                linux_payload(payload, release, native, licenses, headless)
                linux_packages(payload, output, area, headless, epoch)
                install = work / (flavor + '-standalone')
                shutil.copytree(payload, install / 'payload')
                copy(ROOT / 'packaging/source-install.py', install / 'source-install.py', 0o755)
                text(install / 'payload-manifest.json', json.dumps({str(p.relative_to(payload)): digest(p) for p in sorted(payload.rglob('*')) if p.is_file()}, indent=2))
                archive(install, output / f'openconnect-{flavor}-{VERSION}-{target}-source-install.tar.gz', epoch)
            elif 'apple' in target:
                mac_payload(payload, release, native, licenses, headless)
                mac_package(payload, output, area, headless)
                archive(payload, output / f'openconnect-{flavor}-{VERSION}-{target}.tar.gz', epoch)
            elif 'windows' in target:
                windows_payload(payload, release, native, licenses, headless)
                windows_package(payload, output, area, target, headless)
                with zipfile.ZipFile(output / f'openconnect-{flavor}-{VERSION}-{target}.zip', 'w', zipfile.ZIP_DEFLATED) as archive_file:
                    for path in sorted(payload.rglob('*')):
                        if path.is_file():
                            archive_file.write(path, path.relative_to(payload))
            else:
                raise RuntimeError('Unsupported package target')
        source_archive(output, work, epoch, native, target)
        copy(licenses / 'inventory.json', output / f'license-inventory-{target}.json')
    sums = output / f'SHA256SUMS-{target}'
    text(sums, ''.join(f'{digest(path)}  {path.name}\n' for path in sorted(output.iterdir()) if path.is_file() and not path.name.startswith('SHA256SUMS')))
    print(f'Packages: {output.relative_to(ROOT)} (build artifacts, not native installation/interoperability proof)')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'package: {error}')
