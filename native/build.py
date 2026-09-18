#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 OpenConnect GUI contributors
"""Build the pinned C ABI with a dedicated native dependency prefix.

Run from the root: python3 native/build.py --target host --dependency-prefix PATH
Windows: run under MSYS2 with a MinGW-w64 prefix; the Rust target is MSVC.
No package installation or elevation is performed. Requires Python >= 3.10.
"""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

NATIVE = Path(__file__).resolve().parent
ROOT = NATIVE.parent


@contextmanager
def owned_build_output(target):
    output = ROOT / 'target/native' / target
    # Do not follow an output directory redirected outside the workspace.
    for directory in [ROOT / 'target', ROOT / 'target/native', output]:
        if directory.is_symlink():
            raise RuntimeError(f'Refusing symlinked native output: {directory}')
        directory.mkdir(exist_ok=True)
    lock_path = output / '.build.lock'
    if lock_path.is_symlink():
        raise RuntimeError(f'Refusing symlinked native build lock: {lock_path}')
    with lock_path.open('a+b') as lock:
        lock.seek(0, os.SEEK_END)
        if not lock.tell():
            lock.write(b'\0')
            lock.flush()
        lock.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError(f'Another native build owns {output}') from error
        try:
            marker = output / '.ocvpn-build-owner.json'
            identity = {'schema_version': 1, 'generator': 'native/build.py', 'target': target}
            generated = [output / 'source', output / 'stage']
            if marker.is_symlink():
                raise RuntimeError(f'Refusing symlinked native ownership marker: {marker}')
            if marker.exists():
                if json.loads(marker.read_text()) != identity:
                    raise RuntimeError(f'Native output has an unrecognized ownership marker: {output}')
            elif any(path.exists() or path.is_symlink() for path in generated):
                raise RuntimeError(f'Refusing unowned source/stage in {output}; relocate old outputs explicitly')
            else:
                with marker.open('x') as stream:
                    json.dump(identity, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
            for path in generated:
                if path.is_symlink() or (path.exists() and not path.is_dir()):
                    raise RuntimeError(f'Refusing redirected or non-directory native output: {path}')
            for path in generated:
                if path.exists():
                    shutil.rmtree(path)
            yield output
        finally:
            if os.name == 'nt':
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def run(args, cwd=None, env=None):
    print('+', ' '.join(map(str, args)), flush=True)
    try:
        return subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True,
                              text=True, stdout=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, file=sys.stderr, end='')
        raise


def digest(path):
    checksum = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def require_digest(path, expected):
    if digest(path) != expected:
        raise RuntimeError(f'SHA256 mismatch: {path}')


def authenticate(spec):
    for field, checksum in [('archive', 'sha256'), ('signature', 'signature_sha256'),
                            ('signing_key', 'signing_key_sha256'), ('header', 'header_sha256')]:
        require_digest(NATIVE / spec[field], spec[checksum])
    with tempfile.TemporaryDirectory(prefix='ocvpn-gpg-') as home:
        if os.name == 'nt':
            # MSYS GnuPG resolves --homedir as a POSIX path, unlike file inputs.
            home = run(['cygpath', '-u', home]).strip()
        run(['gpg', '--batch', '--homedir', home, '--import', NATIVE / spec['signing_key']])
        status = run(['gpg', '--batch', '--homedir', home, '--status-fd', '1', '--verify',
                      NATIVE / spec['signature'], NATIVE / spec['archive']])
        expected = '[GNUPG:] VALIDSIG ' + spec['signer_fingerprint'] + ' '
        if not any(line.startswith(expected) for line in status.splitlines()):
            raise RuntimeError('Release signature did not match the pinned signer')


def shared(path):
    if not path.is_file() or not (re.search(r'\.so(?:\.\d+)*$', path.name)
                                 or path.suffix in ('.dylib', '.dll')):
        return False
    with path.open('rb') as stream:
        magic = stream.read(4)
    return magic == b'\x7fELF' or magic[:2] == b'MZ' or magic in (
        b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe')


def stage_libraries(prefix, destination):
    copied = {}
    for directory in [prefix / 'lib', prefix / 'lib64', prefix / 'bin']:
        if not directory.exists():
            continue
        for source in directory.rglob('*'):
            if not shared(source):
                continue
            checksum = digest(source)
            if source.name in copied and copied[source.name] != checksum:
                raise RuntimeError(f'Conflicting library basename: {source.name}')
            copied[source.name] = checksum
            shutil.copy2(source.resolve(), destination / source.name)
    return copied


def fix_and_check_closure(directory, system):
    names = {path.name for path in directory.iterdir() if shared(path)}
    for path in list(directory.iterdir()):
        if not shared(path):
            continue
        if system == 'linux':
            run(['patchelf', '--set-rpath', '$ORIGIN', path])
            dependencies = re.findall(r'\(NEEDED\).*?\[(.*?)\]', run(['readelf', '-d', path]))
            baseline = re.compile(r'^(lib(c|m|dl|rt|pthread|resolv|util)\.so\.|ld-linux)')
            for dependency in dependencies:
                if dependency not in names and not baseline.match(dependency):
                    raise RuntimeError(f'Unbundled dependency {dependency} needed by {path.name}')
        elif system == 'macos':
            dependencies = [line.strip().split(' (', 1)[0]
                            for line in run(['otool', '-L', path]).splitlines()[1:]]
            run(['install_name_tool', '-id', '@rpath/' + path.name, path])
            for dependency in dependencies:
                if dependency.startswith(('/usr/lib/', '/System/Library/')):
                    continue
                name = Path(dependency).name
                if name not in names:
                    raise RuntimeError(f'Unbundled dependency {dependency} needed by {path.name}')
                run(['install_name_tool', '-change', dependency, '@loader_path/' + name, path])
        else:
            dependencies = re.findall(r'DLL Name:\s*(\S+)', run(['objdump', '-p', path]))
            baseline = {'kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll',
                        'crypt32.dll', 'bcrypt.dll', 'ncrypt.dll', 'secur32.dll',
                        'winhttp.dll', 'iphlpapi.dll', 'ole32.dll', 'oleaut32.dll',
                        'shell32.dll', 'shlwapi.dll', 'msvcrt.dll', 'ucrtbase.dll',
                        'ntdll.dll', 'setupapi.dll', 'version.dll', 'winscard.dll',
                        'dnsapi.dll', 'normaliz.dll'}
            lower = {name.lower() for name in names}
            for dependency in dependencies:
                name = dependency.lower()
                if name not in lower and name not in baseline and not name.startswith('api-ms-win-'):
                    raise RuntimeError(f'Unbundled dependency {dependency} needed by {path.name}')


def main(resources):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--dependency-prefix', type=Path)
    parser.add_argument('--jobs', type=int, default=os.cpu_count() or 1)
    args = parser.parse_args()
    if sys.version_info < (3, 10) or not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Python >=3.10 with the tarfile security backport is required')
    host_system = platform.system().lower()
    system = ('macos' if host_system == 'darwin' else 'windows'
              if host_system == 'windows' or host_system.startswith(('mingw', 'msys', 'cygwin'))
              else 'linux' if host_system == 'linux' else None)
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine().lower(), platform.machine().lower())
    target = {'linux': f'{arch}-unknown-linux-gnu', 'macos': f'{arch}-apple-darwin',
              'windows': 'x86_64-pc-windows-msvc'}.get(system)
    if not target or (args.target != 'host' and args.target != target):
        raise RuntimeError('Use a native runner for the requested target, not a cross-build')
    if target not in {'x86_64-unknown-linux-gnu', 'x86_64-apple-darwin',
                      'aarch64-apple-darwin', 'x86_64-pc-windows-msvc'}:
        raise RuntimeError(f'Unsupported release target: {target}')
    output = resources.enter_context(owned_build_output(target))
    if args.dependency_prefix is not None:
        prefix = args.dependency_prefix.resolve(strict=True)
    elif system == 'linux':
        prefix = Path('/opt/ocvpn-deps')
        if not prefix.is_dir():
            prefix = ROOT / 'target/native' / target / 'dependencies'
            if not (prefix / 'dependency-prefix.json').is_file():
                run([sys.executable, NATIVE / 'prepare-linux-prefix.py', prefix])
    elif system == 'macos':
        prefix = Path(run(['brew', '--prefix']).strip()).resolve(strict=True)
    else:
        raise RuntimeError('Windows needs --dependency-prefix pointing to the MinGW-w64 dependency installation')
    if not (prefix / 'share/licenses').is_dir():
        raise RuntimeError('Dependency prefix must retain share/licenses for every bundled component')
    spec = json.loads((NATIVE / 'sources.json').read_text())
    deps = json.loads((NATIVE / 'dependencies.json').read_text())
    authenticate(spec['openconnect'])
    environment = os.environ.copy()
    for inherited_version in ('RPM_PACKAGE_VERSION', 'RPM_PACKAGE_RELEASE', 'GIT_DIR'):
        environment.pop(inherited_version, None)
    environment['PKG_CONFIG_LIBDIR'] = os.pathsep.join(str(prefix / path) for path in
                                                     ['lib/pkgconfig', 'lib64/pkgconfig', 'share/pkgconfig'])
    environment.pop('PKG_CONFIG_PATH', None)
    environment['PATH'] = str(prefix / 'bin') + os.pathsep + environment['PATH']
    if system == 'windows':
        environment['CC'] = 'x86_64-w64-mingw32-gcc'
        environment['LDFLAGS'] = environment.get('LDFLAGS', '') + ' -static-libgcc -static-libstdc++'
        # MSYS aclocal does not search the native pkg-config tool's UCRT prefix.
        pkgconf = shutil.which('pkg-config', path=environment['PATH'])
        if pkgconf is None:
            raise RuntimeError('Native MinGW-w64 pkg-config is required')
        macros = Path(pkgconf).resolve().parent.parent / 'share/aclocal'
        aclocal = run(['cygpath', '-u', macros]).strip()
        environment['ACLOCAL_PATH'] = ':'.join(filter(None, [aclocal, environment.get('ACLOCAL_PATH')]))
    else:
        # The command bridge masks SIGPIPE per calling thread, not process-wide.
        environment['CFLAGS'] = environment.get('CFLAGS', '-O2 -g') + ' -pthread'
        environment['LDFLAGS'] = environment.get('LDFLAGS', '') + ' -pthread'
    if system == 'macos':
        # The package supports macOS 13; the SDK's strchrnul needs macOS 15.4.
        # Keep OpenConnect's portable implementation on the deployment baseline.
        environment['ac_cv_func_strchrnul'] = 'no'
    packages = dict(deps['pkg_config'])
    if system == 'linux':
        packages.update(deps['linux_pkg_config'])
    versions = {}
    for package, minimum in packages.items():
        run(['pkg-config', '--atleast-version=' + minimum, package], env=environment)
        versions[package] = run(['pkg-config', '--modversion', package], env=environment).strip()
    with tarfile.open(NATIVE / spec['openconnect']['archive']) as archive:
        archive.extractall(output / 'source', filter='data')
    source = output / 'source/openconnect-9.21'
    shutil.copy2(NATIVE / 'bridge/ocgui.c', source / 'ocgui.c')
    shutil.copy2(NATIVE / 'bridge/ocgui.h', source / 'ocgui.h')
    for patch in ['0001-build-bridge.patch', '0002-peer-policy.patch', '0003-hotp-commit.patch', '0004-array-stdout.patch', '0005-gp-browser.patch', '0006-gp-sso-fields.patch', '0007-command-descriptor-init.patch', '0008-windows-native-helper.patch', '0009-owned-script-group.patch', '0010-public-windows-crt-headers.patch']:
        patch_path = NATIVE / 'patches' / patch
        run(['patch', '-p1', '--batch', '--forward', '-i', patch_path.as_posix() if system == 'windows' else patch_path], cwd=source)
    # autoreconf is a Perl script; native Windows CreateProcess cannot execute
    # an extensionless shebang script. Let MSYS sh perform script dispatch.
    autoreconf = ['sh', '-c', 'exec autoreconf "$@"', 'autoreconf', '-fi'] if system == 'windows' else ['autoreconf', '-fi']
    run(autoreconf, cwd=source, env=environment)
    stage = output / 'stage'
    configure_path = (source / 'configure').as_posix() if system == 'windows' else source / 'configure'
    configure = ['sh', configure_path, '--prefix=/ocvpn-native', '--enable-shared',
                 '--disable-static', '--with-gnutls', '--without-openssl',
                 '--without-libproxy', '--with-builtin-json', '--without-lz4',
                 '--without-gnutls-tss2', '--disable-nls', '--disable-flask-tests',
                 '--with-vpnc-script=/ocvpn-native/libexec/ocvpn-net']
    if system in {'macos', 'windows'}:
        iconv_prefix = run(['cygpath', '-u', prefix], env=environment).strip() if system == 'windows' else str(prefix)
        configure.append('--with-libiconv-prefix=' + iconv_prefix)
    if system == 'windows':
        configure.extend(['--host=x86_64-w64-mingw32', '--disable-nsis-installer'])
    run(configure, cwd=source, env=environment)
    config = (source / 'config.h').read_text()
    for capability in spec['required_capabilities']:
        if not re.search(r'^#define ' + re.escape(capability) + r'\s+1\s*$', config, re.M):
            raise RuntimeError(f'Native configure did not enable required {capability}')
    run(['make', '-j' + str(args.jobs), 'libopenconnect.la'], cwd=source, env=environment)
    # The authenticated archive's version.sh appends "-unknown" when no
    # Git/RPM context exists. Record the compiled string, not an invented
    # release-string equivalence, and reject any unexpected build identity.
    version_source = (source / 'version.c').read_text()
    version_match = re.fullmatch(
        r'const char openconnect_version_str\[\] = "(v[0-9.]+-unknown)";\s*',
        version_source)
    expected_runtime_version = 'v' + spec['openconnect']['version'] + '-unknown'
    if not version_match or version_match[1] != expected_runtime_version:
        raise RuntimeError('Generated native version does not match the pinned archive build identity')
    runtime_version = version_match[1]
    stage_path = subprocess.check_output(['cygpath', '-u', str(stage)], text=True).strip() if system == 'windows' else str(stage)
    run(['make', 'install-libLTLIBRARIES', 'install-includeHEADERS',
         'DESTDIR=' + stage_path], cwd=source, env=environment)
    installed = stage / 'ocvpn-native'
    runtime = installed / 'lib'
    runtime.mkdir(parents=True, exist_ok=True)
    # Runtime consumers use the C ABI through dynamic loading; libtool
    # metadata is neither needed nor safe to ship with build-prefix paths.
    for metadata in runtime.glob('*.la'):
        metadata.unlink()
    # On MinGW libtool installs the DLL in bin and the import archive in lib.
    for dll in (installed / 'bin').glob('*.dll'):
        shutil.copy2(dll, runtime / dll.name)
    stage_libraries(prefix, runtime)
    fix_and_check_closure(runtime, system)
    engine_libraries = sorted(path for path in runtime.iterdir()
                              if shared(path) and 'openconnect' in path.name)
    if not engine_libraries:
        raise RuntimeError('Built OpenConnect shared library is missing')
    with ExitStack() as loader:
        if system == 'windows':
            loader.enter_context(os.add_dll_directory(str(runtime)))
        engine = ctypes.CDLL(str(engine_libraries[0].resolve()))
        for symbol in ['ocgui_set_peer_policy', 'ocgui_duplicate_cmd_handle',
                       'ocgui_send_cmd', 'ocgui_close_cmd_handle',
                       'ocgui_set_gp_browser_mode', 'ocgui_gp_external_allowed',
                       'ocgui_gp_auth_phase', 'ocgui_gp_retry_embedded',
                       'ocgui_verify_browser_chain', 'ocgui_set_script_env', 'ocgui_tun_is_up', 'ocgui_transport_is_udp']:
            if not hasattr(engine, symbol):
                raise RuntimeError(f'Built bridge is missing ABI4 export {symbol}')
        for symbol, expected in [('ocgui_bridge_abi', 4), ('ocgui_has_hpke', 1),
                                 ('ocgui_api_version_major', 5), ('ocgui_api_version_minor', 9)]:
            function = getattr(engine, symbol)
            function.argtypes = []
            function.restype = ctypes.c_uint
            if function() != expected:
                raise RuntimeError(f'Built bridge capability mismatch: {symbol}')
    shutil.copytree(prefix / 'share/licenses', installed / 'share/licenses/dependencies')
    shutil.copytree(NATIVE / 'licenses', installed / 'share/licenses/openconnect')
    shutil.copy2(NATIVE / 'bridge/ocgui.h', installed / 'include/ocgui.h')
    if system == 'windows':
        driver = deps['windows_driver']
        archive_path = output / 'wintun-0.14.1.zip'
        urllib.request.urlretrieve(driver['url'], archive_path)
        require_digest(archive_path, driver['sha256'])
        with zipfile.ZipFile(archive_path) as archive:
            (runtime / 'wintun.dll').write_bytes(archive.read('wintun/bin/amd64/wintun.dll'))
            (installed / 'share/licenses/WINTUN.txt').write_bytes(archive.read('wintun/LICENSE.txt'))
    manifest = {'schema_version': 1, 'target': target, 'openconnect': spec['openconnect']['version'],
                'runtime_version': runtime_version,
                'api': [5, 9], 'bridge_abi': 4, 'hpke': True, 'dependencies': versions,
                'files': {str(path.relative_to(installed)): digest(path)
                          for path in installed.rglob('*') if path.is_file()},
                'verification': 'Build-time capability and dependency closure checks; no protocol/authentication runtime proof.'}
    (installed / 'native-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Staged native runtime: {installed}')


if __name__ == '__main__':
    try:
        with ExitStack() as resources:
            main(resources)
    except (OSError, RuntimeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f'native build failed: {error}', file=sys.stderr)
        sys.exit(1)
