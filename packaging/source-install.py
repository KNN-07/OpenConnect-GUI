#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Install an extracted Linux standalone payload at the fixed protected paths.

Requires explicit root invocation; never elevates an arbitrary user command.
Uninstall and upgrade require native helper-confirmed quiescence/recovery.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

BASE = Path(__file__).resolve().parent
STATE = Path('/var/lib/openconnect-gui')
INSTALLED = STATE / 'source-install-manifest.json'
HELPER = Path('/usr/libexec/openconnect-gui/ocvpn-installer')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protect(path, directory=False, mode=None):
    for ancestor in reversed(path.parents):
        if ancestor.exists():
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError(f'Untrusted destination ancestor: {ancestor}')
        else:
            ancestor.mkdir(mode=0o755)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeError(f'Untrusted destination: {path}')
    if directory:
        path.mkdir(exist_ok=True, mode=mode or 0o755)
        path.chmod(mode or 0o755)


def registration(command, expected):
    protect(HELPER)
    result = subprocess.run([str(HELPER), command], check=True, stdout=subprocess.PIPE)
    value = json.loads(result.stdout)
    if value.get('registered') is not expected or value.get('approval_required') is not False:
        raise RuntimeError('Native service/worker/recovery state is unresolved; all existing files preserved')


def manifest(path):
    value = json.loads(path.read_text())
    for relative, checksum in value.items():
        if Path(relative).is_absolute() or '..' in Path(relative).parts or not relative.startswith(('usr/bin/', 'usr/lib/', 'usr/libexec/', 'usr/share/')) or len(checksum) != 64:
            raise RuntimeError('Unsafe source package manifest')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'uninstall'])
    parser.add_argument('--foreground', action='store_true', help='Fresh install only: leave registration to an administrator-owned external supervisor')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run this source installer explicitly as root')
    os.umask(0o022)
    protect(STATE, True, 0o700)
    protect(INSTALLED)
    old = manifest(INSTALLED) if INSTALLED.exists() else {}
    if args.action == 'uninstall':
        if not old:
            raise RuntimeError('No source-install ownership manifest; use the original package manager')
        # Validate every owned file before the destructive barrier.
        for relative, checksum in old.items():
            path = Path('/') / relative
            protect(path)
            if path.exists() and digest(path) != checksum:
                raise RuntimeError(f'Modified installed file; preserve and reconcile: {relative}')
        registration('uninstall', False)
        for relative in old:
            (Path('/') / relative).unlink(missing_ok=True)
        INSTALLED.unlink()
        for directory in sorted({(Path('/') / relative).parent for relative in old}, key=lambda p: len(p.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass  # Preserve shared/nonempty directories, profiles and journals.
        return
    current = manifest(BASE / 'payload-manifest.json')
    payload = BASE / 'payload'
    for relative, checksum in current.items():
        source = payload / relative
        if source.is_symlink() or not source.resolve().is_relative_to(payload.resolve()) or digest(source) != checksum:
            raise RuntimeError(f'Package checksum failure: {relative}')
        destination = Path('/') / relative
        protect(destination)
        if destination.exists() and relative not in old:
            raise RuntimeError(f'Path belongs to another installation: {relative}; uninstall that package first')
    if old:
        if args.foreground:
            raise RuntimeError('Foreground update requires native quiescence confirmation. Do not overwrite a supervised installation; use native service repair/uninstall after safely migrating its supervisor.')
        registration('uninstall', False)
    for relative in old.keys() - current.keys():
        path = Path('/') / relative
        protect(path)
        if path.exists() and digest(path) != old[relative]:
            raise RuntimeError(f'Modified obsolete file; preserve and reconcile: {relative}')
    for relative in old.keys() - current.keys():
        (Path('/') / relative).unlink(missing_ok=True)
    for relative in current:
        source = payload / relative
        destination = Path('/') / relative
        shutil.copyfile(source, destination)
        destination.chmod(0o755 if os.access(source, os.X_OK) else 0o644)
        os.chown(destination, 0, 0)
    protect(Path('/run/openconnect-gui'), True, 0o755)
    protect(STATE / 'network', True, 0o700)
    INSTALLED.write_text(json.dumps(current, indent=2) + '\n')
    INSTALLED.chmod(0o600)
    if args.foreground:
        print('Installed without service registration. Supervise /usr/libexec/openconnect-gui/ocvpnd --foreground as root; preserve files until shutdown/recovery is confirmed.')
    else:
        registration('install', True)
    print('User profiles preserved. Login auto-connect and callback association remain per-user opt-ins.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'source-install: {error}')
