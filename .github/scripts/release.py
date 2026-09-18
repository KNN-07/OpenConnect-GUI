#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Validate release inputs and publish only fully verified draft assets (Python 3.11+)."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    'x86_64-unknown-linux-gnu',
    'x86_64-apple-darwin',
    'aarch64-apple-darwin',
    'x86_64-pc-windows-msvc',
)
SEMVER = re.compile(
    r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
    r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
    r'(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
)
NOTES = (
    'Native build and idle installation checks passed. See packaged verification '
    'documentation for unverified interactive, tunnel and vendor acceptance. '
    'No license server or feature activation is required.'
)


def preflight():
    desktop = ROOT / 'apps/desktop'
    lock = json.loads((desktop / 'package-lock.json').read_text())
    versions = {
        'Cargo workspace': tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version'],
        'desktop package': json.loads((desktop / 'package.json').read_text())['version'],
        'package-lock': lock['version'],
        'package-lock root package': lock['packages']['']['version'],
        'Tauri config': json.loads((desktop / 'src-tauri/tauri.conf.json').read_text())['version'],
    }
    version = versions['Cargo workspace']
    match = SEMVER.fullmatch(version)
    if not match or (match[4] and any(part.isdigit() and len(part) > 1 and part[0] == '0' for part in match[4].split('.'))):
        raise ValueError(f'Invalid manifest semantic version: {version}')
    if any(value != version for value in versions.values()):
        raise ValueError(f'Release manifests disagree: {versions}')
    ref = os.environ['RELEASE_REF']
    tag = None
    if ref.startswith('refs/tags/'):
        tag = ref.removeprefix('refs/tags/')
        if tag != f'v{version}':
            raise ValueError(f'Tag must exactly match all manifests: expected v{version}, got {tag}')
    elif not ref.startswith('refs/heads/'):
        raise ValueError(f'Unsupported release ref: {ref}')
    print(f'Matching manifest version: {version}; prerelease: {bool(match[4])}')
    return tag, bool(match[4])


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(directory):
    expected_dirs = {f'packages-{target}' for target in TARGETS}
    if {path.name for path in directory.iterdir()} != expected_dirs:
        raise ValueError('Expected exactly one artifact directory for each release target')
    assets = {}
    for target in TARGETS:
        artifact = directory / f'packages-{target}'
        if artifact.is_symlink() or not artifact.is_dir():
            raise ValueError(f'Not a regular artifact directory: {artifact}')
        files = {}
        for path in sorted(artifact.iterdir()):
            if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._+-]*', path.name):
                raise ValueError(f'Unsafe or unexpected artifact entry: {path}')
            if path.name in assets:
                raise ValueError(f'Duplicate release asset name across artifacts: {path.name}')
            files[path.name] = path
            assets[path.name] = (path, digest(path))
        checksum_name = f'SHA256SUMS-{target}'
        checksum_file = files.pop(checksum_name)
        checksums = {}
        for line in checksum_file.read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9 ._+-]*)', line)
            if not match or match[2] in checksums:
                raise ValueError(f'Invalid or duplicate checksum entry in {checksum_file}')
            checksums[match[2]] = match[1]
        if not checksums or checksums.keys() != files.keys():
            raise ValueError(f'Checksums must cover every packaged asset exactly once: {artifact}')
        for name, checksum in checksums.items():
            if assets[name][1] != checksum:
                raise ValueError(f'Packaged checksum mismatch: {files[name]}')
    print(f'Verified {len(assets)} uniquely named release assets')
    return assets


def gh(*args, payload=None):
    result = subprocess.run(
        ['gh', *args], input=json.dumps(payload) if payload is not None else None,
        text=True, stdout=subprocess.PIPE, check=True, timeout=600,
    )
    return result.stdout


def api(endpoint, method='GET', payload=None):
    args = ['api', endpoint, '--method', method]
    if payload is not None:
        args.extend(['--input', '-'])
    return json.loads(gh(*args, payload=payload))


def pages(endpoint):
    # Successful listing distinguishes an absent release from any API/auth failure.
    # Include drafts and all pages; a failed gh invocation is always fatal.
    return [item for page in json.loads(gh('api', endpoint, '--paginate', '--slurp')) for item in page]


def require_draft(endpoint, tag):
    release = api(endpoint)
    if not release['draft'] or release['tag_name'] != tag:
        raise ValueError('Refusing to modify a published release or a different tag')
    return release


def publish(directory):
    tag, prerelease = preflight()
    if tag is None or os.environ.get('GITHUB_EVENT_NAME') != 'push':
        raise ValueError('Only a version-tag push may publish a release')
    assets = verify(directory)
    repository = os.environ['GH_REPO']
    endpoint = f'repos/{repository}/releases'
    matches = [release for release in pages(endpoint + '?per_page=100') if release['tag_name'] == tag]
    if len(matches) > 1:
        raise ValueError('Multiple releases found for the same tag')
    if matches:
        release = matches[0]
        if not release['draft']:
            raise ValueError('Refusing to overwrite a published release')
    else:
        gh('release', 'create', tag, '--repo', repository, '--verify-tag', '--draft',
           '--title', f'OpenConnect GUI {tag}', '--notes', NOTES,
           *(['--prerelease'] if prerelease else []))
        matches = [release for release in pages(endpoint + '?per_page=100') if release['tag_name'] == tag]
        if len(matches) != 1:
            raise ValueError('Created draft could not be uniquely identified')
        release = matches[0]
    endpoint += f'/{release["id"]}'
    require_draft(endpoint, tag)
    remote = pages(endpoint + '/assets?per_page=100')
    if any(asset['name'] not in assets for asset in remote):
        raise ValueError('Draft contains unexpected assets; refusing to publish them')
    for path, _ in assets.values():
        require_draft(endpoint, tag)
        # Replacement is allowed only on a draft, to resume interrupted uploads.
        gh('release', 'upload', tag, str(path), '--repo', repository, '--clobber')
    require_draft(endpoint, tag)
    remote = pages(endpoint + '/assets?per_page=100')
    if len(remote) != len(assets) or {asset['name'] for asset in remote} != assets.keys():
        raise ValueError('Uploaded release asset set does not match verified packages')
    if any(asset['state'] != 'uploaded' or asset['size'] != assets[asset['name']][0].stat().st_size for asset in remote):
        raise ValueError('Release asset upload is incomplete')
    with tempfile.TemporaryDirectory(prefix='release-verify-') as temporary:
        gh('release', 'download', tag, '--repo', repository, '--dir', temporary)
        downloaded = Path(temporary)
        if {path.name for path in downloaded.iterdir()} != assets.keys():
            raise ValueError('Downloaded release asset set does not match packages')
        for name, (_, checksum) in assets.items():
            if digest(downloaded / name) != checksum:
                raise ValueError(f'Uploaded asset checksum mismatch: {name}')
    require_draft(endpoint, tag)
    api(endpoint, 'PATCH', {'draft': False, 'prerelease': prerelease})
    print(f'Published {tag} after verifying all uploaded assets')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['preflight', 'verify', 'publish'])
    parser.add_argument('directory', nargs='?', type=Path)
    args = parser.parse_args()
    if args.operation == 'preflight':
        preflight()
    elif args.directory is None:
        parser.error('verify and publish require an artifact directory')
    elif args.operation == 'verify':
        verify(args.directory)
    else:
        publish(args.directory)


if __name__ == '__main__':
    main()
