#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Collect exact distro sources for the staged dependency closure from deb-src.

Use the pinned Ubuntu snapshot in Dockerfile.release for release production.
APT authenticates source indexes and package hashes. Does not install packages.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prefix', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
listing = subprocess.check_output(['/sbin/ldconfig', '-p'], text=True)
locations = {}
for line in listing.splitlines():
    match = re.match(r'\s*(\S+)\s+\(.*\) => (\S+)', line)
    if match:
        locations[match[1]] = Path(match[2])
packages = set()
for library in (args.prefix / 'lib').iterdir():
    if not library.is_file() or '.so' not in library.name or 'openconnect' in library.name:
        continue
    original = locations[library.name].resolve()
    owners = None
    for candidate in [original, Path(str(original).replace('/usr/lib/', '/lib/'))]:
        result = subprocess.run(['dpkg-query', '-S', str(candidate)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if result.returncode == 0:
            owners = result.stdout.split(': ', 1)[0]
            break
    if not owners:
        raise SystemExit(f'No distro source owner for {library.name}')
    source = subprocess.check_output(['dpkg-query', '-W', '-f=${source:Package}\t${source:Version}', owners], text=True).strip().split('\t')
    packages.add(tuple(source))
for name, version in sorted(packages):
    subprocess.run(['apt-get', 'source', '--download-only', f'{name}={version}'], cwd=args.output, check=True)
root = Path(__file__).resolve().parent.parent
shutil.copyfile(root / 'packaging/Dockerfile.release', args.output / 'Dockerfile.release')
shutil.copyfile(root / 'native/prepare-linux-prefix.py', args.output / 'prepare-linux-prefix.py')
files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(args.output.iterdir()) if p.is_file()}
(args.output / 'sources.json').write_text(json.dumps({'schema_version': 1, 'provenance': 'Ubuntu APT authenticated source packages; versions exactly match bundled installed libraries', 'packages': [{'name': name, 'version': version} for name, version in sorted(packages)], 'files': files}, indent=2) + '\n')
