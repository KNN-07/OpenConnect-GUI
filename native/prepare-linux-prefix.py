#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Collect the Debian/Ubuntu native dependency closure, excluding libc.

Used by Dockerfile.linux and default local builds. No package installation.
Distro dependency versions are recorded by build.py, not claimed source-locked.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

prefix = Path(sys.argv[1])
lib = prefix / 'lib'
lib.mkdir(parents=True)
listing = subprocess.check_output(['/sbin/ldconfig', '-p'], text=True)
locations = {}
for line in listing.splitlines():
    match = re.match(r'\s*(\S+)\s+\(.*\) => (\S+)', line)
    if match:
        locations[match[1]] = Path(match[2])
roots = ['libgnutls.so', 'libnettle.so', 'libhogweed.so', 'libgmp.so',
         'libxml2.so', 'libz.so', 'libp11-kit.so', 'libstoken.so',
         'libpskc.so', 'libpcsclite.so']
pending = [name for name in locations if any(name.startswith(root + '.') for root in roots)]
for root in roots:
    if not any(name.startswith(root + '.') for name in pending):
        raise SystemExit('Missing dependency ' + root)
baseline = re.compile(r'^(lib(c|m|dl|rt|pthread|resolv|util)\.so\.|ld-linux)')
seen = set()
while pending:
    name = pending.pop()
    if name in seen or baseline.match(name):
        continue
    seen.add(name)
    source = locations.get(name)
    if source is None:
        raise SystemExit('Unresolved native dependency ' + name)
    shutil.copy2(source.resolve(), lib / name)
    dynamic = subprocess.check_output(['readelf', '-d', source], text=True)
    pending.extend(re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic))
# pkg-config files retain image /usr include/lib paths, while the output
# prefix contains only libraries needed by the pinned engine dependencies.
shutil.copytree('/usr/lib/x86_64-linux-gnu/pkgconfig', lib / 'pkgconfig')
licenses = prefix / 'share/licenses'
licenses.mkdir(parents=True)
shutil.copytree('/usr/share/common-licenses', licenses / 'common-licenses')
for copyright_file in Path('/usr/share/doc').glob('*/copyright'):
    destination = licenses / copyright_file.parent.name
    destination.mkdir(exist_ok=True)
    shutil.copy2(copyright_file, destination / 'copyright')
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}\t${Version}\n'], text=True)
(prefix / 'share/licenses/distro-packages.txt').write_text(packages)
(prefix / 'dependency-prefix.json').write_text(json.dumps({'libraries': sorted(seen)}, indent=2) + '\n')
