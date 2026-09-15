#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Unpack a content-addressed native prefix plus its corresponding source recipes.

Input archive layout: prefix/{lib,include,share/licenses,...}, sources/ with
sources.json {schema_version:1, packages:[{name,version}], files:{path:sha256}},
and sources/build.py (native dependency build recipe). Archive is independently
pinned by the release operator; no mutable Brew/MSYS download is substituted.
"""
import hashlib
import json
import os
from pathlib import Path
import tarfile
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parent.parent
url = os.environ.get('OCVPN_PREFIX_URL', '')
expected = os.environ.get('OCVPN_PREFIX_SHA256', '')
if urllib.parse.urlparse(url).scheme != 'https' or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
    raise SystemExit('Set OCVPN_PREFIX_URL (HTTPS immutable archive) and OCVPN_PREFIX_SHA256 (64 lowercase hex); see packaging/README.md')
output = root / 'target/frozen-dependencies'
output.mkdir(parents=True, exist_ok=False)
archive = output / 'prefix.tar.gz'
with urllib.request.urlopen(url, timeout=120) as response, archive.open('wb') as stream:
    while chunk := response.read(1024 * 1024):
        stream.write(chunk)
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit('Native prefix digest mismatch')
if not hasattr(tarfile, 'data_filter'):
    raise SystemExit('Install Python with the tarfile security backport')
with tarfile.open(archive) as tar:
    tar.extractall(output, filter='data')
sources = output / 'sources'
manifest = json.loads((sources / 'sources.json').read_text())
if manifest.get('schema_version') != 1 or not manifest.get('packages') or not (sources / 'build.py').is_file():
    raise SystemExit('Frozen prefix must include matching source archives, pinned versions and a native build.py recipe')
for relative, checksum in manifest['files'].items():
    path = sources / relative
    if not path.resolve().is_relative_to(sources.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise SystemExit('Frozen prefix corresponding-source checksum mismatch')
if not (output / 'prefix/share/licenses').is_dir():
    raise SystemExit('Frozen prefix must include dependency license texts')
(output / 'provenance.json').write_text(json.dumps({'archive_sha256': expected, 'url': url}, indent=2) + '\n')
print('Verified native prefix: target/frozen-dependencies/prefix; corresponding sources: target/frozen-dependencies/sources')
