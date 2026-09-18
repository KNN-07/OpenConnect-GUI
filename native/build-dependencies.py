#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build pinned shared dependencies on native macOS or Windows/MinGW-w64.

Requires C toolchain, make, pkg-config, meson, ninja, gettext, m4 and Python
with tarfile.data_filter. No Brew/MSYS dependency libraries are consumed.
Linux release dependencies instead come from packaging/Dockerfile.release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
LOCK = Path(__file__).with_name('dependency-sources.json')


def run(args, **kwargs):
    subprocess.run([str(x) for x in args], check=True, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--fetch-only', action='store_true', help='Download authenticated pinned archives without building')
    args = parser.parse_args()
    target = args.target
    host = next(line[6:] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
    if target == 'host':
        target = host
    if target != host or not any(kind in target for kind in ['apple-darwin', 'pc-windows-msvc']):
        if not args.fetch_only:
            raise RuntimeError('Use a matching native macOS/MSVC runner (Windows C libraries build inside MSYS2 MinGW-w64); Linux uses the baseline snapshot recipe')
    work = ROOT / 'target/dependencies' / target
    sources = work / 'sources'
    sources.mkdir(parents=True, exist_ok=True)
    lock = json.loads(LOCK.read_text())
    for package in lock['packages']:
        filename = package['url'].rsplit('/', 1)[1]
        path = sources / filename
        if not path.exists():
            with urllib.request.urlopen(package['url'], timeout=120) as response, path.open('xb') as output:
                shutil.copyfileobj(response, output)
        if digest(path) != package['sha256']:
            raise RuntimeError(f'Pinned source digest mismatch: {filename}; preserve evidence and replace the corrupt download explicitly')
    shutil.copyfile(LOCK, sources / LOCK.name)
    shutil.copyfile(Path(__file__), sources / 'build.py')
    manifest = {'schema_version': 1, 'packages': lock['packages'], 'files': {p.name: digest(p) for p in sorted(sources.iterdir()) if p.is_file() and p.name != 'sources.json'}}
    (sources / 'sources.json').write_text(json.dumps(manifest, indent=2) + '\n')
    if args.fetch_only:
        return
    prefix = work / 'prefix'
    if prefix.exists():
        completed = json.loads((prefix / 'dependency-prefix.json').read_text())
        if completed.get('target') != target or completed.get('source_lock_sha256') != digest(LOCK) or completed.get('recipe_sha256') != digest(Path(__file__)):
            raise RuntimeError('Dependency prefix provenance differs; preserve or move it before rebuilding')
        for relative, expected in completed['files'].items():
            path = prefix / relative
            if not path.resolve().is_relative_to(prefix.resolve()) or digest(path) != expected:
                raise RuntimeError('Dependency prefix was modified; preserve or move it before rebuilding')
        return
    prefix.mkdir()
    prefix = prefix.resolve()
    # Windows source configure/make must see MSYS POSIX paths, not drive-letter
    # colon-separated pkg-config entries or MSVC compiler flags.
    windows = 'windows' in target
    def native_path(path):
        return subprocess.check_output(['cygpath', '-u', str(path)], text=True).strip() if windows else str(path)
    pfx = native_path(prefix)
    environment = dict(os.environ)
    pkg_prefix = prefix.as_posix() if windows else pfx
    environment.update({'PKG_CONFIG_PATH': pkg_prefix + '/lib/pkgconfig', 'PKG_CONFIG_LIBDIR': pkg_prefix + '/lib/pkgconfig', 'CPPFLAGS': '-I' + pfx + '/include', 'LDFLAGS': '-L' + pfx + '/lib', 'CFLAGS': '-O2 -std=gnu11', 'CXXFLAGS': '-O2'})
    environment['PATH'] = str(prefix / 'bin') + os.pathsep + environment.get('PATH', '')
    if windows:
        environment.update({'CC': 'x86_64-w64-mingw32-gcc', 'CXX': 'x86_64-w64-mingw32-g++', 'AR': 'ar', 'RANLIB': 'ranlib'})
        environment['LDFLAGS'] += ' -static-libgcc -static-libstdc++'
    else:
        environment['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
        environment['DYLD_LIBRARY_PATH'] = str(prefix / 'lib')
    options = {
        'gmp': ['--disable-cxx'],
        'nettle': ['--disable-documentation'],
        'libffi': ['--disable-docs'],
        'libxml2': ['--without-python', '--without-icu', '--without-lzma', '--without-iconv', '--with-zlib', '--disable-maintainer-mode'],
        'gnutls': ['--with-included-unistring', '--with-included-libtasn1', '--without-idn', '--without-tpm', '--without-tpm2', '--without-brotli', '--without-zstd', '--with-zlib=link', '--with-p11-kit', '--disable-libdane', '--disable-cxx', '--disable-tools', '--disable-doc', '--disable-tests', '--disable-nls'],
        'stoken': ['--without-gtk', '--without-java', '--without-tomcrypt', '--with-nettle'],
        'oath-toolkit': ['--disable-gtk-doc', '--disable-nls', '--disable-pam'],
    }
    for package in lock['packages']:
        build = work / 'build' / package['name']
        build.mkdir(parents=True, exist_ok=False)
        with tarfile.open(sources / package['url'].rsplit('/', 1)[1]) as archive:
            archive.extractall(build, filter='data')
        directories = [p for p in build.iterdir() if p.is_dir()]
        if len(directories) != 1:
            raise RuntimeError('Source archive does not have one root')
        source = directories[0]
        name = package['name']
        if name == 'p11-kit':
            meson_environment = environment.copy()
            if windows:
                # Meson/Ninja are native Windows processes, not MSYS shells.
                meson_environment['CPPFLAGS'] = '-I' + pkg_prefix + '/include'
                meson_environment['CFLAGS'] += ' -I' + pkg_prefix + '/include'
                meson_environment['LDFLAGS'] = '-L' + pkg_prefix + '/lib -static-libgcc -static-libstdc++'
            run(['meson', 'setup', 'output', '--prefix', pkg_prefix, '--libdir', 'lib', '--default-library', 'shared', '-Dtrust_module=disabled', '-Dlibffi=enabled', '-Dsystemd=disabled', '-Dgtk_doc=false', '-Dman=false', '-Dnls=false', '-Dtest=false'], cwd=source, env=meson_environment)
            run(['meson', 'compile', '-C', 'output'], cwd=source, env=meson_environment)
            run(['meson', 'install', '-C', 'output'], cwd=source, env=meson_environment)
        elif name == 'zlib' and windows:
            variables = ['PREFIX=x86_64-w64-mingw32-', 'AR=ar', 'RC=windres', 'STRIP=strip', 'prefix=' + pfx, 'LDFLAGS=-static-libgcc', 'SHARED_MODE=1', 'BINARY_PATH=' + pfx + '/bin', 'LIBRARY_PATH=' + pfx + '/lib', 'INCLUDE_PATH=' + pfx + '/include']
            run(['make', '-f', 'win32/Makefile.gcc', '-j2', *variables], cwd=source, env=environment)
            run(['make', '-f', 'win32/Makefile.gcc', 'install', *variables], cwd=source, env=environment)
        else:
            configure = ['sh', './configure', '--prefix=' + pfx]
            if name != 'zlib':
                configure += ['--libdir=' + pfx + '/lib', '--enable-shared', '--disable-static']
                if windows:
                    configure += ['--host=x86_64-w64-mingw32']
            configure += options.get(name, [])
            run(configure, cwd=source, env=environment)
            run(['make', '-j2'], cwd=source, env=environment)
            run(['make', 'install'], cwd=source, env=environment)
        if windows:
            # Native pkg-config cannot resolve MSYS drive paths when launched
            # directly by Python or Meson. Both toolchains accept D:/... paths.
            for pc in (prefix / 'lib/pkgconfig').glob('*.pc'):
                pc.write_text(pc.read_text().replace(pfx, pkg_prefix))
        licenses = prefix / 'share/licenses' / name
        licenses.mkdir(parents=True)
        if name == 'zlib':
            shutil.copyfile(source / 'zlib.h', licenses / 'zlib.h')
        for path in source.rglob('*'):
            if path.is_file() and path.name.upper().startswith(('COPYING', 'LICENSE', 'LICENCE', 'NOTICE')) and 'output' not in path.relative_to(source).parts:
                destination = licenses / path.relative_to(source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
    # Make pkg-config paths relocatable for content-addressed prefix archives.
    for path in (prefix / 'lib/pkgconfig').glob('*.pc'):
        value = path.read_text()
        value = value.replace(pkg_prefix, '${pcfiledir}/../..')
        path.write_text(value)
    (prefix / 'dependency-prefix.json').write_text(json.dumps({'schema_version': 1, 'target': target, 'source_lock_sha256': digest(LOCK), 'recipe_sha256': digest(Path(__file__)), 'files': {p.relative_to(prefix).as_posix(): digest(p) for p in sorted(prefix.rglob('*')) if p.is_file()}}, indent=2) + '\n')
    print(f'Pinned prefix: {prefix.relative_to(ROOT)}; set OCVPN_DEPENDENCY_SOURCES={sources.relative_to(ROOT)} for packaging')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'dependency build: {error}')
