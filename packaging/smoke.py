#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Install/check/uninstall on disposable native reference runners only.

No tunnel/vendor claim. Native lab acceptance is a separate explicit operation.
Requires OCVPN_DISPOSABLE_RUNNER=1; do not use on a developer workstation.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path, nargs='?')
    parser.add_argument('--select-gui', nargs=2, metavar=('DIRECTORY', 'GLOB'))
    args = parser.parse_args()
    if os.environ.get('OCVPN_DISPOSABLE_RUNNER') != '1':
        raise SystemExit('Native install smoke requires an explicitly disposable runner')
    if args.select_gui:
        directory, pattern = args.select_gui
        candidates = [path for path in Path(directory).glob(pattern) if 'openconnect-cli' not in path.name.lower()]
        if len(candidates) != 1 or args.package:
            raise SystemExit('Select exactly one GUI installer')
        package = candidates[0].resolve()
    elif args.package:
        package = args.package.resolve()
    else:
        raise SystemExit('An installer package is required')
    if shutil.which('openconnect'):
        raise SystemExit('Reference runner must not have system OpenConnect installed')
    system = platform.system()
    if system == 'Linux':
        if package.suffix == '.deb':
            run(['sudo', 'apt-get', 'install', '-y', str(package)])
            uninstall = ['sudo', 'apt-get', 'remove', '-y', 'openconnect-gui']
        else:
            run(['sudo', 'dnf', 'install', '-y', package])
            uninstall = ['sudo', 'dnf', 'remove', '-y', 'openconnect-gui']
        cli = Path('/usr/bin/ocvpn')
    elif system == 'Darwin':
        run(['sudo', '/usr/sbin/installer', '-pkg', package, '-target', '/'])
        cli = Path('/Applications/OpenConnect GUI.app/Contents/MacOS/ocvpn')
        uninstall = ['sudo', '/Applications/OpenConnect GUI.app/Contents/Resources/uninstall']
    elif system == 'Windows':
        # Runner process must have native UAC/admin authorization. /S does not
        # bypass elevation or PowerShell execution policy.
        run([package, '/S'])
        cli = Path(os.environ['ProgramW6432']) / 'OpenConnect GUI/ocvpn.exe'
        uninstall = [cli.parent / 'uninstall.exe', '/S']
    else:
        raise SystemExit('Unsupported native runner')
    # Failures preserve the installed service and evidence for diagnosis, rather
    # than turning an unsuccessful lifecycle into an apparent uninstall pass.
    protocols = json.loads(run([cli, 'protocols', '--json'], stdout=subprocess.PIPE).stdout)
    required = {'anyconnect', 'nc', 'pulse', 'gp', 'f5', 'fortinet', 'array'}
    if protocols.get('schema_version') != 1 or not required.issubset({p['id'] for p in protocols['data']['protocols']}):
        raise SystemExit('Installed bundled engine did not report all seven required protocols')
    run([cli, 'doctor', '--json'])
    run([cli, 'service', 'status'])
    run(uninstall)
    if cli.exists():
        raise SystemExit('Uninstall did not remove the installed CLI')
    print('Native package install, installed protocols/doctor/service, and idle uninstall exercised. Tunnel, GUI and vendor behavior not covered.')


if __name__ == '__main__':
    main()
