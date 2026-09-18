#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the RPM lifecycle in an isolated systemd container on a hosted runner."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('Requires a disposable GitHub-hosted runner')
    packages = list(Path('artifacts').glob('openconnect-gui*.rpm'))
    if len(packages) != 1:
        raise SystemExit('Expected exactly one GUI RPM')
    name = 'ocvpn-rpm-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='ocvpn-fedora-') as temporary:
        Path(temporary, 'Dockerfile').write_text(
            'FROM quay.io/fedora/fedora:42@sha256:e78cd1a688cd079c23864f289a89a49a3f4ad66d817864e325e1d058310ee95c\n'
            'RUN dnf install -y systemd sudo python3 && dnf clean all\n'
            'STOPSIGNAL SIGRTMIN+3\n'
            'CMD ["/sbin/init"]\n'
        )
        run('docker', 'build', '--tag', name, temporary)
    run('docker', 'create', '--name', name, '--privileged', '--cgroupns=private',
        '--tmpfs', '/run', '--tmpfs', '/tmp', name)
    try:
        run('docker', 'cp', str(packages[0]), name + ':/package.rpm')
        run('docker', 'cp', 'packaging/smoke.py', name + ':/smoke.py')
        run('docker', 'start', name)
        for _ in range(60):
            ready = subprocess.run(['docker', 'exec', name, 'systemctl', 'is-system-running'], capture_output=True, text=True)
            if ready.stdout.strip() in {'running', 'degraded'}:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Fedora systemd did not become ready')
        run('docker', 'exec', '--env', 'OCVPN_DISPOSABLE_RUNNER=1', name,
            'python3', '/smoke.py', '/package.rpm')
    finally:
        subprocess.run(['docker', 'logs', name], check=False)
        run('docker', 'rm', '--force', name)


if __name__ == '__main__':
    main()
