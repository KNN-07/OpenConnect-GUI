#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prove a failed HOTP commit prevents submission to the real GP fixture."""
import argparse
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile

from verify_protocols import Failure, certificates, fresh_port, process, profile, ready, request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    args = parser.parse_args()
    native = args.native_root.resolve(strict=True)
    suffix = '.exe' if os.name == 'nt' else ''
    token_driver = args.driver.absolute().with_name('hotp_commit_fixture' + suffix)
    if not token_driver.is_file():
        raise Failure('hotp_fixture_driver_missing')
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='ocvpn-hotp-') as directory:
            root = Path(directory)
            ca = certificates(root)
            counts = root / 'request-counts'
            host, port = '127.0.0.1', fresh_port('127.0.0.1')
            environment = dict(os.environ, OCVPN_FIXTURE_COUNTS_FILE=str(counts))
            argv = [str(args.python.absolute()), str(Path(__file__).with_name('run.py').resolve()),
                    'gp', host, str(port), str(root / 'server.pem'), str(root / 'server.key')]
            context = ssl.create_default_context(cafile=str(ca))
            with process(argv, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as server:
                ready(server, host, port, context, 'gp')
                if request(host, port, context, '/CONFIGURE', {'portal_2fa': 'xml'}) != 201:
                    raise Failure('hotp_fixture_configuration_failed')
                input_path = root / 'profile.json'
                input_path.write_text(json.dumps(profile('gp', host, port, ca)), encoding='utf-8')
                with tempfile.TemporaryFile(dir=root) as output:
                    with process([str(token_driver), str(native), str(input_path)],
                                 stdout=output, stderr=subprocess.DEVNULL) as driver:
                        driver.wait(timeout=40)
                        if driver.returncode:
                            raise Failure('hotp_commit_boundary_not_exercised')
                    output.seek(0)
                    result = json.loads(output.read(65537))
                    if result != {'schema_version': 1, 'hotp_commit_failure': True}:
                        raise Failure('unexpected_hotp_driver_result')
                submitted = counts.read_bytes()
                # Field tags are not requests. Only the initial portal password
                # request may cross the boundary before the failed HOTP commit.
                if submitted.count(b'P') != 1 or any(marker in submitted for marker in (b'G', b'C')):
                    raise Failure('hotp_submitted_without_durable_counter_commit')
    finally:
        os.umask(previous_umask)
    print(json.dumps({'schema_version': 1, 'passed': True, 'coverage': 'native_hotp_commit_failure',
                      'portal_password_requests': 1, 'uncommitted_otp_requests': 0}))


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(json.dumps({'schema_version': 1, 'passed': False,
                          'error': str(error) if isinstance(error, Failure) else type(error).__name__}))
        sys.exit(1)
