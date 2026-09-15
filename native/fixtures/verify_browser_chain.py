#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise Rust's actual native browser-chain verifier, not a mocked TLS result."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from verify_protocols import Failure, certificates, process


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    args = parser.parse_args()
    driver = args.driver.absolute().with_name('browser_chain_fixture' + ('.exe' if os.name == 'nt' else ''))
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='ocvpn-browser-chain-') as directory:
            root = Path(directory)
            ca = certificates(root)
            der = root / 'server.der'
            der.write_bytes(x509.load_pem_x509_certificate((root / 'server.pem').read_bytes()).public_bytes(Encoding.DER))
            with tempfile.TemporaryFile(dir=root) as output:
                with process([str(driver), str(args.native_root.resolve(strict=True)), str(der), str(ca)],
                             stdout=output, stderr=subprocess.DEVNULL) as child:
                    child.wait(timeout=30)
                    if child.returncode:
                        raise Failure('native_browser_chain_policy_failed')
                output.seek(0)
                result = json.loads(output.read(65537))
                if result.get('passed') is not True:
                    raise Failure('native_browser_chain_policy_failed')
    finally:
        os.umask(previous)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(json.dumps({'schema_version': 1, 'passed': False,
                          'error': str(error) if isinstance(error, Failure) else type(error).__name__}))
        sys.exit(1)
