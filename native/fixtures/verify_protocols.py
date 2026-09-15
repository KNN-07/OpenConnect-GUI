#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Development-only native authentication proof, not vendor/tunnel interoperability.

Protocol scenarios follow OpenConnect 9.21 tests/auth-multicert,
juniper-auth, pulse-ping, gp-auth-and-config, f5-auth-and-config and
fortinet-auth-and-config. The upstream LGPL-2.1-or-later implementations
and notices remain in the digest-verified archive consumed by run.py.
"""
import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid


class Failure(Exception):
    pass


def driver_diagnostic(stream):
    stream.seek(0)
    raw = stream.read(65537)
    if len(raw) > 65536:
        return 'stderr_limit'
    known_fields = {'username', 'user', 'password', 'passwd', 'credential', 'code',
                    'realm', 'domain', 'gateway', 'authgroup', 'group_list', 'secondary_password', 'method', 'uname', 'pwd'}
    for line in raw.decode('utf-8', errors='replace').splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        code = value.get('code')
        if code in {'authentication_required', 'authentication_rejected', 'certificate_rejected',
                    'unsupported_authentication', 'engine_unavailable', 'protocol_violation',
                    'invalid_input', 'runtime_failure', 'cancelled'}:
            return code
        fields = value.get('fields')
        if isinstance(fields, list):
            names = [field.get('name') for field in fields if isinstance(field, dict)]
            return 'unexpected_prompt:' + ','.join(name if name in known_fields else 'other' for name in names[:16])
    if b'Expected authentication rounds were not requested' in raw:
        return 'unused_rounds'
    return 'no_structured_diagnostic'


@contextlib.contextmanager
def process(argv, **kwargs):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, **kwargs)
    try:
        yield child
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        else:
            child.wait()


def certificates(root):
    def openssl(*args):
        result = subprocess.run(['openssl', *map(str, args)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        if result.returncode:
            raise Failure('certificate_generation_failed')

    ca, ca_key = root / 'ca.pem', root / 'ca.key'
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Disposable OpenConnect fixture CA', '-keyout', ca_key,
            '-out', ca, '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth'), ('secondary', 'clientAuth')]:
        key, csr, cert, ext = [root / (name + suffix) for suffix in ('.key', '.csr', '.pem', '.ext')]
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                       f'extendedKeyUsage={usage}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'
                       + ('subjectAltName=IP:127.0.0.1,IP:::1,DNS:localhost\n' if name == 'server' else ''), encoding='ascii')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN=Fixture {name}',
                '-keyout', key, '-out', csr)
        openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key, '-set_serial',
                str(uuid.uuid4().int), '-days', '1', '-sha256', '-extfile', ext, '-out', cert)
    return ca


def fresh_port(host):
    with socket.socket() as listener:
        listener.bind((host, 0))
        return listener.getsockname()[1]


def request(host, port, context, path, data=None):
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=2)
    try:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        connection.request('POST' if body is not None else 'GET', path, body,
                           {'Content-Type': 'application/x-www-form-urlencoded'} if body is not None else {})
        response = connection.getresponse()
        response.read(65537)
        return response.status
    finally:
        connection.close()


def ready(child, host, port, context, protocol):
    # Pulse wraps its listening socket in TLS and cannot survive a bare TCP
    # connect/close probe. A complete authenticated TLS GET /STATUS is safe.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise Failure('fixture_start_failed')
        try:
            status = request(host, port, context, '/STATUS' if protocol == 'pulse' else '/CONFIGURE')
            if status in (200, 404, 405):
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise Failure('fixture_readiness_timeout')


def profile(protocol, host, port, ca):
    return dict(id=str(uuid.uuid4()), revision=1, name='Private native fixture', protocol=protocol,
                server=f'https://{host}:{port}/', username='test', ca_file=str(ca),
                browser_mode='manual', remember_password=False)


def drive(args, root, payload):
    # No secrets in argv, environment, stdout or retained diagnostics.
    input_path = root / 'input.json'
    input_path.write_text(json.dumps(payload), encoding='utf-8')
    try:
        with tempfile.TemporaryFile(dir=root) as output, tempfile.TemporaryFile(dir=root) as errors:
            with process([str(args.driver), str(args.native_root), str(input_path)],
                         stdout=output, stderr=errors) as child:
                try:
                    child.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    raise Failure('driver_timeout') from None
                if child.returncode:
                    raise Failure('driver_rejected_scenario:' + driver_diagnostic(errors))
            output.seek(0)
            raw = output.read(65537)
            if len(raw) > 65536:
                raise Failure('driver_output_limit')
        result = json.loads(raw)
        if result.get('protocol') != payload['profile']['protocol']:
            raise Failure('driver_protocol_mismatch')
        expected = payload.get('expect_error')
        if expected:
            if result.get('expected_error') != expected:
                raise Failure('driver_error_mismatch')
            return {'expected_error': expected}
        if result.get('authenticated') is not True or result.get('prompt_count') != len(payload['rounds']):
            raise Failure('driver_prompt_contract_mismatch')
        return {'authenticated': True, 'prompt_count': result['prompt_count'],
                'numeric_peer': result.get('numeric_peer') is True}
    finally:
        input_path.unlink(missing_ok=True)


def protocol_cases(args, root, ca, protocol, report):
    host = '127.0.0.1'
    port = fresh_port(host)
    argv = [str(args.python), str(Path(__file__).with_name('run.py').resolve()), protocol, host, str(port)]
    if protocol == 'pulse':
        argv += ['192.0.2.0/24']
    argv += [str(root / 'server.pem'), str(root / 'server.key')]
    if protocol == 'anyconnect':
        argv += ['--enable-multicert', '--cafile', str(ca)]
    context = ssl.create_default_context(cafile=str(ca))
    with process(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
        ready(child, host, port, context, protocol)
        base = profile(protocol, host, port, ca)
        if protocol == 'anyconnect':
            base.update(client_certificate=str(root / 'client.pem'), client_key=str(root / 'client.key'),
                        secondary_certificate=str(root / 'secondary.pem'), secondary_key=str(root / 'secondary.key'))
        gateway = {'gateway': f'{host}:{port}#bar'}
        cases = [('multicert' if protocol == 'anyconnect' else 'password', {}, [], {})]
        if protocol == 'gp':
            cases = [
                ('gateway_selection', {'gateways': 'foo,bar,baz'}, [gateway], {}),
                ('saved_gateway_selection', {'gateways': 'foo,bar,baz'}, [], {'gateway': 'bar'}),
                ('removed_saved_gateway', {'gateways': 'foo,bar,baz'}, [], {'gateway': 'removed-gateway'}),
                ('portal_mfa_cookie_gateway_bypass', {'gateways': 'foo,bar,baz', 'portal_2fa': 'xml',
                 'gw_2fa': 'js', 'portal_cookie': 'portal-userauthcookie'}, [{'passwd': '123456'}, gateway], {}),
                ('independent_portal_gateway_mfa', {'gateways': 'foo,bar,baz', 'portal_2fa': 'xml', 'gw_2fa': 'js'},
                 [{'passwd': '123456'}, gateway, {'passwd': 'test'}, {'passwd': '654321'}], {}),
            ]
        elif protocol == 'fortinet':
            cases = [('password', {}, [], {}),
                     ('non_default_realm', {}, [], {'server': f'https://{host}:{port}/fakeRealm'}),
                     ('two_tokeninfo_rounds', {'want_2fa': '2', 'type_2fa': 'tokeninfo'},
                      [{'code': '123456'}, {'code': '654321'}], {})]
        for name, config, rounds, changes in cases:
            row = {'protocol': protocol, 'case': name, 'coverage': 'authentication_only', 'tunnel': 'unverified'}
            try:
                if protocol not in ('anyconnect', 'pulse'):
                    if request(host, port, context, '/CONFIGURE', config) != 201:
                        raise Failure('fixture_configuration_failed')
                payload = {'profile': dict(base, **changes), 'rounds': rounds, 'password': 'test'}
                if name == 'removed_saved_gateway':
                    payload['expect_error'] = 'authentication_required'
                row.update(drive(args, root, payload), status='passed')
            except (Failure, OSError, ValueError, http.client.HTTPException) as error:
                row.update(status='failed', reason=str(error) if isinstance(error, Failure) else type(error).__name__)
            report.append(row)


@contextlib.contextmanager
def tls_failure_endpoint(root):
    # No fabricated Array auth response: native Array selection reaches a real
    # TLS peer, then the shared certificate callback rejects its untrusted CA.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    listener.settimeout(0.2)
    stop = threading.Event()
    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(2)
                try:
                    with context.wrap_socket(connection, server_side=True) as tls:
                        tls.recv(4096)
                except OSError:
                    pass
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        worker.join(timeout=3)
        if worker.is_alive():
            raise Failure('tls_endpoint_cleanup_failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    args = parser.parse_args()
    args.native_root = args.native_root.resolve(strict=True)
    args.driver = args.driver.resolve(strict=True)
    # Preserve the venv executable symlink: resolving it to /usr/bin/python
    # discards pyvenv.cfg discovery and the fixture's installed dependencies.
    args.python = args.python.absolute()
    if not args.python.is_file():
        raise Failure('fixture_python_missing')
    report = []
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='ocvpn-protocols-') as directory:
            root = Path(directory)
            ca = certificates(root)
            for protocol in ('anyconnect', 'nc', 'pulse', 'gp', 'f5', 'fortinet'):
                try:
                    protocol_cases(args, root, ca, protocol, report)
                except (Failure, OSError, ValueError, http.client.HTTPException) as error:
                    report.append({'protocol': protocol, 'case': 'fixture_setup', 'status': 'failed',
                                   'reason': str(error) if isinstance(error, Failure) else type(error).__name__})
            row = {'protocol': 'array', 'case': 'untrusted_local_tls', 'authentication': 'unverified',
                   'tunnel': 'unverified', 'coverage': 'protocol_selection_and_tls_rejection_only'}
            try:
                with tls_failure_endpoint(root) as port:
                    p = profile('array', '127.0.0.1', port, ca)
                    p.pop('ca_file')
                    row.update(drive(args, root, {'profile': p, 'password': 'test', 'rounds': [{'method': 'default'}], 'certificates': ['reject'],
                                                  'expect_error': 'certificate_rejected'}), status='passed')
            except (Failure, OSError, ValueError) as error:
                row.update(status='failed', reason=str(error) if isinstance(error, Failure) else type(error).__name__)
            report.append(row)
    finally:
        os.umask(previous_umask)
    passed = all(row['status'] == 'passed' for row in report)
    print(json.dumps({'schema_version': 1, 'suite': 'native_protocol_authentication', 'passed': passed,
                      'vendor_interoperability': 'unverified', 'browser_sso': 'not_exercised', 'cases': report}, indent=2))
    return 0 if passed else 1


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(json.dumps({'schema_version': 1, 'passed': False, 'reason': 'interrupted'}))
        raise SystemExit(130)
    except Exception as error:
        print(json.dumps({'schema_version': 1, 'passed': False,
                          'reason': str(error) if isinstance(error, Failure) else type(error).__name__}))
        raise SystemExit(1)
