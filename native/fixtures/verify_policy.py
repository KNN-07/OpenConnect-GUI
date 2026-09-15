#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 OpenConnect GUI contributors
"""Real shared-client TLS policy and native command lifetime coverage, not VPN auth.

All trust/configuration is temporary and private. The selected Python needs
cryptography. The command lifetime probe runs separately with default SIGPIPE,
so Python's usual ignored SIGPIPE cannot conceal a broken native bridge.
"""
import argparse
import base64
import contextlib
import ctypes
import errno
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone

STAGE = 'initialization'
OBSERVED = []
ERROR_CODES = frozenset({
    'invalid_input', 'unsupported_protocol', 'unsupported_authentication', 'engine_unavailable',
    'runtime_failure', 'authentication_required', 'authentication_rejected', 'service_unavailable',
    'authorization_denied', 'busy', 'conflict', 'not_found', 'corrupt_storage', 'newer_schema',
    'keyring_unavailable', 'certificate_rejected', 'cancelled', 'protocol_violation',
    'network_failure', 'recovery_required',
})


class Failure(Exception):
    """Only fixed, nonsecret diagnostic text may be attached."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def private_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream)


def invoke(command, directory, environment=None, timeout=40):
    # Never replay raw native diagnostics: even failed driver output can contain
    # server-supplied fields. Capture privately and expose only validated JSON.
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                    stderr=stderr, env=environment, timeout=timeout,
                                    check=False)
        except subprocess.TimeoutExpired:
            raise Failure('Owned child exceeded its deadline') from None
        if result.returncode != 0:
            stderr.seek(0)
            codes = set()
            for line in stderr.read(16384).splitlines():
                try:
                    diagnostic = json.loads(line)
                    code = diagnostic.get('code') if isinstance(diagnostic, dict) else None
                    if isinstance(code, str) and code in ERROR_CODES:
                        codes.add(code)
                except (ValueError, UnicodeError):
                    pass
            suffix = '; error codes: ' + ','.join(sorted(codes)) if codes else ''
            raise Failure('Owned child failed (exit status %d)%s' % (result.returncode, suffix))
        stdout.seek(0)
        data = stdout.read(16385)
        require(len(data) <= 16384, 'Child result exceeded the JSON limit')
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            raise Failure('Child did not return one JSON result') from None
        require(isinstance(value, dict), 'Child result was not an object')
        return value


def certificates(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable policy fixture CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_path = directory / 'ca.pem'
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    pairs = []
    for index in range(2):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
                .issuer_name(ca_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                    x509.IPAddress(ipaddress.ip_address('::1'))]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        cert_path, key_path = directory / ('server%d.pem' % index), directory / ('server%d.key' % index)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        pin = 'pin-sha256:' + base64.b64encode(hashlib.sha256(spki).digest()).decode('ascii')
        pairs.append((cert_path, key_path, pin))
    require(pairs[0][2] != pairs[1][2], 'Fixture certificates must have distinct SPKIs')
    return ca_path, pairs


class Endpoint(http.server.HTTPServer):
    def __init__(self, pair, redirect=None):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(pair[0]), str(pair[1]))
        self.redirect = redirect
        self.visits = 0
        super().__init__(('127.0.0.1', 0), Request)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        pass  # TLS rejection and disconnects must not dump requests.


class Request(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self):
        self.server.visits += 1
        # We deliberately do not parse/store any authentication request body.
        # Neither endpoint implements a VPN or claims to authenticate a user.
        self.send_response(302 if self.server.redirect else 400)
        if self.server.redirect:
            self.send_header('Location', self.server.redirect)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    do_GET = respond
    do_POST = respond
    do_HEAD = respond


@contextlib.contextmanager
def serving(pair, redirect=None):
    endpoint = Endpoint(pair, redirect)
    thread = threading.Thread(target=endpoint.serve_forever, kwargs={'poll_interval': 0.05})
    thread.start()
    try:
        yield endpoint
    finally:
        endpoint.shutdown()
        endpoint.server_close()
        thread.join(timeout=5)
        require(not thread.is_alive(), 'Owned HTTPS thread did not stop')


def tls_policy(args, directory):
    global STAGE
    ca, pairs = certificates(directory)
    results = []
    with serving(pairs[1]) as second:
        second_port = second.server_port
        with serving(pairs[0], 'https://127.0.0.1:%d/terminal' % second_port) as first:
            first_port = first.server_port
            # Different ports for the same host are intentional: the wrong pin
            # on the redirect must not prevent contacting the initial endpoint.
            cases = [
                ('unpinned_control', [], 'authentication_rejected', True),
                ('redirect_pin_mismatch', [('127.0.0.1', second_port, pairs[0][2])], 'certificate_rejected', False),
                ('matching_redirect_pin', [('127.0.0.1', second_port, pairs[1][2])], 'authentication_rejected', True),
                ('other_hostname_isolation', [('localhost', second_port, pairs[0][2])], 'authentication_rejected', True),
                # A pin on neither endpoint must not change their CA trust.
                # Pinning the initial endpoint instead intentionally disables
                # CA trust for this context; a new redirect needs approval.
                ('other_port_isolation', [('127.0.0.1', 1, pairs[0][2])], 'authentication_rejected', True),
                ('strict_pin_new_peer_requires_decision', [('127.0.0.1', first_port, pairs[0][2])],
                 'certificate_rejected', False),
                ('strict_matching_without_ca', [('127.0.0.1', first_port, pairs[0][2]),
                                                 ('127.0.0.1', second_port, pairs[1][2])],
                 'authentication_rejected', True),
            ]
            for name, pins, error, visit_second in cases:
                STAGE = name
                config = directory / name
                config.mkdir(mode=0o700)
                private_json(config / 'certificate-pins.json', {
                    'schema_version': 1, 'revision': 1,
                    'pins': [{'host': host, 'port': port, 'fingerprint': pin} for host, port, pin in pins]})
                profile = {'id': str(uuid.uuid4()), 'revision': 1, 'name': 'TLS policy fixture',
                           'protocol': 'anyconnect', 'server': 'https://127.0.0.1:%d/start' % first_port,
                           'ca_file': None if name == 'strict_matching_without_ca' else str(ca),
                           'remember_password': False}
                fixture = config / 'input.json'
                private_json(fixture, {'profile': profile, 'rounds': [], 'expect_error': error})
                environment = dict(os.environ)
                environment['OCVPN_CONFIG_DIR'] = str(config)
                # Avoid inherited proxy configuration routing loopback traffic.
                for key in list(environment):
                    if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
                        del environment[key]
                before = (first.visits, second.visits)
                try:
                    value = invoke([str(args.driver), str(args.native_root), str(fixture)], directory, environment)
                finally:
                    OBSERVED.append({'case': name, 'initial_http_requests': first.visits - before[0],
                                     'redirect_http_requests': second.visits - before[1]})
                require(value.get('expected_error') == error and value.get('protocol') == 'anyconnect',
                        'Driver did not confirm the expected typed policy result')
                observed = (first.visits - before[0], second.visits - before[1])
                require(observed[0] > 0, 'Initial CA-trusted endpoint was not contacted')
                require((observed[1] > 0) if visit_second else (observed[1] == 0),
                        'Redirect HTTP visitation violated the saved-pin policy')
                results.append({'case': name, 'expected_error': error,
                                'initial_http_requests': observed[0], 'redirect_http_requests': observed[1]})
    return {'coverage': 'tls_policy_only_not_vpn_authentication', 'cases': results}


def command_lifetime(root):
    require(sys.platform.startswith('linux'), 'Command FD lifetime probe currently requires Linux')
    import fcntl
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    library = ctypes.CDLL(str(root / 'lib/libopenconnect.so.5'), use_errno=True)
    def function(name, result, *arguments):
        value = getattr(library, name)
        value.restype, value.argtypes = result, list(arguments)
        return value
    pointer = ctypes.c_void_p
    abi = function('ocgui_bridge_abi', ctypes.c_uint)
    require(abi() == 4, 'Command probe requires bridge ABI4')
    init = function('openconnect_init_ssl', ctypes.c_int)
    new = function('openconnect_vpninfo_new', pointer, ctypes.c_char_p, pointer, pointer, pointer, pointer, pointer)
    free = function('openconnect_vpninfo_free', None, pointer)
    setup = function('openconnect_setup_cmd_pipe', ctypes.c_int, pointer)
    duplicate = function('ocgui_duplicate_cmd_handle', ctypes.c_ssize_t, pointer)
    send = function('ocgui_send_cmd', ctypes.c_int, ctypes.c_ssize_t, ctypes.c_ubyte)
    close = function('ocgui_close_cmd_handle', None, ctypes.c_ssize_t)
    require(init() == 0, 'Native TLS initialization failed')
    # An invalid native implementation now kills only this isolated child.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGPIPE})
    vpn, owned = new(b'ocvpn-policy-lifetime', None, None, None, None, None), -1
    require(bool(vpn), 'Native context allocation failed')
    try:
        original = setup(vpn)
        require(original >= 0, 'Native command pipe setup failed')
        owned = duplicate(vpn)
        require(owned >= 0 and owned != original, 'Command duplicate was not independently owned')
        require(fcntl.fcntl(owned, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, 'Command duplicate was inheritable')
        require(send(owned, ord('x')) == 0, 'Live command send failed')
        free(vpn)
        vpn = None
        require_closed(original)
        os.fstat(owned)
        result = send(owned, ord('x'))
        require(result == -errno.EPIPE, 'Destroyed-context command send did not return EPIPE')
        descriptor = owned
        ctypes.set_errno(errno.EDOM)
        close(owned)
        owned = -1
        require(ctypes.get_errno() == errno.EDOM, 'Command close did not preserve errno')
        require_closed(descriptor)
        return {'bridge_abi': abi(), 'live_send': 'ok', 'after_context_free': 'epipe',
                'sigpipe_disposition': 'default', 'duplicate_noninheritable': True,
                'original_closed_by_context': True, 'duplicate_closed_by_owner': True}
    finally:
        if vpn:
            free(vpn)
        if owned >= 0:
            close(owned)


def require_closed(descriptor):
    try:
        os.fstat(descriptor)
    except OSError as error:
        require(error.errno == errno.EBADF, 'Descriptor closure returned an unexpected error')
    else:
        raise Failure('Owned command descriptor leaked')


def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', required=True, type=Path)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--python', required=True, type=Path)
    parser.add_argument('--child', choices=('tls', 'command'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.native_root = args.native_root.resolve(strict=True)
    args.driver = args.driver.resolve(strict=True)
    # Do not resolve a venv interpreter symlink to the system interpreter:
    # Python uses the invoked path to discover pyvenv.cfg and dependencies.
    args.python = args.python.absolute()
    require(args.python.is_file(), 'Selected Python interpreter is missing')
    os.umask(0o077)
    command = [str(args.python), str(Path(__file__).resolve()), '--native-root', str(args.native_root),
               '--driver', str(args.driver), '--python', str(args.python)]
    if args.child is None:
        # Replacement avoids a killed TLS supervisor stranding a driver child.
        os.execv(str(args.python), command + ['--child', 'tls'])
    if args.child == 'command':
        # No private filesystem state is needed by the crash-isolated probe.
        print(json.dumps(command_lifetime(args.native_root), indent=2))
        return
    with tempfile.TemporaryDirectory(prefix='ocvpn-policy-') as temporary:
        directory = Path(temporary)
        result = {'schema_version': 1, 'coverage': 'tls_policy_and_command_lifetime_not_vpn_authentication'}
        result['tls_policy'] = tls_policy(args, directory)
        STAGE = 'command_lifetime'
        result['command_lifetime'] = invoke(command + ['--child', 'command'], directory, timeout=15)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        detail = str(error) if isinstance(error, Failure) else type(error).__name__
        print(json.dumps({'schema_version': 1, 'coverage': 'tls_policy_and_command_lifetime_not_vpn_authentication',
                          'passed': False, 'stage': STAGE, 'observed': OBSERVED, 'error': detail}, indent=2), file=sys.stderr)
        sys.exit(1)
