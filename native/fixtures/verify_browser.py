#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real GP/WebKit authentication and unrelated-origin isolation, not tunnel proof.

Linux automation owns a private Xvfb display. Other native runners use
--interactive and their logged-in desktop; credentials stay in a private file.
"""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from verify_protocols import Failure, certificates, fresh_port, process, profile, ready, request


@contextlib.contextmanager
def display_environment(interactive):
    environment = dict(os.environ)
    if interactive:
        yield environment
        return
    if sys.platform != 'linux':
        raise Failure('native_desktop_required_use_interactive_on_matching_runner')
    for executable in ['Xvfb', 'xdotool', 'import']:
        if not shutil.which(executable):
            raise Failure('missing_browser_verification_dependency_' + executable)
    reader, writer = os.pipe()
    try:
        with process(['Xvfb', '-displayfd', str(writer), '-screen', '0', '1200x850x24', '-nolisten', 'tcp'],
                     pass_fds=(writer,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as server:
            os.close(writer)
            writer = -1
            if not select.select([reader], [], [], 15)[0]:
                raise Failure('private_display_readiness_timeout')
            number = os.read(reader, 32).strip()
            if not number.isdigit() or server.poll() is not None:
                raise Failure('private_display_start_failed')
            environment.update(DISPLAY=':' + number.decode('ascii'), GDK_BACKEND='x11',
                               LIBGL_ALWAYS_SOFTWARE='1', WEBKIT_DISABLE_DMABUF_RENDERER='1',
                               WEBKIT_DISABLE_COMPOSITING_MODE='1', WEBKIT_SKIA_CPU_RENDERING='1')
            subprocess.run(['xdotool', 'getdisplaygeometry'], env=environment, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            yield environment
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)


@contextlib.contextmanager
def isolation_probe(root):
    class Handler(http.server.BaseHTTPRequestHandler):
        completed = 0
        exposed = False
        lock = threading.Lock()

        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path.startswith('/result?'):
                with self.lock:
                    Handler.completed += 1
                    Handler.exposed |= self.path != '/result?exposed=0'
                self.send_response(204)
                self.end_headers()
                return
            body = b'''<!doctype html><title>Unrelated origin</title><p>Isolation probe</p>
<script>
let exposed = !!window.__TAURI_INTERNALS__ || !!window.__TAURI__ || !!window.ipc;
try { exposed ||= !!window.webkit?.messageHandlers?.ipc; } catch (_) {}
fetch('/result?exposed=' + Number(exposed), {cache:'no-store'});
</script>'''
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # A subresource from another origin cannot supply SAML completion.
            self.send_header('saml-auth-status', '1')
            self.send_header('saml-username', 'wrong-origin-account')
            self.send_header('prelogin-cookie', 'not-an-authentication-credential')
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'https://127.0.0.1:{server.server_port}/', Handler
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise Failure('isolation_probe_cleanup_failed')


def submit_form(child, counts, expected, probe, probe_expected, environment, account, password, screenshot):
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise Failure('native_browser_exited_before_form')
        if counts.read_bytes().count(b'S') >= expected and probe.completed >= probe_expected:
            if probe.exposed:
                raise Failure('unrelated_origin_has_application_ipc')
            windows = subprocess.run(['xdotool', 'search', '--onlyvisible', '--name', '^OpenConnect GUI — Authentication$'],
                                     env=environment, capture_output=True, timeout=5).stdout.split()
            if len(windows) == 1:
                time.sleep(0.5)
                subprocess.run(['xdotool', 'windowfocus', '--sync', windows[0]], env=environment,
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                subprocess.run(['import', '-display', environment['DISPLAY'], '-window', 'root', str(screenshot)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                for value, key in [(account, 'Tab'), (password, 'Return')]:
                    subprocess.run(['xdotool', 'type', '--clearmodifiers', '--file', '-'], input=value.encode(),
                                   env=environment, check=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
                    subprocess.run(['xdotool', 'key', key], env=environment, check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                return
        time.sleep(0.1)
    raise Failure(f'native_browser_form_or_isolation_probe_timeout(forms={counts.read_bytes().count(b"S")}, probe_results={probe.completed})')


def drive(args, root, config, counts, probe, environment, accounts, evidence):
    payload = {'profile': config, 'password': 'fixture-only-password', 'browser_accounts': accounts}
    input_path = root / 'input.json'
    input_path.write_text(json.dumps(payload), encoding='utf-8')
    before = counts.read_bytes()
    probe_before = probe.completed
    with tempfile.TemporaryFile(dir=root) as output:
        with process([str(args.driver), str(args.native_root), str(input_path), str(args.gui)],
                     env=environment, stdout=output, stderr=subprocess.DEVNULL) as child:
            if args.interactive:
                print(f'Complete portal then gateway using browser_accounts/password in private {input_path}.', file=sys.stderr)
            else:
                for index, account in enumerate(accounts):
                    submit_form(child, counts, before.count(b'S') + index + 1, probe, probe_before + index + 1,
                                environment, account, payload['password'], evidence / f'round-{index + 1}.png')
            child.wait(timeout=120)
            if child.returncode:
                raise Failure('native_browser_authentication_failed')
        output.seek(0)
        raw = output.read(65537)
        if len(raw) > 65536 or payload['password'].encode() in raw or b'FAKE_username_' in raw:
            raise Failure('native_browser_output_privacy_failed')
        events = [json.loads(line) for line in raw.splitlines()]
    completion = events[-1] if events else {}
    if completion.get('event') != 'authenticated' or completion.get('confirmed') != 2 or completion.get('phases') != ['portal', 'gateway']:
        raise Failure('independent_native_saml_rounds_missing')
    observed = counts.read_bytes()[len(before):]
    if observed.count(b'S') != 2 or observed.count(b'C') != 2 or observed.count(b'K') != 2 or b'W' in observed:
        raise Failure('native_saml_cookie_field_or_password_fallback_failed')
    if probe.completed - probe_before < 2 or probe.exposed:
        raise Failure('unrelated_origin_isolation_not_verified')
    return {'confirmed_rounds': 2, 'cookie_field_submissions': 2, 'password_fallbacks': 0,
            'unrelated_origin_ipc': False, 'native_handoff_account_checked': True}


def drive_security(args, root, config, counts, environment):
    cases = {}
    for name, mode, expected, cancel in [
            ('wrong_origin', 'wrong_origin', 'invalid_input', False),
            ('wrong_transaction', 'wrong_transaction', 'conflict', False),
            ('secret_error', 'secret_error', 'runtime_failure', False),
            ('truncated_frame', 'drop_mid_frame', 'protocol_violation', False),
            ('timeout', 'hold', 'authentication_required', False),
            ('cancel', 'hold', 'cancelled', True)]:
        payload = {'profile': config, 'password': 'fixture-only-password',
                   'expected_error': expected, 'cancel_at_waiting': cancel, 'browser_timeout_seconds': 3}
        input_path = root / 'adversarial-input.json'
        input_path.write_text(json.dumps(payload), encoding='utf-8')
        before = len(counts.read_bytes())
        with tempfile.TemporaryFile(dir=root) as output:
            with process([str(args.driver), str(args.native_root), str(input_path), str(args.peer)],
                         env=dict(environment, OCVPN_BROWSER_ATTACK=mode),
                         stdout=output, stderr=subprocess.DEVNULL) as child:
                child.wait(timeout=30)
                if child.returncode:
                    raise Failure('browser_security_case_failed_' + name)
            output.seek(0)
            raw = output.read(65537)
            if len(raw) > 65536 or b'fixture-secret-marker' in raw or b'fixture-only-password' in raw:
                raise Failure('secret_bearing_browser_error_escaped')
            events = [json.loads(line) for line in raw.splitlines()]
        terminal = events[-1] if events else {}
        if terminal.get('event') != 'cancelled' and not (
                terminal.get('event') == 'failed' and terminal.get('code') == expected):
            raise Failure('browser_security_wrong_terminal_state_' + name)
        if any(marker in counts.read_bytes()[before:] for marker in [b'P', b'G', b'C']):
            raise Failure('rejected_browser_peer_submitted_authentication_' + name)
        cases[name] = {'rejected_without_credential_submission': True, 'secret_error_exported': False}
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--gui', type=Path, required=True)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--interactive', action='store_true')
    args = parser.parse_args()
    # Do not resolve the venv Python symlink: that discards its environment.
    for name in ['native_root', 'driver', 'gui', 'peer', 'python', 'evidence']:
        setattr(args, name, getattr(args, name).absolute())
    previous = os.umask(0o077)
    try:
        evidence = args.evidence / str(uuid.uuid4())
        evidence.mkdir(parents=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix='ocvpn-browser-') as temporary, display_environment(args.interactive) as environment:
            root = Path(temporary)
            ca = certificates(root)
            counts = root / 'counts'
            environment.update(OCVPN_CONFIG_DIR=str(root / 'config'), XDG_DATA_HOME=str(root / 'data'))
            with isolation_probe(root) as (probe_url, probe):
                server_environment = dict(os.environ, OCVPN_FIXTURE_COUNTS_FILE=str(counts), OCVPN_FIXTURE_BROWSER_PROBE=probe_url)
                port = fresh_port('127.0.0.1')
                context = ssl.create_default_context(cafile=ca)
                with process([str(args.python), str(Path(__file__).with_name('run.py')), 'gp', '127.0.0.1', str(port),
                              str(root / 'server.pem'), str(root / 'server.key')], env=server_environment,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as server:
                    ready(server, '127.0.0.1', port, context, 'gp')
                    config = profile('gp', '127.0.0.1', port, ca)
                    config.update(username='browser-lab-user', browser_mode='embedded')
                    cases = {}
                    for name, accounts in [('same_account', ['browser-lab-user', 'browser-lab-user']),
                                           ('different_accounts', ['browser-lab-user', 'gateway-lab-user'])]:
                        if request('127.0.0.1', port, context, '/CONFIGURE', {'portal_saml': 'prelogin-cookie',
                                   'gateway_saml': 'prelogin-cookie', 'saml_comments_only': '1', 'saml_needs_js': '1'}) != 201:
                            raise Failure('saml_fixture_configuration_failed')
                        case_evidence = evidence / name
                        case_evidence.mkdir(mode=0o700)
                        cases[name] = drive(args, root, config, counts, probe, environment, accounts, case_evidence)
                    cases['adversarial_peer'] = drive_security(args, root, config, counts, environment)
        result = {'schema_version': 1, 'passed': True, 'platform': sys.platform,
                  'coverage': 'native_browser_authentication_and_origin_isolation_not_tunneling',
                  'cases': cases, 'evidence': str(evidence)}
        (evidence / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
    finally:
        os.umask(previous)


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps({'schema_version': 1, 'passed': False,
                          'error': str(error) if isinstance(error, Failure) else type(error).__name__}))
        sys.exit(1)
