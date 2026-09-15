#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise native Secret Service credentials only inside the owned VPN lab."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time

if os.getuid() != 1000 or Path('/proc/1/cmdline').read_bytes().split(b'\0')[:3] != [b'python3', b'/opt/lab/runtime.py', b'supervise']:
    raise SystemExit('Run this probe as lab through the isolated VPN laboratory')
os.umask(0o077)
home = Path(tempfile.mkdtemp(prefix='quiet-proof-', dir='/home/lab'))
for name in ['data', 'config', 'cache', 'control']:
    (home / name).mkdir(mode=0o700)
os.environ.update(HOME=str(home), XDG_DATA_HOME=str(home / 'data'), XDG_CONFIG_HOME=str(home / 'config'), XDG_CACHE_HOME=str(home / 'cache'), GNOME_KEYRING_CONTROL=str(home / 'control'))
password = Path('/home/lab/password').read_bytes()


def cli(*args, password_input=False, expected=None):
    inputs = {'input': password} if password_input else {'stdin': subprocess.DEVNULL}
    result = subprocess.run(['ocvpn', '--json', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=70, **inputs)
    value = json.loads(result.stdout)
    code = value.get('error', {}).get('code')
    if expected:
        if result.returncode != 3 or code != expected:
            raise RuntimeError('Locked credentials did not require explicit authentication')
        return value
    if result.returncode:
        # Never include native authentication output in evidence.
        raise RuntimeError('CLI operation failed: ' + (code or 'unknown'))
    return value['data']


def bus(method, *args):
    result = subprocess.run(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets', '--object-path', '/org/freedesktop/secrets', '--method', 'org.freedesktop.Secret.Service.' + method, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
    return result.stdout.decode()


with tempfile.TemporaryFile() as daemon_output, tempfile.TemporaryFile() as monitor_output, tempfile.TemporaryFile() as monitor_errors:
    # One owned foreground process receives the nonempty master secret on stdin.
    # A second --unlock process can initialize a different daemon/collection.
    daemon = subprocess.Popen(['gnome-keyring-daemon', '--unlock', '--foreground', '--components=pkcs11,secrets', '--control-directory', str(home / 'control')], stdin=subprocess.PIPE, stdout=daemon_output, stderr=daemon_output)
    monitor = None
    try:
        daemon.stdin.write(secrets.token_urlsafe(32).encode())
        daemon.stdin.close()
        for _ in range(100):
            if daemon.poll() is not None:
                raise RuntimeError('Owned keyring daemon exited before readiness')
            if (home / 'control/control').exists():
                break
            time.sleep(.05)
        else:
            raise RuntimeError('Owned keyring control socket did not become ready')
        alias = bus('ReadAlias', 'default')
        collection = re.fullmatch(r"\((?:objectpath )?'(/org/freedesktop/secrets/collection/[A-Za-z0-9_]+)',\)\s*", alias)
        if not collection:
            raise RuntimeError('Unlocked persistent default collection is unavailable')
        collection = collection.group(1)
        monitor = subprocess.Popen(['stdbuf', '-oL', 'dbus-monitor', '--session', "type='method_call',interface='org.freedesktop.Secret.Prompt',member='Prompt'", "type='method_call',interface='org.freedesktop.Secret.Service',member='OpenSession'"], stdout=monitor_output, stderr=monitor_errors)
        for _ in range(100):
            if monitor.poll() is not None:
                raise RuntimeError('Private bus monitor exited before readiness')
            if b'member=NameLost' in os.pread(monitor_output.fileno(), 8192, 0):
                break
            time.sleep(.05)
        else:
            raise RuntimeError('Private bus monitoring did not become ready')
        advanced = home / 'profile.json'
        advanced.write_text(json.dumps({'username': 'lab', 'ca_file': '/home/lab/ca.pem', 'remember_password': True, 'reconnect_timeout_secs': 30}))
        cli('profile', 'add', '--name', 'quiet', '--server', 'https://192.0.2.1', '--protocol', 'anyconnect', '--file', str(advanced))
        if cli('connect', 'quiet', '--password-stdin', '--non-interactive', password_input=True)['state'] != 'connected':
            raise RuntimeError('First credential creation did not complete native connection')
        cli('disconnect')
        if cli('connect', 'quiet', '--non-interactive')['state'] != 'connected':
            raise RuntimeError('Quiet stored credential read did not complete native connection')
        cli('disconnect')
        locked = bus('Lock', "['" + collection + "']")
        if collection not in locked:
            raise RuntimeError('The persistent collection did not lock')
        cli('connect', 'quiet', '--non-interactive', expected='authentication_required')
        if cli('status')['state'] not in ['disconnected', 'failed', 'authentication_required']:
            raise RuntimeError('Locked keyring left an active tunnel')
        monitor.terminate()
        monitor.wait(timeout=10)
        monitor_output.seek(0)
        messages = monitor_output.read().decode(errors='replace')
        if 'member=Prompt' in messages or 'string "plain"' in messages or 'dh-ietf1024-sha256-aes128-cbc-pkcs7' not in messages:
            raise RuntimeError('Quiet credential operations prompted or lacked observed encrypted sessions')
        print(json.dumps({'schema_version': 1, 'passed': True, 'unlocked_first_creation': True, 'stored_read_connected': True, 'locked_read_failed_closed': True, 'locked_exit': 3, 'locked_error': 'authentication_required', 'prompt_calls': 0, 'encrypted_open_session_observed': True}))
    finally:
        try:
            cli('disconnect')
        finally:
            if monitor and monitor.poll() is None:
                monitor.terminate()
                monitor.wait(timeout=10)
            daemon.terminate()
            daemon.wait(timeout=10)
            shutil.rmtree(home)
