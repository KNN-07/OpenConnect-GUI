#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Execute unmodified, signed upstream auth fixtures without debug servers or payload logs."""
import contextlib
import hashlib
import html
import ipaddress
import os
from pathlib import Path
import sys
import tarfile
import urllib.parse

FIXTURES = {
    'anyconnect': 'fake-cisco-server.py', 'nc': 'fake-juniper-server.py',
    'pulse': 'fake-pulse-server.py', 'gp': 'fake-gp-server.py',
    'f5': 'fake-f5-server.py', 'fortinet': 'fake-fortinet-server.py',
}
ARCHIVE_SHA256 = '5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58'

def main():
    if len(sys.argv) < 5 or sys.argv[1] not in FIXTURES:
        raise ValueError('Expected protocol, loopback host, port and fixture arguments')
    if not ipaddress.ip_address(sys.argv[2]).is_loopback:
        raise ValueError('Fixtures are restricted to loopback')
    if not 1024 <= int(sys.argv[3]) <= 65535:
        raise ValueError('Fixture port must be unprivileged')
    script = FIXTURES[sys.argv[1]]
    archive = Path(__file__).resolve().parents[1] / 'vendor/openconnect-9.21.tar.gz'
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != ARCHIVE_SHA256:
            raise ValueError('Pinned fixture archive digest mismatch')
    with tarfile.open(archive) as source:
        member = source.getmember('openconnect-9.21/tests/' + script)
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError('Invalid pinned fixture member')
        code = source.extractfile(member).read()
    # Keep upstream protocol/auth implementation unchanged. Disable only Flask's
    # development reloader/debugger; they are not authentication behavior.
    if sys.argv[1] != 'pulse':
        import flask
        run = flask.Flask.run
        def isolated_run(self, *args, **kwargs):
            kwargs.update(debug=False, use_debugger=False, use_reloader=False)
            counts_path = os.environ.get('OCVPN_FIXTURE_COUNTS_FILE')
            if counts_path:
                # Observe only fixed endpoint counts, never bodies, headers or cookies.
                counts = os.fdopen(os.open(counts_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb', buffering=0)
                @self.before_request
                def count_request():
                    marker = {'/global-protect/getconfig.esp': b'P', '/ssl-vpn/login.esp': b'G',
                              '/ANOTHER-HOST/SAML-ENDPOINT': b'S', '/SAML20/SP/ACS': b'C'}.get(flask.request.path)
                    if marker:
                        counts.write(marker)
                        if marker in (b'P', b'G'):
                            # Field identity only: a SAML credential must not be
                            # mistaken for an ordinary password by the native flow.
                            if flask.request.form.get('prelogin-cookie'):
                                counts.write(b'K')
                            elif flask.request.form.get('portal-userauthcookie'):
                                counts.write(b'U')
                            elif flask.request.form.get('passwd'):
                                counts.write(b'W')
            probe = os.environ.get('OCVPN_FIXTURE_BROWSER_PROBE')
            if probe:
                parsed = urllib.parse.urlsplit(probe)
                if parsed.scheme != 'https' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password or not parsed.port:
                    raise ValueError('Browser isolation probe must use loopback HTTPS')
                @self.after_request
                def browser_probe(response):
                    # Optional security probe only; upstream authentication and
                    # its JavaScript-dependent form/completion remain unchanged.
                    if flask.request.path == '/ANOTHER-HOST/SAML-ENDPOINT' and response.status_code == 200:
                        response.set_data(response.get_data() + ('<iframe title="Unrelated origin isolation probe" src="' +
                            html.escape(probe, quote=True) + '"></iframe>').encode('utf-8'))
                    return response
            return run(self, *args, **kwargs)
        flask.Flask.run = isolated_run
    sys.argv = [script, *sys.argv[2:]]
    with open('/dev/null' if sys.platform != 'win32' else 'NUL', 'w') as quiet:
        with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
            exec(compile(code, script, 'exec'), {'__name__': '__main__', '__file__': script})

if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        # Upstream exception messages may embed request bodies or credentials.
        print(f'Authentication fixture stopped ({type(error).__name__}); check its dependencies and loopback port.', file=sys.stderr)
        sys.exit(1)
