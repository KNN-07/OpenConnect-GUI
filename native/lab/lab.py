#!/usr/bin/env python3
"""Disposable native VPN lab. Never runs network commands on the host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / 'target/ocvpn-lab'

def run(args, **kw):
    return subprocess.run([str(x) for x in args], check=True, **kw)

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)

def owned():
    data = json.loads((STATE / 'owner.json').read_text())
    inspect = json.loads(subprocess.check_output(['docker', 'inspect', data['container']]))[0]
    if inspect['Config']['Labels'].get('org.openconnectgui.lab') != data['token']:
        raise RuntimeError('Container ownership mismatch; refusing operation')
    return data

def native(args):
    if os.environ.get('OCVPN_LAB_ISOLATED_VM') != 'yes':
        raise RuntimeError('Native macOS/Windows lab requires a disposable isolated VM: set OCVPN_LAB_ISOLATED_VM=yes only there')
    server, ca = os.environ.get('OCVPN_LAB_SERVER'), os.environ.get('OCVPN_LAB_CA')
    if not server or not ca or not Path(ca).is_file():
        raise RuntimeError('Supply OCVPN_LAB_SERVER and existing OCVPN_LAB_CA from the isolated dual-stack Linux ocserv lab')
    if args.action == 'down':
        run(['ocvpn', 'disconnect'])
        return
    if args.action == 'up':
        STATE.mkdir(parents=True, exist_ok=True)
        save(STATE / 'native-profile.json', {'username':'lab', 'ca_file':str(Path(ca).resolve())})
        run(['ocvpn','profile','add','--name','lab','--server',server,'--protocol','anyconnect','--file',STATE / 'native-profile.json'])
        return
    # Native proof uses the same observable CLI and network scenario contract, not a cross-compile.
    run([sys.executable, ROOT / 'native/lab/native_verify.py', '--profile', args.profile])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['up','down','verify','exec','gui','screenshot','matrix'])
    parser.add_argument('--target', default='host')
    parser.add_argument('--profile', default='lab')
    args, args_command = parser.parse_known_args()
    args.command = args_command
    if args.command and args.action != 'exec':
        parser.error('unexpected arguments: ' + ' '.join(args.command))
    os.umask(0o077)
    if args.action == 'matrix':
        STATE.mkdir(parents=True, exist_ok=True)
        matrix = STATE / 'vendor-matrix.json'
        if matrix.exists():
            raise RuntimeError('Refusing to replace recorded vendor evidence')
        outcomes = ['authentication', 'tunnel', 'ipv4', 'ipv6', 'dns', 'reconnect']
        save(matrix, {'schema_version':1, 'rows':[{
            'protocol':p, 'os':o, 'status':'unverified',
            'authorization_reference':None, 'appliance_version':None,
            'authentication_type':None,
            'evidence':{key:'unverified' for key in outcomes},
            'limitations':['No authorized appliance verification recorded.'],
        } for p in ['anyconnect','nc','pulse','gp','f5','fortinet','array']
          for o in ['linux','macos-intel','macos-arm64','windows']]})
        return
    if platform.system() != 'Linux':
        native(args)
        return
    if args.action == 'down':
        if not (STATE / 'owner.json').exists():
            return
        data = owned()
        run(['docker','rm','--force',data['container']], stdout=subprocess.DEVNULL)
        (STATE / 'owner.json').unlink()
        print('Owned container and namespaces removed; private lab files/evidence retained.')
        return
    if args.action == 'up':
        if (STATE / 'owner.json').exists():
            raise RuntimeError('Lab already tracked; run lab down before recreating it')
        STATE.mkdir(parents=True, exist_ok=True)
        STATE.chmod(0o700)
        target = args.target
        if target == 'host':
            target = 'x86_64-unknown-linux-gnu'
        if target != 'x86_64-unknown-linux-gnu' or platform.machine() != 'x86_64':
            raise RuntimeError('Linux lab requires the matching x86_64 native runner')
        binaries = Path(os.environ.get('OCVPN_LAB_BIN_DIR', ROOT / 'target' / target / 'release')).resolve()
        stage = ROOT / 'target/native' / target / 'stage/ocvpn-native'
        names = ['ocvpn','ocvpn-gui','ocvpn-auth-callback','ocvpnd','ocvpn-net','ocvpn-installer']
        for path in [*(binaries / n for n in names), stage / 'native-manifest.json']:
            if not path.exists():
                raise RuntimeError(f'Missing native build input {path}; build first or set OCVPN_LAB_BIN_DIR to matching native binaries')
        lock = STATE / 'image-lock.json'
        inputs = {name:hashlib.sha256((ROOT/'native/lab'/name).read_bytes()).hexdigest() for name in ['Dockerfile','runtime.py','verify_keyring.py']}
        if lock.exists():
            locked = json.loads(lock.read_text())
            if locked.get('inputs') != inputs:
                raise RuntimeError('Lab recipe changed; preserve evidence and remove target/ocvpn-lab/image-lock.json explicitly to resolve a new runtime image')
            image = locked['image']
            run(['docker','image','inspect',image], stdout=subprocess.DEVNULL)
        else:
            base = os.environ.get('OCVPN_LAB_BASE_IMAGE', 'ubuntu:26.04')
            run(['docker','pull',base])
            base = json.loads(subprocess.check_output(['docker','image','inspect',base]))[0]['RepoDigests'][0]
            run(['docker','build','--build-arg',f'BASE={base}','--tag','ocvpn-lab-runtime',ROOT / 'native/lab'])
            image = json.loads(subprocess.check_output(['docker','image','inspect','ocvpn-lab-runtime']))[0]['Id']
            save(lock, {'base':base,'image':image,'inputs':inputs})
        token = uuid.uuid4().hex
        name = 'ocvpn-lab-' + token[:12]
        run(['docker','create','--name',name,'--label',f'org.openconnectgui.lab={token}','--privileged','--network','none','--hostname','ocvpn-lab',image], stdout=subprocess.DEVNULL)
        save(STATE / 'owner.json', {'container':name,'token':token})
        try:
            inspection = json.loads(subprocess.check_output(['docker','inspect',name]))[0]
            if inspection['HostConfig']['NetworkMode'] != 'none' or inspection['HostConfig'].get('Binds') or inspection.get('Mounts'):
                raise RuntimeError('Lab requires its own network namespace and no host mounts')
            for n in names:
                dest = '/usr/bin/' if n in names[:3] else '/usr/libexec/openconnect-gui/'
                run(['docker','cp',binaries/n,f'{name}:{dest}{n}'])
            run(['docker','cp',str(stage),f'{name}:/usr/lib/openconnect-gui'])
            run(['docker','cp',ROOT/'packaging/common/vpnc-script',f'{name}:/usr/libexec/openconnect-gui/vpnc-script'])
            run(['docker','start',name], stdout=subprocess.DEVNULL)
            run(['docker','exec',name,'python3','/opt/lab/runtime.py','ready'])
            run(['docker','cp',f'{name}:/lab-packages.txt',STATE/'runtime-packages.txt'])
            run(['docker','cp',f'{name}:/home/lab/password',STATE/'password'])
            (STATE/'password').chmod(0o600)
        except BaseException:
            logs = subprocess.run(['docker','logs',name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (STATE/'startup.log').write_bytes(logs.stdout + logs.stderr)
            for component in ['ocserv','daemon','dns','http4','http6','display','window-manager']:
                destination = STATE / f'startup-{component}.log'
                subprocess.run(['docker','cp',f'{name}:/opt/lab/{component}.log',destination], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if destination.exists():
                    destination.chmod(0o600)
            print('Private startup diagnostics retained in target/ocvpn-lab/startup*.log', file=sys.stderr)
            run(['docker','rm','--force',name], stdout=subprocess.DEVNULL)
            (STATE/'owner.json').unlink()
            raise
        print('Lab ready. Password is private target/ocvpn-lab/password, never printed. CLI/TUI: python3 native/lab/lab.py exec -- ocvpn tui; GUI: python3 native/lab/lab.py gui; screenshot: python3 native/lab/lab.py screenshot')
        return
    data = owned()
    name = data['container']
    if args.action == 'verify':
        try:
            run(['docker','exec',name,'python3','/opt/lab/runtime.py','verify','--profile',args.profile])
        finally:
            run(['docker','cp',f'{name}:/evidence/.',STATE])
    elif args.action == 'exec':
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        if not command:
            raise RuntimeError('Supply an installed command after --')
        run(['docker','exec','-it','--user','lab','--env','HOME=/home/lab','--env','DISPLAY=:99',name,*command])
    elif args.action == 'gui':
        run(['docker','exec','--detach','--user','lab','--env','HOME=/home/lab','--env','DISPLAY=:99',name,'dbus-run-session','ocvpn-gui'])
    elif args.action == 'screenshot':
        run(['docker','exec','--user','lab','--env','DISPLAY=:99',name,'xwd','-root','-silent','-out','/home/lab/screenshot.xwd'])
        run(['docker','cp',f'{name}:/home/lab/screenshot.xwd',STATE/'screenshot.xwd'])

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'lab: {error}', file=sys.stderr)
        sys.exit(1)
