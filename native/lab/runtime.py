#!/usr/bin/env python3
"""Runs only inside the owned, network-none privileged container."""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time

HOME = Path('/home/lab')
PIDS = Path('/opt/lab/pids.json')
SERVER4 = '192.0.2.1'
SERVER6 = 'fd00:0:1::1'
INTERNAL4 = '10.77.0.1'
INTERNAL6 = 'fd00:77::1'

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def capture(args):
    return subprocess.check_output(args, text=True).strip()

def ns(*args):
    return ['ip','netns','exec','server',*args]

def cli(*args, password=False):
    command = ['runuser','-u','lab','--','env','HOME=/home/lab','ocvpn','--json',*args]
    # Authentication stderr/stdout are never persisted in evidence.
    result = subprocess.run(command, input=(HOME/'password').read_bytes() if password else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if result.returncode:
        raise RuntimeError(f'ocvpn {args[0]} failed with exit {result.returncode}; inspect interactively (auth output not recorded)')
    return json.loads(result.stdout)['data']

def snapshot():
    return cli('status')

def wait_state(states, timeout=35):
    deadline = time.monotonic()+timeout
    seen = []
    while time.monotonic()<deadline:
        try:
            state = snapshot()
            seen.append({'state':state['state'],'sequence':state['sequence']})
            if state['state'] in states:
                return state, seen
        except (RuntimeError, ValueError):
            pass
        time.sleep(.25)
    raise RuntimeError(f'Daemon did not reach {states}')

def net():
    def stable(items):
        for item in items:
            for key in ['valid_life_time','preferred_life_time','expires','cache','stats64','stats']:
                item.pop(key,None)
            for addr in item.get('addr_info',[]):
                addr.pop('valid_life_time',None)
                addr.pop('preferred_life_time',None)
        return sorted(items,key=lambda x:json.dumps(x,sort_keys=True))
    return {'routes4':stable(json.loads(capture(['ip','-j','-4','route','show','table','all']))),
            'routes6':stable(json.loads(capture(['ip','-j','-6','route','show','table','all']))),
            'addresses':stable(json.loads(capture(['ip','-j','address']))),
            'dns':Path('/etc/resolv.conf').read_text()}

def route(address):
    return json.loads(capture(['ip','-j','route','get',address]))[0]['dev']

def config(mode):
    routes = 'route = 10.77.0.0/16\nroute = fd00:77::/48\n' if mode=='split' else 'route = default\nroute = ::/0\n'
    Path('/opt/lab/ocserv.conf').write_text('''auth = "plain[passwd=/opt/lab/ocpasswd]"
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ocserv-lab.sock
server-cert = /opt/lab/server.pem
server-key = /opt/lab/server-key.pem
ca-cert = /home/lab/ca.pem
isolate-workers = false
max-clients = 4
max-same-clients = 2
keepalive = 5
dpd = 5
mobile-dpd = 5
try-mtu-discovery = false
cookie-timeout = 300
device = vpns
ipv4-network = 10.78.0.0
ipv4-netmask = 255.255.255.0
ipv6-network = fd00:78::/64
ipv6-subnet-prefix = 128
dns = 10.77.0.1
dns = fd00:77::1
default-domain = ocvpn.test
tunnel-all-dns = true
no-route = 198.51.100.0/24
no-route = fd00:99::/64
''' + routes)

def spawn(name,args):
    log = open('/opt/lab/'+name+'.log','ab')
    process = subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True)
    log.close()
    pids = json.loads(PIDS.read_text()) if PIDS.exists() else {}
    pids[name] = {'pid':process.pid,'start':Path(f'/proc/{process.pid}/stat').read_text().split()[21]}
    PIDS.write_text(json.dumps(pids))
    return process

def stop(name, sig=signal.SIGTERM):
    record = json.loads(PIDS.read_text())[name]
    proc = Path(f"/proc/{record['pid']}/stat")
    if proc.exists() and proc.read_text().split()[21] == record['start']:
        os.killpg(record['pid'],sig)
        for _ in range(50):
            if not proc.exists() or proc.read_text().split()[2]=='Z':
                break
            time.sleep(.1)
        else:
            os.killpg(record['pid'],signal.SIGKILL)

def start_server(mode):
    config(mode)
    spawn('ocserv',ns('ocserv','--foreground','--config=/opt/lab/ocserv.conf'))
    time.sleep(2)

def setup():
    links = json.loads(capture(['ip','-j','-d','link']))
    fallback_kinds = {'ipip','sit','gre','gretap','erspan','ip6tnl','ip6gre','ip6gretap','ip6erspan','vti','vti6'}
    if not any(link.get('link_type') == 'loopback' for link in links) or any(
        link.get('link_type') != 'loopback' and ('UP' in link.get('flags', []) or link.get('linkinfo', {}).get('info_kind') not in fallback_kinds)
        for link in links
    ):
        raise RuntimeError('Expected isolated network-none namespace with only loopback and down kernel fallback devices')
    for p in ['/usr/bin/ocvpn','/usr/bin/ocvpn-gui','/usr/bin/ocvpn-auth-callback','/usr/libexec/openconnect-gui/ocvpnd','/usr/libexec/openconnect-gui/ocvpn-net','/usr/libexec/openconnect-gui/ocvpn-installer','/usr/libexec/openconnect-gui/vpnc-script']:
        os.chown(p,0,0)
        os.chmod(p,0o755)
    native = Path('/usr/lib/openconnect-gui')
    for path in [native, *native.rglob('*')]:
        metadata = path.lstat()
        os.chown(path, 0, 0, follow_symlinks=False)
        if path.is_symlink():
            if not path.resolve().is_relative_to(native):
                raise RuntimeError('Native runtime link escapes installed bundle')
        else:
            os.chmod(path, 0o755 if path.is_dir() or metadata.st_mode & 0o111 else 0o644)
    run(['ip','link','set','lo','up'])
    run(['ip','netns','add','server'])
    run(['ip','link','add','outside','type','veth','peer','name','server0'])
    run(['ip','link','set','server0','netns','server'])
    for command in [['ip','addr','add','192.0.2.2/24','dev','outside'],['ip','-6','addr','add','fd00:0:1::2/64','dev','outside','nodad'],['ip','link','set','outside','up'],ns('ip','link','set','lo','up'),ns('ip','addr','add','192.0.2.1/24','dev','server0'),ns('ip','-6','addr','add','fd00:0:1::1/64','dev','server0','nodad'),ns('ip','link','set','server0','up'),ns('ip','link','add','inside','type','dummy'),ns('ip','addr','add','10.77.0.1/16','dev','inside'),ns('ip','-6','addr','add','fd00:77::1/48','dev','inside','nodad'),ns('ip','link','set','inside','up'),['ip','route','add','default','via',SERVER4],['ip','-6','route','add','default','via',SERVER6]]:
        run(command)
    for binary, address in [('iptables',INTERNAL4),('ip6tables',INTERNAL6)]:
        run(ns(binary,'-A','INPUT','-i','server0','-d',address,'-j','DROP'))
    # A real resolver backend consumed by the installed vpnc lifecycle script.
    Path('/etc/resolvconf.conf').write_text('resolv_conf=/etc/resolv.conf\nname_servers="192.0.2.1"\n')
    run(['resolvconf','-u'])
    Path('/opt/lab/ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Disposable OCVPN lab CA\n[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n')
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-config','/opt/lab/ca.cnf','-keyout','/opt/lab/ca-key.pem','-out',str(HOME/'ca.pem')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=ocvpn-lab','-keyout','/opt/lab/server-key.pem','-out','/opt/lab/server.csr'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    Path('/opt/lab/server.ext').write_text('subjectAltName=IP:192.0.2.1,IP:fd00:0:1::1\nextendedKeyUsage=serverAuth\n')
    run(['openssl','x509','-req','-in','/opt/lab/server.csr','-CA',str(HOME/'ca.pem'),'-CAkey','/opt/lab/ca-key.pem','-CAcreateserial','-days','2','-extfile','/opt/lab/server.ext','-out','/opt/lab/server.pem'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    password=secrets.token_urlsafe(32)
    (HOME/'password').write_text(password+'\n')
    run(['ocpasswd','--passwd','/opt/lab/ocpasswd','lab'],input=(password+'\n'+password+'\n').encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for name in ['password','ca.pem']:
        os.chown(HOME/name,1000,1000)
        os.chmod(HOME/name,0o600)
    start_server('split')
    spawn('http4',ns('python3','/opt/lab/runtime.py','http4'))
    spawn('http6',ns('python3','/opt/lab/runtime.py','http6'))
    spawn('dns',ns('dnsmasq','--keep-in-foreground','--no-resolv','--no-hosts','--bind-interfaces','--interface=inside','--address=/inside.ocvpn.test/10.77.0.1','--address=/inside.ocvpn.test/fd00:77::1'))
    spawn('daemon',['/usr/libexec/openconnect-gui/ocvpnd','--foreground'])
    spawn('display',['runuser','-u','lab','--','Xvfb',':99','-screen','0','1080x720x24','-nolisten','tcp','-ac'])
    time.sleep(1)
    spawn('window-manager',['runuser','-u','lab','--','env','DISPLAY=:99','openbox'])
    wait_state(['disconnected'])
    advanced=HOME/'profile.json'
    advanced.write_text(json.dumps({'username':'lab','ca_file':str(HOME/'ca.pem'),'reconnect_timeout_secs':30}))
    os.chown(advanced,1000,1000)
    cli('profile','add','--name','lab','--server','https://192.0.2.1','--protocol','anyconnect','--file',str(advanced))
    Path('/opt/lab/ready').touch()

def fetch(address):
    url = 'http://'+('['+address+']' if ':' in address else address)+':8080/'
    return subprocess.run(['curl','--noproxy','*','--fail','--silent','--max-time','5',url],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)

def verify_streams(profile):
    before = net()
    watchers = []
    def records(output):
        data = os.pread(output.fileno(), 1024*1024, 0)
        if len(data) == 1024*1024:
            raise RuntimeError('Subscription evidence exceeded its bound')
        documents = [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith(b'\n')]
        if any('data' not in item and item.get('error',{}).get('code') != 'cancelled' for item in documents):
            raise RuntimeError('Observation consumer reported an unexpected error')
        return [item['data'] for item in documents if 'data' in item]
    try:
        cli('connect', profile, '--password-stdin', '--non-interactive', password=True)
        for name, arguments in [('status', ['status','--watch']), ('logs', ['logs','--follow'])]:
            output = open('/evidence/stream-'+name+'.jsonl', 'w+b')
            process = subprocess.Popen(['ocvpn','--json',*arguments], stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.DEVNULL, user=1000, group=1000,
                extra_groups=[], env={**os.environ,'HOME':str(HOME)}, start_new_session=True)
            watchers.append((name, process, output))
        deadline = time.monotonic()+15
        while any(os.fstat(output.fileno()).st_size == 0 for _, _, output in watchers):
            if time.monotonic() >= deadline or any(process.poll() is not None for _, process, _ in watchers):
                raise RuntimeError('Native observation consumers did not become ready')
            time.sleep(.05)
        cli('disconnect')
        deadline = time.monotonic()+10
        while not any(record.get('payload',{}).get('type') == 'snapshot'
                      and record['payload']['data']['state'] == 'disconnected'
                      for record in records(watchers[0][2])):
            if time.monotonic() >= deadline:
                raise RuntimeError('Status stream did not observe actual disconnect')
            time.sleep(.05)
        result = {'passed':True}
        for name, process, output in watchers:
            process.send_signal(signal.SIGINT)
            if process.wait(timeout=10) != 130:
                raise RuntimeError('Observation consumer did not interrupt cleanly')
            live = [record for record in records(output) if 'payload' in record]
            expected = 'snapshot' if name == 'status' else 'log'
            if not live or any(record['payload']['type'] != expected for record in live):
                raise RuntimeError(name+' subscription delivered the wrong event kind')
            result[name+'_events'] = len(live)
        if net() != before:
            raise RuntimeError('Subscription verification did not restore networking')
        return result
    finally:
        for _, process, output in watchers:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            output.close()

def verify(profile):
    evidence={'schema_version':1,'kind':'isolated-ocserv-packet-proof','vendor_interoperability':'unverified','scenarios':[],'passed':False}
    try:
        for mode in ['split','full']:
            cli('disconnect')
            stop('ocserv')
            start_server(mode)
            before=net()
            if fetch(INTERNAL4).returncode==0 or fetch(INTERNAL6).returncode==0:
                raise RuntimeError('Internal targets are reachable without VPN; isolation failed')
            cli('connect',profile,'--password-stdin','--non-interactive',password=True)
            connected,_=wait_state(['connected'])
            interface=connected['network']['interface']
            row={'mode':mode,'before':before,'connected':net(),'snapshot':connected}
            evidence['scenarios'].append(row)
            for address in [INTERNAL4,INTERNAL6]:
                response=fetch(address)
                if response.returncode or response.stdout!=b'ocvpn-lab-ok':
                    raise RuntimeError('VPN-only HTTP payload failed for '+address)
                if route(address)!=interface:
                    raise RuntimeError('Internal route does not use observed VPN interface')
            resolved={info[4][0] for info in socket.getaddrinfo('inside.ocvpn.test',8080)}
            if not {INTERNAL4,INTERNAL6}.issubset(resolved):
                raise RuntimeError('System VPN DNS did not resolve dual-stack internal target')
            row['resolved']=sorted(resolved)
            for address in [SERVER4,SERVER6,'198.51.100.1','fd00:99::1']:
                if route(address)!='outside':
                    raise RuntimeError('Transport/exclusion bypass route failed: '+address)
            for address in ['203.0.113.1','fd00:88::1']:
                if route(address)!=('outside' if mode=='split' else interface):
                    raise RuntimeError('Split/full route policy failed: '+address)
            first=snapshot()['traffic']
            for _ in range(50):
                if fetch(INTERNAL4).returncode:
                    raise RuntimeError('VPN transfer failed')
            time.sleep(3)
            last=snapshot()['traffic']
            if not (last['rx_bytes']>first['rx_bytes'] and last['tx_bytes']>first['tx_bytes']):
                raise RuntimeError('Real RX/TX counters did not increase')
            row['traffic']={'before':first,'after':last}
            cli('disconnect')
            wait_state(['disconnected'])
            row['after']=net()
            if row['after']!=before:
                raise RuntimeError('Disconnect did not exactly restore lab network state')
            row['passed']=True
        # A server outage must be observable; no timer synthesizes reconnect success.
        cli('connect',profile,'--password-stdin','--non-interactive',password=True)
        stop('ocserv',signal.SIGKILL)
        state,events=wait_state(['reconnecting','failed','authentication_required','disconnected'],45)
        start_server('full')
        end,more=wait_state(['connected','failed','authentication_required','disconnected'],45)
        if end['state']=='connected' and fetch(INTERNAL4).stdout!=b'ocvpn-lab-ok':
            raise RuntimeError('Reconnected state without packet transfer')
        evidence['outage']={'observations':events+more,'result':end['state']}
        cli('disconnect')
        for crash in ['worker','daemon']:
            baseline=net()
            run(['ip','route','add','203.0.113.17/32','dev','outside'])
            preserved=net()
            cli('connect',profile,'--password-stdin','--non-interactive',password=True)
            wait_state(['connected'])
            if crash=='worker':
                record = json.loads(PIDS.read_text())['daemon']
                daemon = record['pid']
                if Path(f'/proc/{daemon}/stat').read_text().split()[21] != record['start']:
                    raise RuntimeError('Owned daemon identity changed')
                # Tokio may spawn the worker from any runtime thread, not the
                # thread-group leader represented by /task/<daemon>/children.
                children = set()
                for task in Path(f'/proc/{daemon}/task').iterdir():
                    try:
                        children.update(map(int, (task/'children').read_text().split()))
                    except FileNotFoundError:
                        pass
                with contextlib.ExitStack() as descriptors:
                    workers = []
                    for pid in children:
                        try:
                            descriptor = os.pidfd_open(pid)
                            descriptors.callback(os.close, descriptor)
                            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
                            command = Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                            if int(fields[1]) == daemon and command == [b'/usr/libexec/openconnect-gui/ocvpnd', b'--worker']:
                                workers.append(descriptor)
                        except (ProcessLookupError, FileNotFoundError):
                            pass
                    if len(workers) != 1:
                        raise RuntimeError('Cannot uniquely identify owned daemon worker')
                    signal.pidfd_send_signal(workers[0], signal.SIGKILL)
                wait_state(['failed','authentication_required','disconnected'])
            else:
                stop('daemon',signal.SIGKILL)
                spawn('daemon',['/usr/libexec/openconnect-gui/ocvpnd','--foreground'])
                wait_state(['disconnected'])
            cli('disconnect')
            after=net()
            evidence[crash+'-recovery']={'before':preserved,'after':after,'passed':after==preserved}
            if after!=preserved:
                raise RuntimeError(crash+' recovery failed or changed unrelated route')
            run(['ip','route','del','203.0.113.17/32','dev','outside'])
            if net()!=baseline:
                raise RuntimeError('Recovery test teardown mismatch')
        evidence['subscription-streams']=verify_streams(profile)
        keyring_before=net()
        evidence['quiet-keyring']=json.loads(capture(['runuser','-u','lab','--','env','HOME=/home/lab','dbus-run-session','--','python3','/opt/lab/verify_keyring.py']))
        if not evidence['quiet-keyring'].get('passed') or net()!=keyring_before:
            raise RuntimeError('Quiet keyring verification failed or changed network state')
        evidence['passed']=True
    finally:
        try:
            cli('disconnect')
        except Exception:
            evidence['cleanup_error']='Disconnect failed; destroy owned lab container with lab down'
        Path('/evidence/tunnel.json').write_text(json.dumps(evidence,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('--profile',default='lab')
    args=parser.parse_args()
    os.umask(0o077)
    if args.action=='supervise':
        setup()
        while True:
            try:
                os.wait()
            except ChildProcessError:
                time.sleep(1)
    elif args.action=='ready':
        for _ in range(120):
            if Path('/opt/lab/ready').exists():
                return
            time.sleep(1)
        raise RuntimeError('Lab failed startup; docker logs and private /opt/lab/*.log contain diagnostics')
    elif args.action=='verify':
        verify(args.profile)
    elif args.action in ['http4','http6']:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length',str(len(b'ocvpn-lab-ok')))
                self.end_headers()
                self.wfile.write(b'ocvpn-lab-ok')
            def log_message(self,*args):
                pass
        class Server(http.server.HTTPServer):
            address_family=socket.AF_INET6 if args.action=='http6' else socket.AF_INET
        Server((INTERNAL6 if args.action=='http6' else INTERNAL4,8080),Handler).serve_forever()

if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print('lab runtime: '+str(error),file=sys.stderr)
        sys.exit(1)
