#!/usr/bin/env python3
"""Native VM-only packet proof. Server control is an explicit authorized argv adapter.
OCVPN_LAB_SERVER_CONTROL_JSON is an argv JSON array; its final argument is split,
full, stop, or start. It must manage only the isolated ocserv server. Password is
read from OCVPN_LAB_PASSWORD_FILE; it never enters argv, environment or evidence.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]

def command(argv):
    return subprocess.check_output(argv,text=True).strip()

def cli(*args,password=False):
    value=Path(os.environ['OCVPN_LAB_PASSWORD_FILE']).read_bytes() if password else None
    result=subprocess.run(['ocvpn','--json',*args],input=value,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    if result.returncode:
        raise RuntimeError('Native CLI operation failed: '+args[0]+'; exit '+str(result.returncode))
    return json.loads(result.stdout)['data']

def network():
    if platform.system()=='Darwin':
        return {'routes4':command(['/usr/sbin/netstat','-rn','-f','inet']), 'routes6':command(['/usr/sbin/netstat','-rn','-f','inet6']), 'dns':command(['/usr/sbin/scutil','--dns']), 'interfaces':command(['/sbin/ifconfig'])}
    if platform.system()=='Windows':
        # Constant code, never server-supplied strings. Native cmdlets enumerate actual OS state.
        script='[ordered]@{routes=@(Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric); addresses=@(Get-NetIPAddress | Select-Object IPAddress,PrefixLength,InterfaceIndex); dns=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses); nrpt=@(Get-DnsClientNrptRule | Select-Object Name,Namespace,NameServers,Comment)} | ConvertTo-Json -Depth 8'
        return json.loads(command(['powershell.exe','-NoProfile','-NonInteractive','-Command',script]))
    raise RuntimeError('Native VM verifier is for macOS/Windows only')

def fetch(address):
    host='['+address+']' if ':' in address else address
    request=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with request.open('http://'+host+':8080/',timeout=5) as response:
        return response.read(64)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',default='lab')
    args=parser.parse_args()
    if os.environ.get('OCVPN_LAB_ISOLATED_VM')!='yes':
        raise RuntimeError('Refusing native networking outside explicitly isolated disposable VM')
    password=Path(os.environ['OCVPN_LAB_PASSWORD_FILE'])
    if os.name!='nt' and password.stat().st_mode & 0o077:
        raise RuntimeError('Password input file must be owner-only')
    control=json.loads(os.environ['OCVPN_LAB_SERVER_CONTROL_JSON'])
    if not isinstance(control,list) or not control or not all(isinstance(x,str) for x in control):
        raise RuntimeError('Server control must be an explicit nonempty argv JSON array')
    # Explicit lab addresses permit a remote isolated deployment without invented endpoints.
    addresses=[str(ipaddress.IPv4Address(os.environ['OCVPN_LAB_INTERNAL_IPV4'])),str(ipaddress.IPv6Address(os.environ['OCVPN_LAB_INTERNAL_IPV6']))]
    evidence={'schema_version':1,'platform':platform.platform(),'kind':'native-isolated-ocserv','vendor_interoperability':'unverified','scenarios':[],'passed':False,'manual_requirements':['GUI/TUI shared-state scenarios','worker crash and daemon restart recovery preserving unrelated routes','suspend/resume','deny elevation and keyring access','route exclusion/transport bypass review against before/connected/after evidence']}
    try:
        for mode in ['split','full']:
            subprocess.run([*control,mode],check=True)
            before=network()
            for address in addresses:
                try:
                    fetch(address)
                except (OSError,ValueError):
                    continue
                raise RuntimeError('Internal lab target is reachable without VPN')
            cli('connect',args.profile,'--password-stdin','--non-interactive',password=True)
            state=cli('status')
            if state['state']!='connected' or not state['session_id'] or not state['network']:
                raise RuntimeError('Native service did not establish an observed tunnel')
            row={'mode':mode,'before':before,'connected':network(),'snapshot':state}
            evidence['scenarios'].append(row)
            for address in addresses:
                if fetch(address)!=b'ocvpn-lab-ok':
                    raise RuntimeError('Internal packet payload mismatch')
            resolved={info[4][0] for info in socket.getaddrinfo('inside.ocvpn.test',8080)}
            if not set(addresses).issubset(resolved):
                raise RuntimeError('System VPN DNS failed dual-stack resolution')
            first=cli('status')['traffic']
            for _ in range(50):
                fetch(addresses[0])
            time.sleep(3)
            last=cli('status')['traffic']
            if last['rx_bytes']<=first['rx_bytes'] or last['tx_bytes']<=first['tx_bytes']:
                raise RuntimeError('Native counters did not increase')
            row['traffic']={'before':first,'after':last}
            row['resolved']=sorted(resolved)
            cli('disconnect')
            row['after']=network()
            # Native dumps contain incidental timers. Preserve evidence and require
            # exact stable Windows state; macOS must additionally be reviewed natively.
            if platform.system()=='Windows' and row['before']!=row['after']:
                raise RuntimeError('Windows routes/address/DNS state was not exactly restored')
            row['packet_proof_passed']=True
        evidence['passed']=True
        evidence['acceptance_complete']=False
    finally:
        try:
            cli('disconnect')
        except Exception:
            evidence['cleanup_error']='Disconnect failed; inspect service repair in this VM before disposal'
        output=ROOT/'target/ocvpn-lab/native-tunnel.json'
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(evidence,indent=2)+'\n')

if __name__=='__main__':
    main()
