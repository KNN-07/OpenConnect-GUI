#!/usr/bin/env python3
"""Record authorized appliance observations separately from local fixture proof.
An evidence JSON must contain authentication, tunnel, ipv4, ipv6, dns, reconnect
fields each equal to passed, failed, or unverified. This command records operator
attestation; it does not authenticate to an appliance or infer interoperability.
Never put passwords, cookies, callback URLs, or private endpoints in evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--protocol',required=True,choices=['anyconnect','nc','pulse','gp','f5','fortinet','array'])
parser.add_argument('--os',required=True,choices=['linux','macos-intel','macos-arm64','windows'])
parser.add_argument('--authorization-reference',required=True)
parser.add_argument('--appliance-version',required=True)
parser.add_argument('--authentication-type',required=True)
parser.add_argument('--evidence',type=Path,required=True)
parser.add_argument('--limitation',action='append',default=[],help='Nonsecret known limitation; repeat for multiple limitations')
args=parser.parse_args()
for value in [args.authorization_reference,args.appliance_version,args.authentication_type,*args.limitation]:
    if not value.strip() or any(ord(c)<32 for c in value):
        parser.error('Attestation metadata must be nonempty printable text')
evidence=json.loads(args.evidence.read_text())
keys=['authentication','tunnel','ipv4','ipv6','dns','reconnect']
if set(evidence)!=set(keys) or any(evidence[k] not in ['passed','failed','unverified'] for k in keys):
    parser.error('Evidence must contain exactly the six documented outcome fields')
path=Path(__file__).resolve().parents[2]/'target/ocvpn-lab/vendor-matrix.json'
matrix=json.loads(path.read_text())
row=next(r for r in matrix['rows'] if r['protocol']==args.protocol and r['os']==args.os)
row.update(status='operator-attested',authorization_reference=args.authorization_reference,appliance_version=args.appliance_version,authentication_type=args.authentication_type,evidence=evidence,limitations=args.limitation,evidence_sha256=hashlib.sha256(args.evidence.read_bytes()).hexdigest())
path.write_text(json.dumps(matrix,indent=2)+'\n')
