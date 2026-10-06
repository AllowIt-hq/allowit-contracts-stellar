#!/usr/bin/env python3
"""Write a public source/artifact manifest after a native build; contains no keys."""
import argparse,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,help='Write the manifest to this explicit path; otherwise print to stdout only')
args=parser.parse_args()
source=subprocess.check_output(['python3',str(ROOT/'scripts/check-policy.py')],text=True).strip()
stellar=(ROOT/'crates/factory').exists()
files=list((ROOT/('target/wasm32v1-none/release' if stellar else 'target/deploy')).glob('allowit_*'+('.wasm' if stellar else '.so')))
assert files,'Build native contracts first'
manifest={'schema':1,'source_bundle':source,'git_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'network':None,'deployments':[],'artifacts':[{'name':f.name,'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(files)]}
payload=json.dumps(manifest,indent=2)+'\n'
if args.output:
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(payload)
else:
    print(payload,end='')
