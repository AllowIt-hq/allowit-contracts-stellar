#!/usr/bin/env python3
"""Write a public source/artifact manifest after a native build; contains no keys."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=subprocess.check_output(['python3',str(ROOT/'scripts/check-policy.py')],text=True).strip()
stellar=(ROOT/'crates/factory').exists()
files=list((ROOT/('target/wasm32v1-none/release' if stellar else 'target/deploy')).glob('allowit_*'+('.wasm' if stellar else '.so')))
assert files,'Build native contracts first'
manifest={'schema':1,'source_bundle':source,'git_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'network':None,'deployments':[],'artifacts':[{'name':f.name,'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(files)]}
(ROOT/'artifacts').mkdir(exist_ok=True)
(ROOT/'artifacts/manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
