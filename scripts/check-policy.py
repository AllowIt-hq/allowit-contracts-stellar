#!/usr/bin/env python3
"""Check or regenerate the identity of the literal portable Rust source bundle."""
import argparse, hashlib, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(); p.add_argument('--write', action='store_true'); p.add_argument('--peer', type=Path)
args = p.parse_args()
h = hashlib.sha256(b'allowit-policy-source-v1\0')
for name in ['policy.rs', 'policy_api.rs']:
    data = (ROOT/'policy'/name).read_bytes()
    h.update(name.encode()+b'\0'+len(data).to_bytes(8,'little')+data)
    if args.peer: assert data == (args.peer/'policy'/name).read_bytes(), f'Cross-network drift: {name}'
value = 'pub const SOURCE_HASH: [u8; 32] = [' + ', '.join(str(b) for b in h.digest()) + '];\n'
path = ROOT/'policy/source_hash.rs'
if args.write: path.write_text(value)
else:
    actual = bytes(int(b) for b in re.search(r'=\s*\[([^]]+)\]',path.read_text()).group(1).split(',') if b.strip())
    assert actual == h.digest(), 'Stale source hash: run python3 scripts/check-policy.py --write'
print(h.hexdigest())
