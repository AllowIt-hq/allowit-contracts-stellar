#!/usr/bin/env python3
"""Check authored-source and argument-schema digests in generated policy modules."""
import ast
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)"
PAIRS = (
    ("policy.rs", "generated_policy.rs"),
    ("recipient-policy.rs", "generated_recipient_policy.rs"),
    ("financial-policy.rs", "test_generated_financial_policy.rs"),
    ("bool-policy.rs", "test_generated_bool_policy.rs"),
    ("xlm-policy.rs", "generated_xlm_policy.rs"),
    ("state-policy.rs", "generated_state_policy.rs"),
    ("local-state-policy.rs", "generated_local_state_policy.rs"),
)


def binding(text, name):
    match = re.search(r"pub\s+const\s+" + name + r"\s*:\s*\[\s*u8\s*;\s*32\s*\]\s*=\s*(\[[\s\S]*?\]);", text)
    if not match:
        raise ValueError("Missing generated binding: " + name)
    value = bytes(ast.literal_eval(match.group(1)))
    if len(value) != 32:
        raise ValueError("Invalid generated binding length: " + name)
    return value


for source, generated in PAIRS:
    source_path = ROOT / "crates/odc/policy" / source
    generated_path = ROOT / "crates/odc/src" / generated
    text = generated_path.read_text()
    if binding(text, "SOURCE_HASH") != hashlib.sha256(source_path.read_bytes()).digest():
        raise SystemExit("Generated policy source binding is stale: " + generated)
    if binding(text, "ARGUMENT_SCHEMA_HASH") != hashlib.sha256(SCHEMA).digest():
        raise SystemExit("Generated policy argument schema differs: " + generated)
protocol = (ROOT / "crates/protocol/src/lib.rs").read_text()
if SCHEMA.decode() not in protocol:
    raise SystemExit("Native argument schema differs from generated policy bindings")
print(f"PASS {len(PAIRS)} authored policy bindings and the admitted argument schema")
