#!/usr/bin/env python3
"""Check the custom policy's argument-schema binding and report its source digest and standard prefix.

The contract compiles policy/policy.rs verbatim. build.rs derives SOURCE_HASH from the same bytes."""
import ast
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)"
RULES = ("transaction_cap", "spent_cap", "day_spent_cap", "day_total_cap", "call_cap", "recipients", "tokens", "expiry")
CALL = re.compile(r"allowit::(\w+)\(ctx, &ctx\.grant\.(\w+)\)\?;")


def binding(text, name):
    match = re.search(r"pub\s+const\s+" + name + r"\s*:\s*\[\s*u8\s*;\s*32\s*\]\s*=\s*(\[[\s\S]*?\]);", text)
    if not match:
        raise ValueError("Missing binding: " + name)
    value = bytes(ast.literal_eval(match.group(1)))
    if len(value) != 32:
        raise ValueError("Invalid binding length: " + name)
    return value


def standard_prefix(source):
    """Consecutive leading statements of the exact form allowit::<rule>(ctx, &ctx.grant.<rule>)?;"""
    body = source.split("-> allowit::Result {", 1)[1]
    prefix = []
    for line in filter(None, (line.strip() for line in body.splitlines())):
        match = CALL.fullmatch(line)
        if not match or match.group(1) != match.group(2) or match.group(1) not in RULES:
            break
        prefix.append(match.group(1))
    return prefix


source = (ROOT / "crates/custom-policy/policy/policy.rs").read_bytes()
contract = (ROOT / "crates/custom-policy/src/lib.rs").read_text()
if binding(contract, "ARGUMENT_SCHEMA_HASH") != hashlib.sha256(SCHEMA).digest():
    raise SystemExit("Custom policy argument schema differs")
if 'include!("../policy/policy.rs")' not in contract or "/source_hash.rs" not in contract:
    raise SystemExit("Custom policy must compile and hash its authored source verbatim")
if SCHEMA.decode() not in (ROOT / "crates/protocol/src/lib.rs").read_text():
    raise SystemExit("Native argument schema differs from the custom policy binding")
print("PASS custom policy source " + hashlib.sha256(source).hexdigest() + " prefix " + ",".join(standard_prefix(source.decode())))
