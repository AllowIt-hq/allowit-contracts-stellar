#!/usr/bin/env python3
"""Check the custom policy's argument-schema binding and report its source digest.

The contract compiles policy/policy.rs verbatim as a module. build.rs derives SOURCE_HASH from the same
bytes, so the file must be the whole policy: it must not read other files, the environment or crates
other than `allowit` and `core`, and it must bind `allowit` only to the canonical crate. The host portability test includes the file, which
rejects inner attributes and doc comments."""
import ast
import hashlib
import re
from pathlib import Path

from policy_source import checked_code

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)"


def binding(text, name):
    match = re.search(r"pub\s+const\s+" + name + r"\s*:\s*\[\s*u8\s*;\s*32\s*\]\s*=\s*(\[[\s\S]*?\]);", text)
    if not match:
        raise ValueError("Missing binding: " + name)
    value = bytes(ast.literal_eval(match.group(1)))
    if len(value) != 32:
        raise ValueError("Invalid binding length: " + name)
    return value


source = (ROOT / "crates/custom-policy/policy/policy.rs").read_bytes()
contract = (ROOT / "crates/custom-policy/src/lib.rs").read_text()
if binding(contract, "ARGUMENT_SCHEMA_HASH") != hashlib.sha256(SCHEMA).digest():
    raise SystemExit("Custom policy argument schema differs")
if '#[path = "../policy/policy.rs"]\nmod policy;' not in contract or "/source_hash.rs" not in contract:
    raise SystemExit("Custom policy must compile and hash its authored source verbatim")
for path in ("crates/custom-policy/policy/policy.rs", "crates/custom-policy/src/branch_policy.rs"):
    try:
        checked_code((ROOT / path).read_text())
    except ValueError as error:
        raise SystemExit(path + ": " + str(error)) from None
if SCHEMA.decode() not in (ROOT / "crates/protocol/src/lib.rs").read_text():
    raise SystemExit("Native argument schema differs from the custom policy binding")
print("PASS custom policy source " + hashlib.sha256(source).hexdigest())
