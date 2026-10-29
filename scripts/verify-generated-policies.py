#!/usr/bin/env python3
"""Regenerate policy modules with the pinned SDK and reject different output bytes."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/AllowIt-hq/allowit-sdk.git"
PAIRS = (("policy.rs", "generated_policy.rs"),)


def run(arguments, **kwargs):
    return subprocess.check_output(arguments, text=True, **kwargs)


def verify(sdk, revision):
    if run(["git", "-C", str(sdk), "rev-parse", "HEAD"]).strip() != revision:
        raise SystemExit("Policy compiler checkout differs from the pinned SDK revision")
    if run(["git", "-C", str(sdk), "status", "--porcelain", "--untracked-files=all"]).strip():
        raise SystemExit("Policy compiler checkout must be clean")
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(ROOT / "target/policy-codegen")
    for source, generated in PAIRS:
        source_path = ROOT / "crates/custom-policy/policy" / source
        expected = (ROOT / "crates/custom-policy/src" / generated).read_text()
        actual = run(["cargo", "run", "--quiet", "--locked", "--manifest-path", str(sdk / "Cargo.toml"),
                      "--bin", "allowit", "--", "stellar-native", str(source_path)], env=environment)
        if actual != expected:
            raise SystemExit("Generated policy output differs from its pinned compiler: " + generated)
    print(f"PASS {len(PAIRS)} generated policy modules reproduced at SDK " + revision)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sdk", type=Path, default=os.environ.get("ALLOWIT_SDK_PATH"),
                    help="Clean checkout at the pinned SDK revision; otherwise fetch an isolated sparse checkout")
args = parser.parse_args()
configuration = json.loads((ROOT / "scripts/policy-codegen.json").read_text())
if configuration.get("repository") != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", configuration.get("revision", "")):
    raise SystemExit("Invalid pinned policy compiler identity")
revision = configuration["revision"]
if args.sdk:
    verify(args.sdk.resolve(), revision)
else:
    with tempfile.TemporaryDirectory(prefix="allowit-policy-codegen-") as directory:
        sdk = Path(directory)
        subprocess.run(["git", "init", "--quiet", str(sdk)], check=True)
        subprocess.run(["git", "-C", str(sdk), "fetch", "--quiet", "--depth=1", "--no-tags",
                        "--filter=blob:none", REPOSITORY, revision], check=True)
        subprocess.run(["git", "-C", str(sdk), "sparse-checkout", "set", "--cone", "src", "tests"], check=True)
        subprocess.run(["git", "-C", str(sdk), "checkout", "--quiet", "--detach", revision], check=True)
        verify(sdk, revision)
