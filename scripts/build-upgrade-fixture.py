#!/usr/bin/env python3
"""Build the immutable prior ODC solely to test readable owner-recovery state after upgrade."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/AllowIt-hq/allowit-contracts-stellar.git"
configuration = json.loads((ROOT / "scripts/upgrade-fixture.json").read_text())
if configuration.get("repository") != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", configuration.get("revision", "")):
    raise SystemExit("Invalid immutable ODC state-fixture identity")
for revision, filename in [(configuration["revision"], "odc_unbound_v1.wasm"),
                           (configuration["policy_bound_revision"], "odc_bound_v1.wasm")]:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit("Invalid immutable ODC fixture revision")
    with tempfile.TemporaryDirectory(prefix="allowit-odc-state-fixture-") as directory:
        checkout = Path(directory)
        subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "fetch", "--quiet", "--depth=1", "--no-tags",
                        "--filter=blob:none", REPOSITORY, revision], check=True)
        subprocess.run(["git", "-C", str(checkout), "sparse-checkout", "set", "--cone", "crates"], check=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", revision], check=True)
        environment = dict(os.environ)
        environment["CARGO_TARGET_DIR"] = str(ROOT / "target/upgrade-state")
        subprocess.run([os.environ.get("STELLAR_BIN", "stellar"), "contract", "build", "--locked", "--package", "allowit-odc"],
                       cwd=checkout, env=environment, check=True)
        output = ROOT / ("target/test-fixtures/" + filename)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "target/upgrade-state/wasm32v1-none/release/allowit_odc.wasm", output)
    print("Built immutable prior ODC state fixture " + revision)
