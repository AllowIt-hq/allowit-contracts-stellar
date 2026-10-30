#!/usr/bin/env bash
# Build policy/engine test fixtures, then restore every deployable default artifact.
set -euo pipefail
cd "$(dirname "$0")/.."
# Tests include fixtures from the default target/ directory.
unset CARGO_TARGET_DIR
python3 scripts/check-policy-bindings.py
stellar_bin="${STELLAR_BIN:-stellar}"
"$stellar_bin" contract build --locked --package allowit-wallet-engine --features test-deny
mkdir -p target/test-fixtures
cp target/wasm32v1-none/release/allowit_wallet_engine.wasm target/test-fixtures/engine_deny.wasm
"$stellar_bin" contract build --locked
