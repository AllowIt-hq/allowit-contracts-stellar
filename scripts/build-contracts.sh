#!/usr/bin/env bash
# Build policy/engine test fixtures, then restore every deployable default artifact.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/check-policy-bindings.py
python3 scripts/verify-generated-policies.py
stellar_bin="${STELLAR_BIN:-stellar}"
"$stellar_bin" contract build --locked --package allowit-wallet-engine --features test-deny
mkdir -p target/test-fixtures
cp target/wasm32v1-none/release/allowit_wallet_engine.wasm target/test-fixtures/engine_deny.wasm
"$stellar_bin" contract build --locked --package allowit-odc --features test-recipient-policy
cp target/wasm32v1-none/release/allowit_odc.wasm target/test-fixtures/odc_recipient_policy.wasm
"$stellar_bin" contract build --locked --package allowit-odc --features test-xlm-policy
cp target/wasm32v1-none/release/allowit_odc.wasm target/test-fixtures/odc_xlm_policy.wasm
"$stellar_bin" contract build --locked --package allowit-odc --features test-state-policy
cp target/wasm32v1-none/release/allowit_odc.wasm target/test-fixtures/odc_state_policy.wasm
"$stellar_bin" contract build --locked --package allowit-odc --features test-local-state-policy
cp target/wasm32v1-none/release/allowit_odc.wasm target/test-fixtures/odc_local_state_policy.wasm
"$stellar_bin" contract build --locked
