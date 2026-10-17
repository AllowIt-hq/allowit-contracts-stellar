#!/usr/bin/env bash
# Build the deny-engine test fixture, then restore every deployable default artifact.
set -euo pipefail
cd "$(dirname "$0")/.."
stellar_bin="${STELLAR_BIN:-stellar}"
"$stellar_bin" contract build --locked --package allowit-wallet-engine --features test-deny
mkdir -p target/test-fixtures
cp target/wasm32v1-none/release/allowit_wallet_engine.wasm target/test-fixtures/engine_deny.wasm
"$stellar_bin" contract build --locked
