# AllowIt native Stellar contracts

`allowit-odc` is an owner-controlled SAC transfer wallet. The public `execute(...)` wrapper authenticates the installed module, private entrypoint, schema and canonical arguments. It then calls the statically compiled owner policy. It checks recipient permissions, per-transfer/daily/lifetime caps, call count, expiry, nonce and revision locally. Amounts use exact native `i128` units. The shared `allowit-wallet-engine` returns only a veto decision. `allowit-engine-parent` manages its shared executable and separate upgrade authority.

Owner pause, recovery, grant/agent/engine changes, ownership handoff and ODC code upgrades never call the engine. Spending counters survive configuration changes. General calls, token approvals and external contract-account signing are unsupported. Fund the ODC with a direct SAC transfer.

[Architecture](docs/architecture.md) · [Setup and administration](docs/admin.md) · [Mainnet preparation](docs/mainnet.md)

## Build and test

Use Rust 1.98.0, Soroban SDK 28.0.0 and [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli) 28.1.0. The CLI processes contract specs during the Wasm build.

```sh
python3 scripts/check-policy.py
scripts/build-contracts.sh
cargo test --workspace --locked
python3 scripts/artifacts.py
```

Tests execute compiled ODC, parent and engine upgrades, owner recovery and token custody. Native account administration uses the [setup and administration tools](docs/admin.md).

The `policy/` files are shared portable source fixtures. Check their identity with `python3 scripts/check-policy.py --peer ../OTHER_REPO`. The deployable contracts use the typed interfaces in `crates/protocol/`.

Save signed transaction bytes before broadcast. Check the original transaction after an uncertain result before signing a replacement. `python3 scripts/artifacts.py --output PATH` saves a manifest for the three deployable contracts.

## Compiled owner policy and execution

The authored source is `crates/odc/policy/policy.rs`. Generate its native Rust module with the SDK compiler:

```sh
cargo run --manifest-path "$ALLOWIT_SDK_PATH/Cargo.toml" --bin allowit -- stellar-native crates/odc/policy/policy.rs > crates/odc/src/generated_policy.rs
scripts/build-contracts.sh
```

The build regenerates each module at the SDK revision in `scripts/policy-codegen.json`. It rejects byte differences. Set `ALLOWIT_SDK_PATH` to a clean checkout at that revision to use a local compiler. Otherwise, the build fetches an isolated sparse checkout. Editing authored source without regeneration fails the build.

The generator checks the unchanged private `_execute(...)` source. It rejects operations outside the admitted local transfer profile. Custody Wasm contains statically compiled Rust checks. The SDK evaluates the same source for native-wallet execution.

`policy_binding()` reports the logical policy ID, actual wallet executable digest, compiled source digest, private entrypoint and argument-schema digest. The SDK maps its existing typed `ExecutionRequest` to this native wire profile and preserves its operation ID. Canonical argument bytes encode `stellar::sep41_transfer(token, from, to, amount)` with native `i128` units. The kernel requires its installed asset and its own address as source. It rejects unknown selectors, modules, schemas, extra arguments and reused operation IDs.

Each call authenticates the agent before decoding arguments. The generated private policy, local owner grant and shared-engine veto all apply. Effects, counters, nonce and receipt commit atomically. Configuration changes preserve consumption and replay records. The generated `execute` wrapper is the only automated spending entrypoint.
