# AllowIt native Stellar contracts

`allowit-odc` is an owner-controlled SAC transfer wallet. The public `execute(...)` wrapper authenticates the installed module, private entrypoint, schema and canonical arguments. It then calls the statically compiled owner policy. It checks recipient permissions, per-transfer/daily/lifetime caps, call count, expiry, nonce and deployment version locally. Amounts use exact native `i128` units. The shared `allowit-wallet-engine` returns only a veto decision. `allowit-engine-parent` manages its shared executable and separate upgrade authority.

Owner policy deployments, pause and recovery never call the engine. Spending counters survive configuration changes. General calls, token approvals and arbitrary contract-account signing are unsupported. The owner can enable exact SAC transfer authorization for standard Stellar x402. Fund the ODC with a direct SAC transfer.

[Architecture](docs/architecture.md) · [Setup and administration](docs/admin.md)

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

Each spending path authenticates the agent and binds exact canonical arguments. The generated private policy, local owner grant and shared-engine veto all apply. Effects, counters, nonce and receipt commit atomically. Configuration changes preserve consumption and replay records. The generated `execute` wrapper and owner-enabled constrained `__check_auth` hook share automated spending checks.

## Standard x402 authorization

The owner enables or disables the constrained agent signer in a complete `deploy_policy(deployment)` packet.
The Ed25519 key is derived from the configured G-account agent. Explicit `x402_enabled` opt-in delegates that key.
Native account threshold changes do not revoke it. Disable it explicitly or replace the agent.
A grant or agent change requires `x402_enabled: false`. A later deployment can enable the derived key.
New wallets start with the path disabled.

`__check_auth` accepts one exact installed-SAC `transfer(wallet, recipient, amount)` context.
Its `X402Authorization` contains the canonical `ExecutionRequest` and a 64-byte agent signature.
The signature covers SHA-256 of the XDR tuple `(Symbol("allowit_x402_v1"), host_signature_payload, execution)`.
The host payload already binds the network, authorization nonce, ledger expiry and invocation tree.
Both spending paths enforce the compiled policy, grant, engine veto, counters and operation replay state.
The hook uses cached admitted asset metadata and never calls the active SAC. Native SAC behavior enforces
transfer effects. A failed enclosing transfer rolls back authorization accounting atomically.
Owner recovery and administration remain independent of this path and the engine.

## Versioned owner policy deployment

`deploy_policy` accepts `PolicyDeployment`: `deployment_version`, `owner`, `agent`, `engine`, `grant`,
`paused`, `x402_enabled` and optional `wasm_hash`. The target version must equal the active version plus one.
Owner, grant, agent, engine, pause, delegated key and kernel changes use this same signed deployment path.
A changed owner also authorizes the exact packet. The asset remains fixed. Accounting and replay records survive.

`set_pause(paused, deployment_version)` uses the same next-version ordering without an engine call.
`recover(recipient, amount)` authenticates the owner and moves funds without a configuration version or version increment.
Agent execution binds the active `deployment_version`, so an owner deployment invalidates earlier preparations.
`policy_binding().contract_version` identifies the supported contract release and call format.
Stored state carries the same release value. This format requires a fresh deployment and rejects
pre-stable layouts instead of performing an implicit conversion. For an incompatible state change,
pause, deploy and run a migration contract, deploy the new contract using the migrated state, then
unpause. Normal contract operations never migrate state.
The shared engine context uses the same `deployment_version` value.

`contract_version: 1` is the first explicitly numbered kernel release. `engine_version()` returns
that engine executable's release number. These are not Cargo semver or parent administration counters. Exact Wasm digests still identify executable bytes. Reading the
wallet binding never calls the engine; engine metadata is a separate optional observation.
