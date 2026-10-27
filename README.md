# AllowIt native Stellar contracts

`allowit-odc` is an owner-controlled SAC transfer wallet. It checks recipient permissions, per-transfer/daily/lifetime caps, call count, expiry, nonce and revision locally. Amounts use exact native `i128` units. The shared `allowit-wallet-engine` returns only a veto decision. `allowit-engine-parent` manages its shared executable and separate upgrade authority.

Owner pause, recovery, grant/agent/engine changes, ownership handoff and ODC code upgrades never call the engine. Spending counters survive configuration changes. General calls, token approvals and external contract-account signing are unsupported. Fund the ODC with a direct SAC transfer.

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
