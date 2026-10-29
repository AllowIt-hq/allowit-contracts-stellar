# AllowIt native Stellar contracts

`allowit-odc` is an owner-controlled wallet for one immutable native SAC. Its kernel authenticates the
agent and exact transfer, checks pause, expiry, deployment version, execution nonce and replay, and
verifies native effects. Authored policy chooses its validation and returns the final named `Spent`
map. `Grant` is owner-signed named configuration, with no mandatory limit or recipient keys.

`allowit-policy-rules` supplies the same canonical rules to bundled policy code and the shared
`allowit-wallet-engine`. Placement is selected before deployment and recorded in the compiler
manifest. There is no runtime fallback. A shared check returns a decision and proposed spent data,
with no authority over owner configuration, code or token authorization.

Owner deployment, pause and recovery do not call the engine or read spent data. The owner can
explicitly enable standard x402 authorization for one exact installed-SAC transfer. General calls,
allowances and arbitrary account signing are outside this transfer ABI.

[Architecture and authoring](docs/architecture.md) · [Setup and administration](docs/admin.md)

## Build and test

Use Rust 1.98.0, Soroban SDK 28.0.0 and [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli)
28.1.0. The CLI processes contract specs during the Wasm build.

```sh
python3 scripts/check-policy.py
scripts/build-contracts.sh
cargo test --workspace --locked
python3 -m unittest discover -s scripts/tests -v
python3 scripts/artifacts.py --output PATH
```

The build reproduces generated policy modules at the immutable SDK revision in
`scripts/policy-codegen.json`. `ALLOWIT_SDK_PATH` can select a clean checkout at that revision.
Otherwise, it fetches an isolated compiler checkout. Regenerate authored policy changes with the
pinned SDK's `stellar-native` command before building.

The `policy/` directory contains separate portable source fixtures. The deployable custody ABI is
in `crates/protocol/`, and the exact rule parameter contracts are documented in `crates/rules/`.
Save signed bytes before broadcast and reconcile the original transaction hash after uncertainty.
