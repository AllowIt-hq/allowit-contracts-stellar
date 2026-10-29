# AllowIt Stellar policy wallets

Three owner-controlled contract implementations share custody and administration mixins:

- `SimplePolicyEngine` requires agent and server approval for delegated transfers. The server checks the authored policy offchain.
- `CommonPolicyEngine` adds an explicit owner-selected list of canonical local policy checks.
- `CustomPolicy` compiles bespoke local policy into its own contract and reuses the same wallet mixins.

The owner controls wallet upgrades, configuration, pause, recovery and exact passthrough calls.
Shared checker upgrades belong to a separate parent and grant no wallet custody authority.
Classic G-address accounts can use agent-and-server multisig without a Soroban custody contract.
They still require classic reserves, and they cannot execute custom onchain policy code.

[Architecture and authoring](docs/architecture.md) · [Engine parent](docs/engine-parent.md) · [Setup and administration](docs/admin.md)

## Build and test

Use Rust 1.98.0, Soroban SDK 28.0.0 and [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli) 28.1.0.

```sh
python3 scripts/check-policy.py
scripts/build-contracts.sh
cargo test --workspace --locked
python3 -m unittest discover -s scripts/tests -v
python3 scripts/artifacts.py --output PATH
```

The build reproduces the CustomPolicy sample at the immutable SDK revision in
`scripts/policy-codegen.json`. `ALLOWIT_SDK_PATH` can select a clean checkout at that revision.
Otherwise, the verifier fetches an isolated compiler checkout. Authored sample source is in
`crates/custom-policy/policy/`; the custody mixins are in `crates/policy-wallet/`.
The canonical rule parameter contracts are documented in `crates/rules/`.
Save signed bytes before broadcast and reconcile the original transaction hash after uncertainty.
