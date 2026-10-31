# AllowIt Stellar policy wallets

Three owner-controlled contract implementations share custody and administration mixins:

- `AllowitSimplePolicyEngine` requires agent and server approval for delegated transfers and SEP-56 deposits. The server checks the authored policy offchain.
- `AllowitCommonPolicyEngine` runs the owner-approved standard prefix of canonical rule calls.
- `AllowitCustomPolicy` compiles a complete authored policy verbatim into its own contract and reuses the same wallet mixins.

Policy source is portable Rust against `crates/allowit`:
`allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;`. `execute(ctx)` takes only the
context. `AllowitContext` is plain data: backend `env`, the owner's `params`, current policy `state`
and the `request`. `params` and `request.args` are key => `AllowitValue` maps: the owner sets params
at install and changes them by signed update; the agent supplies args per call. A rule takes the
looked-up value, so it may read any key, and returns its passing constraint or an error. The offchain
server and `AllowitCustomPolicy` compile the file verbatim. The standard contract runs only its
leading canonical calls, supplied by the owner as `rules`, skips absent params and admits only the
nine canonical keys. `scripts/contract_admin.py` derives `rules` from the source. Only an error
that the policy returns denies; a caught error lets the policy continue. `allowit::operations`
admits only the op names in the owner's `operations` param and returns the op name for a `match`.
`allowit::param(ctx, key)` and `allowit::arg(ctx, key)` return the typed value of an owner param
or an agent arg and panic when it is missing or mistyped. A panic denies the run and discards its
writes. After approval the wallet
and the server run the same `allowit::post_flight`, which updates the standard state keys and
applies the policy's `allowit::set_state` writes. Simple and Common never add or change a policy
key, so their post-flight denies every policy write, on the server as onchain. Policy keys left by
earlier Custom code stay unchanged. The server uses
`allowit = { default-features = false, features = ["std"] }` and builds with `overflow-checks = true`.

The owner controls wallet upgrades, configuration, pause, recovery and exact passthrough calls.
Shared checker upgrades belong to a separate parent and grant no wallet custody authority.
Classic G-address accounts can use agent-and-server multisig without a Soroban custody contract.
They still require classic reserves, and they cannot execute custom onchain policy code.

[Architecture and authoring](docs/architecture.md) · [Engine parent](docs/engine-parent.md) · [Setup and administration](docs/admin.md) · [Mainnet preparation](docs/mainnet.md)

## Build and test

Use Rust 1.98.0, Soroban SDK 28.0.0 and [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli) 28.1.0.

```sh
python3 scripts/check-policy-bindings.py
scripts/build-contracts.sh
cargo test --workspace --locked
python3 -m unittest discover -s scripts/tests -v
python3 scripts/artifacts.py --output PATH
```

The `AllowitCustomPolicy` sample source is `crates/custom-policy/policy/policy.rs`. Its contract compiles that
file verbatim as a module, and `build.rs` binds `SOURCE_HASH` to its bytes. No SDK code generation is involved.
The canonical rules and their param keys are in `crates/allowit/`; the custody mixins are in
`crates/policy-wallet/`. `scripts/policy-smoke.rs` compiles the sample against the host backend with
plain `rustc`. `cargo test` builds and runs it, then compares its outcomes on the shared vectors in
`scripts/policy-vectors.rs` with the Soroban backend and the custom, standard and simple Wasm.
Save signed bytes before broadcast and reconcile the original transaction hash after uncertainty.
