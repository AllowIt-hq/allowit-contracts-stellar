# AllowIt native Stellar contracts

Rust/Soroban policy and vault contracts enforce owner-approved spending. A factory creates owner-bound vaults from shared Wasm.

Owners fund, tune, approve, revoke, switch policy and withdraw. Transfers require the executor and check asset, UTC daily limit, nonce and revision. Funding and tuning preserve spending counters. Switching policy clears approval.

Limits use six-decimal units: `1_000_000` units = one token. The daily ceiling is `50_000_000`. Zero pauses spending. Vaults accept seven-decimal Stellar Asset Contracts and multiply transfer amounts by ten. Withdrawal cannot recover smaller sub-unit dust.

## Build and test

Use Rust 1.98.0, Soroban SDK 28.0.0 and [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli) 28.1.0. The CLI processes contract specs during the Wasm build.

```sh
python3 scripts/check-policy.py
stellar contract build
cargo test --workspace --locked
python3 scripts/artifacts.py
```

Tests execute compiled policy and vault Wasm, token custody and factory deployment.

## Deploy to Stellar Testnet

Build first. Create a fresh funded identity in the secure store. Upload each Wasm, then deploy the policy and factory:

```sh
stellar keys generate allowit-native-owner --network testnet --fund --secure-store
policy_hash=$(stellar contract upload --wasm target/wasm32v1-none/release/allowit_policy.wasm --network testnet --source allowit-native-owner)
vault_hash=$(stellar contract upload --wasm target/wasm32v1-none/release/allowit_vault.wasm --network testnet --source allowit-native-owner)
factory_hash=$(stellar contract upload --wasm target/wasm32v1-none/release/allowit_factory.wasm --network testnet --source allowit-native-owner)
policy_id=$(stellar contract deploy --wasm-hash "$policy_hash" --network testnet --source allowit-native-owner)
factory_id=$(stellar contract deploy --wasm-hash "$factory_hash" --network testnet --source allowit-native-owner -- --vault_wasm "$vault_hash")
printf 'Policy: %s\nFactory: %s\n' "$policy_id" "$factory_id"
```

Create an owner vault through [`Factory.create`](crates/factory/src/lib.rs). Supply a fresh salt, executor, asset, policy address, source bundle, policy Wasm hash and daily limit.

For a complete Testnet deployment and XLM transfer exercise, use the [testnet driver](scripts/testnet.py):

```sh
stellar keys generate allowit-native-executor --network testnet --fund --secure-store
stellar keys generate allowit-native-recipient --network testnet --fund --secure-store
python3 -u scripts/testnet.py --output-dir /absolute/path/outside/checkout/testnet-run
```

The driver deploys fresh policy, vault and factory contracts. It funds a vault, tests approved and rejected transfers, then withdraws the balance. Addresses and transaction hashes appear in `evidence.json`. This uses Testnet XLM, not USDC. Reuse existing funded identities instead of generating replacements.

No verified AllowIt mainnet deployment address is recorded.

## Contract identity and operation

The [vault](crates/vault/src/lib.rs) defines the ABI. Clients pin factory address, factory/vault/policy Wasm hashes, source bundle, asset, owner and executor. Every policy call checks the resolved Wasm hash. Contracts expose no upgrade entrypoint. Owners can select a new policy version.

Maintain policy code and instance TTL. Archived policy blocks evaluation. Owner withdrawal remains independent. Vault and factory extend storage TTL during use. RPC simulation determines upload, resource and TTL fees.

[Policy source](policy/policy.rs) calls `require_approval` and `enforce_daily_limit` from [policy_api.rs](policy/policy_api.rs). Custody commits spending and transfers atomically. Check shared source copies with `python3 scripts/check-policy.py --peer ../OTHER_REPO`.

Save signed transaction bytes before broadcast. Check the original transaction after an uncertain result before signing a replacement. `python3 scripts/artifacts.py --output PATH` saves a build manifest.
