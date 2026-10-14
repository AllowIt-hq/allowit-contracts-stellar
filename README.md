# AllowIt native Stellar contracts

Rust/Soroban policy and vault contracts enforce owner-approved spending. A factory creates owner-bound vaults from shared Wasm.

Owners fund, tune, approve, revoke, switch policy and withdraw. Transfers require both the executor and the independent policy authority and check asset, UTC daily limit, nonce and revision. Funding and tuning preserve spending counters. Switching policy clears approval. This immutable v2 vault requires a fresh deployment; existing v1 vaults are not upgraded.

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

Create an owner vault through [`Factory.create`](crates/factory/src/lib.rs). Supply a fresh salt, owner, executor, authority, asset, policy address, source bundle, policy Wasm hash and daily limit. Constructor and factory arguments place `authority` immediately after `executor`. Owner, executor and authority must be distinct. Executor and authority must be classic G addresses.

For a complete Testnet deployment and XLM transfer exercise, use the [testnet driver](scripts/testnet.py):

```sh
stellar keys generate allowit-native-executor --network testnet --fund --secure-store
stellar keys generate allowit-native-authority --network testnet --fund --secure-store
stellar keys generate allowit-native-recipient --network testnet --fund --secure-store
python3 -u scripts/testnet.py --output-dir /absolute/path/outside/checkout/testnet-run
```

The driver deploys fresh policy, vault and factory contracts. It funds a vault, tests approved and rejected transfers, then withdraws the balance. Addresses and transaction hashes appear in `evidence.json`. This uses Testnet XLM, not USDC. Reuse existing funded identities instead of generating replacements.

The direct dual-signer transfer driver also needs Node 22+ and `npm ci --ignore-scripts` for the pinned official Stellar SDK. Set `STELLAR_TESTNET_NODE` if Node is not on PATH. Its helper simulates the exact transfer, captures the two requested CLI identity keys only in process memory, signs the native Soroban authorizations and transaction, and saves public signed bytes before broadcasting. It never logs or writes private keys. Existing signed proofs are reconciled without new signing or broadcasting. The helper is hardcoded to Testnet and does not implement marketplace settlement.

## Contract identity and operation

The [vault](crates/vault/src/lib.rs) defines the ABI. Clients pin factory address, factory/vault/policy Wasm hashes, source bundle, asset, owner, executor and authority. Every policy call checks the resolved Wasm hash. Contracts expose no upgrade entrypoint. Owners can select a new policy version.

Maintain policy code and instance TTL. Archived policy blocks evaluation. Owner withdrawal remains independent. Vault and factory extend storage TTL during use. RPC simulation determines upload, resource and TTL fees.

[Policy source](policy/policy.rs) calls `require_approval` and `enforce_daily_limit` from [policy_api.rs](policy/policy_api.rs). Custody commits spending and transfers atomically. Check shared source copies with `python3 scripts/check-policy.py --peer ../OTHER_REPO`.

Save signed transaction bytes before broadcast. Check the original transaction after an uncertain result before signing a replacement. `python3 scripts/artifacts.py --output PATH` saves a build manifest.

## Standard Stellar x402 authorization

The vault is a Soroban contract account. A standard SEP-41 `asset.transfer(vault, recipient, amount)` can use its C address as the payer. The reserved `__check_auth` hook accepts exactly one transfer context for the vault's bound seven-decimal Stellar Asset Contract. It rejects arbitrary calls, approvals, other assets, self-transfers, nonpositive amounts and sub-micro-unit dust. Numeric policy checks and balance checks remain mandatory. Successful authorization advances the same daily counters and nonce as `transfer`; failure of the subsequent token transfer rolls everything back. The hook emits no additional contract events, leaving the single token transfer event required by x402 facilitators.

The custom signature is a `PaymentAuthorization` ScMap with `nonce`, `revision`, `expires_at`, `request_hash`, `executor_signature` and `authority_signature`. Integer fields are XDR `u64`; hashes and signatures are 32- and 64-byte values. ScMap keys use canonical alphabetical ordering. `request_hash` must be nonzero. The deadline must be after chain time and at most 300 seconds ahead.

Both configured Ed25519 keys sign the SHA-256 of this XDR ScVal tuple, in this exact order:

```text
(Symbol("allowit_x402_v1"), vault Address, host signature-payload Bytes32,
 nonce u64, revision u64, expires_at u64, request_hash Bytes32)
```

The host payload binds the Soroban authorization, including network, exact transfer, host nonce and expiration ledger. The additional tuple binds AllowIt metadata. The authority attests an off-chain allow decision for the exact request and challenge. The contract authenticates that attestation and independently enforces its numeric rules; its shared policy API remains `require_approval` and `enforce_daily_limit`. The SDK/CLI operator-signing path does not connect the existing backend or Jev assessment. A request hash records the request binding; it is not an on-chain provider-delivery assertion. Clients must persist each request ID and exact authorization before submission and never create a second payment when settlement is uncertain.

These hook signatures authenticate the immutable Ed25519 public-key identities encoded by the executor and authority G addresses. They do not consult Stellar account multisig thresholds or later master-key changes. Use dedicated keys; owner `approve(false, revision)` revokes vault spending. The existing `transfer` entrypoint instead requires native Soroban authorization from both addresses and binds its exact arguments. Its authorization expiration ledger is selected and signed by the clients; it has no timestamp argument. Owner withdrawal remains independent of the policy and authority.

Contract tests use actual signed `SorobanAuthorizationEntry` values against both native and compiled vault code, test atomic rollback, and compare the digest with an independently generated official Stellar SDK vector. They do not establish compatibility with a particular live marketplace or its custom-account payer checks. Configure and verify the actual USDC issuer/contract separately; the existing Testnet driver exercises XLM and the direct dual-signer path.
